"""
Command-line interface for SSH Log Analyzer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from fang import __version__
from fang.detector import BruteForceDetector
from fang.exporter import ReportExporter
from fang.handlers.console import ConsoleAlertHandler
from fang.handlers.net_access import NetAccessControllerHook
from fang.models import AnalysisSummary, SecurityAlert
from fang.parser import SshLogParser

logger = logging.getLogger("fang")


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="fang",
        description="Fang: Fast, secure SSH brute-force attack detector and log analyzer for Linux.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-l",
        "--log-file",
        default="/var/log/auth.log",
        help="Path to authentication log file, or '-' for stdin (/var/log/auth.log or /var/log/secure, plaintext or .gz).",
    )
    parser.add_argument(
        "--journalctl",
        "--journald",
        action="store_true",
        help="Read SSH authentication logs directly from systemd journald (journalctl -u ssh -u sshd -o short-iso).",
    )
    parser.add_argument(
        "-f",
        "--follow",
        action="store_true",
        help="Continuously tail the authentication log file in real-time.",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=5,
        help="Minimum number of failed login attempts to trigger a brute-force alert.",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=60,
        help="Sliding time window duration in seconds.",
    )
    parser.add_argument(
        "-c",
        "--cooldown",
        type=int,
        default=300,
        help="Alert cooldown duration in seconds per source IP to prevent alert spam.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional path to export structured JSON security report.",
    )
    parser.add_argument(
        "--enable-net-access-hook",
        action="store_true",
        help="Enable net-access-controller extension point hook (runs in dry-run mode in v1.0).",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress real-time alert panels and display only the final summary.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )
    parser.add_argument(
        "--no-root-escalation",
        action="store_true",
        help="Disable automatic severity inflation to HIGH for root/admin targeted attempts.",
    )
    parser.add_argument(
        "--distributed-threshold",
        type=int,
        default=5,
        help="Number of distinct source IPs targeting a single user required to trigger a distributed spray alert (default: 5).",
    )
    parser.add_argument(
        "--no-distributed",
        action="store_true",
        help="Disable multi-IP distributed brute-force / password spraying detection.",
    )
    parser.add_argument(
        "--max-evidence-lines",
        type=int,
        default=50,
        help="Maximum raw log lines to embed in each alert evidence report (default: 50).",
    )
    parser.add_argument(
        "--exit-code-on-alert",
        action="store_true",
        help="Exit with return code 2 if any security alert is triggered (useful for CI/CD or automation).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"fang {__version__}",
    )

    return parser


def run_analyzer(
    log_file: str = "/var/log/auth.log",
    threshold: int = 5,
    window: int = 60,
    cooldown: int = 300,
    output_path: str | None = None,
    enable_net_access_hook: bool = False,
    quiet: bool = False,
    use_journalctl: bool = False,
    follow: bool = False,
    escalate_privileged: bool = True,
    detect_distributed: bool = True,
    distributed_threshold: int = 5,
    max_evidence_lines: int = 50,
    stop_event: Any | None = None,
    console: Console | None = None,
) -> tuple[AnalysisSummary, list[SecurityAlert]]:
    """
    Core execution logic: parses log stream, feeds events to detector,
    and returns summary along with all triggered alerts.
    """
    console = console or Console()
    parser = SshLogParser()
    detector = BruteForceDetector(
        threshold=threshold,
        window_seconds=window,
        cooldown_seconds=cooldown,
        escalate_privileged=escalate_privileged,
        detect_distributed=detect_distributed,
        distributed_threshold=distributed_threshold,
        max_evidence_events=max_evidence_lines,
    )

    # Initialize handlers
    handlers = []
    if not quiet:
        handlers.append(ConsoleAlertHandler(console=console))

    if enable_net_access_hook:
        handlers.append(NetAccessControllerHook(enabled=True, dry_run=True))

    alerts: list[SecurityAlert] = []
    unique_ips: set[str] = set()

    # Determine input stream
    proc = None
    if use_journalctl:
        import subprocess

        summary = AnalysisSummary(
            log_file_path="<journalctl>",
            scan_start_time=datetime.now(timezone.utc),
        )
        try:
            proc = subprocess.Popen(
                [
                    "journalctl",
                    "-u",
                    "ssh",
                    "-u",
                    "sshd",
                    "-o",
                    "short-iso",
                    "--no-pager",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except FileNotFoundError as err:
            raise FileNotFoundError(
                "journalctl command not found. Ensure systemd-journald is installed."
            ) from err
        event_stream = parser.parse_stream(proc.stdout)
    elif log_file == "-":
        summary = AnalysisSummary(
            log_file_path="<stdin>",
            scan_start_time=datetime.now(timezone.utc),
        )
        event_stream = parser.parse_stream(sys.stdin)
    elif follow:
        summary = AnalysisSummary(
            log_file_path=log_file,
            scan_start_time=datetime.now(timezone.utc),
        )
        event_stream = parser.follow_file(log_file, stop_event=stop_event)
    else:
        summary = AnalysisSummary(
            log_file_path=log_file,
            scan_start_time=datetime.now(timezone.utc),
        )
        event_stream = parser.parse_file(log_file)

    # Stream parse the log file
    for event in event_stream:
        summary.total_events_parsed += 1
        unique_ips.add(event.source_ip)

        if event.event_type.is_failure:
            summary.failed_attempts_count += 1

        alert = detector.process_event(event)
        if alert:
            alerts.append(alert)
            for h in handlers:
                try:
                    h.handle_alert(alert)
                except Exception as err:
                    logger.error("Handler %s error: %s", h.__class__.__name__, err)

    if proc is not None:
        proc.wait()

    summary.total_lines_read = parser.lines_read
    summary.unique_source_ips = len(unique_ips)
    summary.alerts_triggered = len(alerts)
    summary.scan_end_time = datetime.now(timezone.utc)

    # Export JSON if requested
    if output_path:
        ReportExporter.export_json(summary, alerts, output_path=output_path)
        console.print(
            f"[green][+] Exported JSON security report to:[/green] [bold]{output_path}[/bold]"
        )

    return summary, alerts


def main(argv: list[str] | None = None) -> int:
    """Main entrypoint for CLI execution."""
    args = build_parser().parse_args(argv)
    console = Console()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    err_console = Console(stderr=True)

    # Validate file existence before starting unless using stdin or journalctl
    if not args.journalctl and args.log_file != "-":
        target_file = Path(args.log_file)
        if not target_file.exists():
            err_console.print(
                f"[bold red]Error:[/bold red] Log file not found at '{target_file}'.\n"
                "  * On Debian/Ubuntu: default is [cyan]/var/log/auth.log[/cyan]\n"
                "  * On RHEL/CentOS: use [cyan]--log-file /var/log/secure[/cyan]\n"
                "  * To read from stdin: use [cyan]--log-file -[/cyan]\n"
                "  * To read journald: use [cyan]--journalctl[/cyan]\n"
                "  * To analyze a test file: use [cyan]--log-file <path-to-file>[/cyan]"
            )
            return 1
        target_str = str(target_file)
    else:
        target_str = args.log_file

    try:
        summary, alerts = run_analyzer(
            log_file=target_str,
            threshold=args.threshold,
            window=args.window,
            cooldown=args.cooldown,
            output_path=args.output,
            enable_net_access_hook=args.enable_net_access_hook,
            quiet=args.quiet,
            use_journalctl=args.journalctl,
            follow=args.follow,
            escalate_privileged=not args.no_root_escalation,
            detect_distributed=not args.no_distributed,
            distributed_threshold=args.distributed_threshold,
            max_evidence_lines=args.max_evidence_lines,
            console=console,
        )

        # Print summary table unless quiet
        ReportExporter.print_summary_table(summary, alerts, console=console)

        if args.exit_code_on_alert and alerts:
            return 2

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Stopped monitoring.[/yellow]")
        return 0

    except PermissionError as e:
        err_console.print(
            f"[bold red]Permission Denied:[/bold red] {e}\n"
            "SSH log files often require administrative privileges.\n"
            "  * Run with: [bold]sudo fang [options][/bold]\n"
            "  * Or add your user to the 'adm' group: [bold]sudo usermod -aG adm $USER[/bold]"
        )
        return 1
    except Exception as e:
        err_console.print(f"[bold red]Execution Error:[/bold red] {e}")
        if args.verbose:
            err_console.print_exception()
        return 1


if __name__ == "__main__":
    sys.exit(main())

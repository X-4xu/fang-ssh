"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from collections.abc import Sequence
from datetime import timezone, tzinfo
from typing import Any, NoReturn, TextIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ._version import __version__
from .analyzer import Analyzer, iter_events, merge_events
from .config import ConfigError, load_config
from .console import ConsoleAlertHandler, print_summary, use_color
from .detector import DEFAULT_PRIVILEGED_USERS, Detector, DetectorConfig
from .handlers import ActionHandler, BlocklistHandler, JsonlAlertHandler, NetAccessControllerHook
from .models import AnalysisStats, Severity
from .report import build_report, write_report
from .sources import FileSource, FollowSource, JournalSource, LineSource, StreamSource
from .util import Allowlist

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ALERTS = 2
EXIT_USAGE = 64
EXIT_INTERRUPTED = 130

DEFAULT_LOGS = ("/var/log/auth.log", "/var/log/secure")

_INT_OPTIONS = (
    "threshold", "window", "cooldown", "slow_threshold", "history_window", "spray_threshold",
    "spray_window", "compromise_failures", "max_tracked_ips", "max_tracked_users", "evidence_limit",
)  # fmt: skip


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    err_stream: TextIO | None = None

    def error(self, message: str) -> NoReturn:
        # argparse's default exit code (2) collides with "alerts found".
        stream = self.err_stream if self.err_stream is not None else sys.stderr
        self.print_usage(stream)
        stream.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(EXIT_USAGE)


def build_parser(err_stream: TextIO | None = None) -> argparse.ArgumentParser:
    p = _Parser(
        prog="fang",
        description="Defensive SSH brute-force / password-spraying / possible-compromise detector.",
        epilog="Exit codes: 0 ok, 1 error, 2 alerts found (with --exit-code-on-alert), 64 usage error.",
    )
    p.err_stream = err_stream
    src = p.add_argument_group("input")
    src.add_argument("-l", "--log-file", action="append", metavar="PATH",
                     help="log file (plain, .gz, .bz2, .xz); '-' reads stdin; repeatable. "
                          "Default: /var/log/auth.log or /var/log/secure, else journald")  # fmt: skip
    src.add_argument("--journald", action="store_true", help="read sshd entries from systemd-journald")
    src.add_argument("--journal-since", metavar="WHEN", help='journald start time, e.g. "1 hour ago"')
    src.add_argument("-f", "--follow", action="store_true", help="keep running and watch for new entries")
    src.add_argument(
        "--from-start", action="store_true", help="with --follow on a file: also process existing content"
    )
    src.add_argument(
        "--assume-tz",
        metavar="TZ",
        help="time zone of timestamps without offset (default UTC; 'local' allowed)",
    )
    src.add_argument("--year", type=int, metavar="YYYY", help="force the year of BSD syslog timestamps")
    src.add_argument(
        "--max-bytes",
        type=int,
        default=0,
        metavar="N",
        help="abort a source after N decompressed bytes (0 = unlimited)",
    )

    det = p.add_argument_group("detection (0 disables a rule where noted)")
    det.add_argument("-t", "--threshold", type=int, help="failed attempts per window to alert (default 5)")
    det.add_argument("-w", "--window", type=int, help="sliding window in seconds (default 60)")
    det.add_argument("-c", "--cooldown", type=int, help="seconds before the same alert repeats (default 300)")
    det.add_argument(
        "--slow-threshold",
        type=int,
        help="low-and-slow: attempts per history window, 0 disables (default 20)",
    )
    det.add_argument(
        "--history-window", type=int, help="low-and-slow / compromise look-back in seconds (default 3600)"
    )
    det.add_argument(
        "--spray-threshold", type=int, help="distinct IPs against one account, 0 disables (default 10)"
    )
    det.add_argument("--spray-window", type=int, help="spray window in seconds (default 600)")
    det.add_argument(
        "--compromise-failures",
        type=int,
        help="failures before a login counts as suspicious, 0 disables (default 3)",
    )
    det.add_argument(
        "--ignore-preauth-disconnects",
        action="store_true",
        default=None,
        help="do not count 'Connection closed ... [preauth]' as failures",
    )
    det.add_argument(
        "--privileged-user",
        action="append",
        metavar="NAME",
        help="account that raises severity (repeatable; default root, admin, administrator, wheel)",
    )
    det.add_argument(
        "--allow",
        action="append",
        metavar="IP/CIDR",
        help="trusted address or network that never alerts (repeatable)",
    )
    det.add_argument("--config", metavar="FILE", help="TOML configuration file")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="FILE", help="write the JSON report (mode 0600)")
    out.add_argument("--jsonl", metavar="FILE", help="append every alert as one JSON line")
    out.add_argument(
        "--blocklist-file",
        metavar="FILE",
        help="maintain a plain IP blocklist for nftables/ipset (never enforced by Fang)",
    )
    out.add_argument(
        "--block-min-severity",
        choices=[s.value for s in Severity],
        help="minimum severity for the blocklist (default high)",
    )
    out.add_argument(
        "--enable-net-access-hook", action="store_true", help="print dry-run net-access-controller payloads"
    )
    out.add_argument("-q", "--quiet", action="store_true", help="no alert panels, summary only")
    out.add_argument("--no-summary", action="store_true", help="do not print the final summary")
    out.add_argument("--no-color", action="store_true", help="disable colors")
    out.add_argument("-v", "--verbose", action="store_true", help="debug logging to stderr")
    out.add_argument(
        "--exit-code-on-alert", action="store_true", help="exit with status 2 if any alert was raised"
    )
    out.add_argument("--version", action="version", version=f"fang {__version__}")
    return p


def resolve_tz(name: str) -> tzinfo:
    lowered = name.strip().lower()
    if lowered in ("utc", "z", "gmt"):
        return timezone.utc
    if lowered == "local":
        from datetime import datetime

        local = datetime.now().astimezone().tzinfo
        return local if local is not None else timezone.utc
    try:
        return ZoneInfo(name.strip())
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise _UsageError(f"unknown time zone {name!r} (try e.g. 'UTC', 'local' or 'Asia/Baghdad')") from None


def _settings(args: argparse.Namespace) -> tuple[DetectorConfig, dict[str, Any]]:
    defaults = DetectorConfig()
    values: dict[str, Any] = {name: getattr(defaults, name) for name in _INT_OPTIONS}
    values["count_preauth_disconnects"] = True
    values["privileged_users"] = list(DEFAULT_PRIVILEGED_USERS)
    values["allow"] = []
    values["assume_timezone"] = "UTC"
    values["blocklist_min_severity"] = "high"

    file_values: dict[str, Any] = {}
    if args.config:
        try:
            file_values = load_config(args.config)
        except ConfigError as exc:
            raise _UsageError(str(exc)) from None
    values.update(file_values)

    for name in _INT_OPTIONS:
        cli = getattr(args, name, None)
        if cli is not None:
            values[name] = cli
    if args.ignore_preauth_disconnects:
        values["count_preauth_disconnects"] = False
    if args.privileged_user:
        values["privileged_users"] = list(args.privileged_user)
    values["allow"] = [*values["allow"], *(args.allow or [])]
    if args.assume_tz:
        values["assume_timezone"] = args.assume_tz
    if args.block_min_severity:
        values["blocklist_min_severity"] = args.block_min_severity

    try:
        allowlist = Allowlist(values["allow"])
        config = DetectorConfig(
            allowlist=allowlist,
            privileged_users=frozenset(values["privileged_users"]),
            count_preauth_disconnects=values["count_preauth_disconnects"],
            **{name: values[name] for name in _INT_OPTIONS},
        )
        Severity.parse(values["blocklist_min_severity"])
    except ValueError as exc:
        raise _UsageError(str(exc)) from None
    return config, values


def _build_sources(
    args: argparse.Namespace, stats: AnalysisStats, stop: threading.Event, stderr: TextIO
) -> list[LineSource]:
    paths: list[str] = list(args.log_file or [])
    if args.follow and (len(paths) + (1 if args.journald else 0)) > 1:
        raise _UsageError("--follow supports exactly one source")
    if args.follow and "-" in paths:
        raise _UsageError("--follow cannot be combined with stdin ('-')")
    if args.from_start and not (args.follow and paths):
        raise _UsageError("--from-start requires --follow with --log-file")
    if args.journal_since and not args.journald and paths:
        raise _UsageError("--journal-since requires --journald")

    sources: list[LineSource] = []
    use_journal = args.journald
    if not paths and not use_journal:
        existing = next((p for p in DEFAULT_LOGS if os.path.isfile(p)), None)
        if existing is not None:
            paths = [existing]
        elif JournalSource.available():
            stderr.write("fang: no auth log file found, falling back to journald\n")
            use_journal = True
        else:
            raise _UsageError("no log source found; use --log-file PATH, --journald or '-l -' for stdin")

    for path in paths:
        if path == "-":
            sources.append(StreamSource(sys.stdin.buffer, stats=stats, max_bytes=args.max_bytes))
        elif args.follow:
            sources.append(FollowSource(path, stats=stats, from_start=args.from_start, stop_event=stop))
        else:
            sources.append(FileSource(path, stats=stats, max_bytes=args.max_bytes))
    if use_journal:
        try:
            sources.append(
                JournalSource(stats=stats, since=args.journal_since, follow=args.follow, stop_event=stop)
            )
        except ValueError as exc:
            raise _UsageError(str(exc)) from None
    return sources


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    for stream in (out, err):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")

    parser = build_parser(err)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_OK

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="fang: %(levelname)s: %(message)s",
        stream=err,
        force=True,
    )
    stop = stop_event if stop_event is not None else threading.Event()
    stats = AnalysisStats()

    try:
        config, values = _settings(args)
        tz = resolve_tz(values["assume_timezone"])
        if args.year is not None and not 1970 <= args.year <= 2200:
            raise _UsageError("--year must be between 1970 and 2200")
        if args.max_bytes < 0:
            raise _UsageError("--max-bytes must not be negative")
        sources = _build_sources(args, stats, stop, err)
    except _UsageError as exc:
        err.write(f"fang: error: {exc}\n")
        return EXIT_USAGE

    color = use_color(out, args.no_color)
    handlers: list[ActionHandler] = [ConsoleAlertHandler(out, color=color, quiet=args.quiet)]
    try:
        if args.jsonl:
            handlers.append(JsonlAlertHandler(args.jsonl))
        if args.blocklist_file:
            handlers.append(
                BlocklistHandler(
                    args.blocklist_file, config.allowlist, Severity.parse(values["blocklist_min_severity"])
                )
            )
    except OSError as exc:
        err.write(f"fang: error: cannot open output file: {exc.strerror or exc}\n")
        for handler in handlers:
            handler.close()
        return EXIT_ERROR
    if args.enable_net_access_hook:
        handlers.append(NetAccessControllerHook(config.allowlist, err))

    stats.log_sources = [s.name for s in sources]
    detector = Detector(config, stats)
    analyzer = Analyzer(detector, handlers)

    previous: dict[int, Any] = {}
    if args.follow and threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())

    interrupted = False
    try:
        streams = [iter_events(s, stats, tz=tz, year=args.year) for s in sources]
        analyzer.run(merge_events(streams))
    except KeyboardInterrupt:
        interrupted = True
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        analyzer.close()

    offenders = detector.top_offenders(10)
    if not args.no_summary:
        print_summary(out, stats, analyzer.alerts, offenders, color)
    if args.output:
        try:
            write_report(args.output, build_report(analyzer.alerts, stats, config.to_dict(), offenders))
        except OSError as exc:
            err.write(f"fang: error: cannot write report: {exc.strerror or exc}\n")
            return EXIT_ERROR
    if args.no_summary:  # the summary already lists warnings; avoid printing them twice
        for message in (*stats.source_errors, *stats.warnings):
            err.write(f"fang: warning: {message}\n")

    if interrupted:
        return EXIT_INTERRUPTED
    if args.exit_code_on_alert and stats.alerts_triggered:
        return EXIT_ALERTS
    if stats.source_errors:
        return EXIT_ERROR
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

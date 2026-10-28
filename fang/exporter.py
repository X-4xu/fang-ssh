"""
Structured report export utilities (JSON and terminal tables).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from fang import __version__
from fang.models import AnalysisSummary, SecurityAlert


class ReportExporter:
    """Exports security analysis results to JSON reports and terminal presentations."""

    @staticmethod
    def build_report_dict(
        summary: AnalysisSummary, alerts: list[SecurityAlert]
    ) -> dict[str, Any]:
        """Construct the standardized report dictionary."""
        return {
            "schema_version": "1.0.0",
            "analyzer_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary.to_dict(),
            "alerts_count": len(alerts),
            "alerts": [alert.to_dict() for alert in alerts],
        }

    @classmethod
    def export_json(
        cls,
        summary: AnalysisSummary,
        alerts: list[SecurityAlert],
        output_path: str | Path | None = None,
        indent: int = 2,
    ) -> str:
        """
        Generate JSON string and optionally save to file.
        Safely creates parent directories if needed.
        """
        data = cls.build_report_dict(summary, alerts)
        json_str = json.dumps(data, indent=indent, default=str)

        if output_path:
            path = Path(output_path)
            # Create parent directories if they don't exist
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    @staticmethod
    def print_summary_table(
        summary: AnalysisSummary,
        alerts: list[SecurityAlert],
        console: Console | None = None,
    ) -> None:
        """Render a clean summary table to the console."""
        console = console or Console()

        # 1. Summary Metrics Table
        summary_table = Table(
            title="Fang: SSH Security Analysis Summary",
            show_header=True,
            header_style="bold cyan",
        )
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("Log File Path", summary.log_file_path)
        summary_table.add_row("Total Lines Scanned", str(summary.total_lines_read))
        summary_table.add_row("SSH Events Parsed", str(summary.total_events_parsed))
        summary_table.add_row(
            "Failed Login Attempts", str(summary.failed_attempts_count)
        )
        summary_table.add_row("Unique Source IPs", str(summary.unique_source_ips))
        summary_table.add_row(
            "Brute-Force Alerts Triggered", str(summary.alerts_triggered)
        )

        duration = (
            (summary.scan_end_time - summary.scan_start_time).total_seconds()
            if summary.scan_end_time
            else 0.0
        )
        summary_table.add_row("Execution Time", f"{duration:.3f}s")

        console.print()
        console.print(summary_table)

        # 2. Detected Alerts Table (if any)
        if alerts:
            alerts_table = Table(
                title="Detected Brute-Force Incidents",
                show_header=True,
                header_style="bold red",
            )
            alerts_table.add_column("Alert ID", style="dim")
            alerts_table.add_column("Source IP", style="bold")
            alerts_table.add_column("Severity", justify="center")
            alerts_table.add_column("Attempts", justify="right")
            alerts_table.add_column("Target Users")
            alerts_table.add_column("Time Window")

            for alert in alerts:
                severity_style = {
                    "critical": "[red bold]CRITICAL[/red bold]",
                    "high": "[bright_red]HIGH[/bright_red]",
                    "medium": "[yellow]MEDIUM[/yellow]",
                    "low": "[cyan]LOW[/cyan]",
                }.get(alert.severity.value, alert.severity.value)

                users = ", ".join(alert.target_usernames[:4])
                if len(alert.target_usernames) > 4:
                    users += f" (+{len(alert.target_usernames) - 4} more)"
                if not users:
                    users = "N/A"

                window_str = f"{alert.start_time.strftime('%H:%M:%S')} - {alert.end_time.strftime('%H:%M:%S')}"

                alerts_table.add_row(
                    alert.alert_id,
                    alert.source_ip,
                    severity_style,
                    str(alert.failed_attempts_count),
                    users,
                    window_str,
                )

            console.print()
            console.print(alerts_table)
            console.print()
        else:
            console.print(
                "\n[bold green][OK] No brute-force attacks detected matching the criteria.[/bold green]\n"
            )

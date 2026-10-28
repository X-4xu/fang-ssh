"""Plain-text console output (no third-party dependencies).

Every string that reaches the terminal was sanitized by the parser (control,
escape and bidi characters removed) and addresses were validated, so log
content cannot inject terminal escape sequences or fake output.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from datetime import datetime
from typing import Any, TextIO

from .handlers import ActionHandler
from .models import AnalysisStats, SecurityAlert, Severity

_WIDTH = 78
_COLORS = {Severity.MEDIUM: "33", Severity.HIGH: "31", Severity.CRITICAL: "1;37;41"}


def use_color(stream: TextIO, disabled: bool = False) -> bool:
    """Color only on a real terminal, honouring NO_COLOR and TERM=dumb."""
    if disabled or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _fmt_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _join(items: Sequence[object], limit: int = 12) -> str:
    shown = ", ".join(str(i) for i in items[:limit])
    extra = len(items) - limit
    return shown + (f" (+{extra} more)" if extra > 0 else "") if items else "-"


def _write(stream: TextIO, text: str) -> None:
    try:
        stream.write(text)
    except UnicodeEncodeError:
        stream.write(text.encode("ascii", "backslashreplace").decode("ascii"))
    stream.flush()


def render_alert(alert: SecurityAlert, color: bool = False) -> str:
    sev = alert.severity.value.upper()
    tag = "ESCALATED " if alert.escalation else ""
    title = f" FANG ALERT: {alert.alert_type.label} [{tag}{sev}] "
    top = "+" + title.center(_WIDTH - 2, "-") + "+"
    if color:
        top = top.replace(f"[{tag}{sev}]", _paint(f"[{tag}{sev}]", _COLORS[alert.severity], True))
    rows = [("Alert ID", alert.alert_id)]
    if alert.source_ip is not None:
        rows.append(("Source IP", alert.source_ip))
    else:
        rows.append(("Sources", f"{len(alert.source_ips)} IPs: {_join(alert.source_ips, 6)}"))
    window = (
        f"in {alert.window_seconds}s window" if alert.alert_type.value != "possible_compromise" else "recent"
    )
    rows.append(("Failed attempts", f"{alert.attempts} ({window})"))
    if alert.total_failures_from_ip is not None:
        rows.append(("Total from IP", str(alert.total_failures_from_ip)))
    rows.append(("Time range (UTC)", f"{_fmt_time(alert.start_time)} -> {_fmt_time(alert.end_time)}"))
    rows.append(("Target users", _join(alert.target_usernames)))
    if alert.ports:
        rows.append(("Source ports", _join(alert.ports, 8)))
    if alert.login_username is not None:
        rows.append(("Successful login", f"{alert.login_username} via {alert.login_method or 'unknown'}"))
    rows.append(("Pattern", alert.pattern))
    lines = [top] + [f"| {name + ':':<17} {value}" for name, value in rows] + ["+" + "-" * (_WIDTH - 2) + "+"]
    return "\n".join(lines) + "\n"


class ConsoleAlertHandler(ActionHandler):
    def __init__(self, stream: TextIO | None = None, *, color: bool = False, quiet: bool = False) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.color = color
        self.quiet = quiet

    def handle(self, alert: SecurityAlert) -> None:
        if not self.quiet:
            _write(self.stream, render_alert(alert, self.color))


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out = [sep, "| " + " | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)) + " |", sep]
    out += ["| " + " | ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)) + " |" for r in rows]
    out.append(sep)
    return out


def render_summary(
    stats: AnalysisStats,
    alerts: Sequence[SecurityAlert],
    offenders: Sequence[dict[str, Any]],
    color: bool = False,
) -> str:
    sources = ", ".join(stats.log_sources) if stats.log_sources else "-"
    rows = [
        ("Log sources", sources if len(sources) <= 60 else sources[:57] + "..."),
        ("Lines scanned", f"{stats.lines_read:,}"),
        ("SSH events parsed", f"{stats.events_parsed:,}"),
        ("Failed login attempts", f"{stats.failed_attempts:,}"),
        ("Successful logins", f"{stats.accepted_logins:,}"),
        ("Unique source IPs", f"{stats.unique_source_ips:,}"),
        ("Alerts triggered", f"{stats.alerts_triggered:,}"),
        ("Suppressed duplicates", f"{stats.suppressed_alerts:,}"),
        ("Execution time", f"{stats.duration_seconds:.3f}s"),
    ]
    if stats.allowlisted_events:
        rows.insert(6, ("Allow-listed events", f"{stats.allowlisted_events:,}"))
    if stats.oversized_lines or stats.invalid_ip_lines:
        rows.append(("Skipped (oversized/bad IP)", f"{stats.oversized_lines:,} / {stats.invalid_ip_lines:,}"))
    if stats.suspicious_lines:
        rows.append(("Log-injection attempts", f"{stats.suspicious_lines:,}"))
    out = ["", "Fang: SSH Security Analysis Summary", *_table(("Metric", "Value"), rows)]
    if alerts:
        out += ["", "Detected incidents"]
        listing = [
            (
                a.alert_id,
                a.alert_type.value,
                a.severity.value.upper(),
                a.source_ip or f"{len(a.source_ips)} IPs",
                str(a.attempts),
                _join(a.target_usernames, 4),
            )
            for a in alerts[:50]
        ]
        out += _table(("Alert ID", "Type", "Severity", "Source", "Attempts", "Users"), listing)
        if len(alerts) > 50:
            out.append(f"... and {len(alerts) - 50} more (see the JSON report)")
    if offenders:
        out += ["", "Top offenders"]
        out += _table(
            ("Source IP", "Failed", "Users tried"),
            [
                (str(o["ip"]), str(o["failed_attempts"]), _join(list(o["usernames"]), 4))
                for o in offenders[:5]
            ],
        )
    for message in (*stats.source_errors, *stats.warnings):
        out.append(f"WARNING: {message}")
    return "\n".join(out) + "\n"


def print_summary(
    stream: TextIO,
    stats: AnalysisStats,
    alerts: Sequence[SecurityAlert],
    offenders: Sequence[dict[str, Any]],
    color: bool = False,
) -> None:
    _write(stream, render_summary(stats, alerts, offenders, color))

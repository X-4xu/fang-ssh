"""Core data models shared by every Fang component."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class EventType(str, enum.Enum):
    """Kinds of sshd log lines Fang understands."""

    FAILED_PASSWORD = "FAILED_PASSWORD"  # noqa: S105
    FAILED_PUBLICKEY = "FAILED_PUBLICKEY"
    FAILED_OTHER = "FAILED_OTHER"  # keyboard-interactive, gssapi, ...
    FAILED_NONE = "FAILED_NONE"  # informational, never counted
    AUTH_FAILURE = "AUTH_FAILURE"  # PAM line; informational, never counted
    INVALID_USER = "INVALID_USER"  # informational, never counted
    PREAUTH_DISCONNECT = "PREAUTH_DISCONNECT"  # weak failure
    MAX_AUTH_EXCEEDED = "MAX_AUTH_EXCEEDED"  # weak failure
    ACCEPTED_PASSWORD = "ACCEPTED_PASSWORD"  # noqa: S105
    ACCEPTED_PUBLICKEY = "ACCEPTED_PUBLICKEY"
    ACCEPTED_OTHER = "ACCEPTED_OTHER"

    @property
    def is_failure(self) -> bool:
        """True for every line that reports a failed authentication.

        Note: not every failure line is *counted* by the detector. PAM and
        ``Failed none`` lines duplicate the explicit ``Failed password`` line
        for the same attempt, so counting them would halve the real threshold.
        """
        return self in _FAILURE_LIKE

    @property
    def is_accepted(self) -> bool:
        return self in ACCEPTED_TYPES


#: Explicit authentication failures (one log line == one attempt).
STRONG_FAILURES = frozenset({EventType.FAILED_PASSWORD, EventType.FAILED_PUBLICKEY, EventType.FAILED_OTHER})
#: Failures inferred from connection teardown. Counted at most once per
#: connection, and only when no explicit failure line was seen for it.
WEAK_FAILURES = frozenset({EventType.PREAUTH_DISCONNECT, EventType.MAX_AUTH_EXCEEDED})
ACCEPTED_TYPES = frozenset(
    {EventType.ACCEPTED_PASSWORD, EventType.ACCEPTED_PUBLICKEY, EventType.ACCEPTED_OTHER}
)
_FAILURE_LIKE = STRONG_FAILURES | WEAK_FAILURES | {EventType.FAILED_NONE, EventType.AUTH_FAILURE}


class Severity(str, enum.Enum):
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None


_SEVERITY_RANK = {Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

#: Name used by Fang 1.x.
AlertSeverity = Severity


class AlertType(str, enum.Enum):
    BRUTE_FORCE = "brute_force"
    SLOW_BRUTE_FORCE = "slow_brute_force"
    DISTRIBUTED_ATTACK = "distributed_attack"
    POSSIBLE_COMPROMISE = "possible_compromise"

    @property
    def label(self) -> str:
        """Human-readable name (``title`` would shadow ``str.title``)."""
        return _ALERT_TITLES[self]


_ALERT_TITLES = {
    AlertType.BRUTE_FORCE: "SSH BRUTE-FORCE",
    AlertType.SLOW_BRUTE_FORCE: "LOW-AND-SLOW BRUTE-FORCE",
    AlertType.DISTRIBUTED_ATTACK: "DISTRIBUTED ATTACK",
    AlertType.POSSIBLE_COMPROMISE: "POSSIBLE COMPROMISE",
}


@dataclass(frozen=True, slots=True)
class SshAuthEvent:
    """One parsed, sanitized sshd authentication event."""

    timestamp: datetime
    event_type: EventType
    source_ip: str
    username: str
    host: str = ""
    pid: int | None = None
    port: int | None = None
    is_invalid_user: bool = False
    auth_method: str = ""
    weight: int = 1  # >1 for rsyslog "message repeated N times"
    line_number: int = 0
    raw_line: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "source_ip": self.source_ip,
            "port": self.port,
            "username": self.username,
            "is_invalid_user": self.is_invalid_user,
            "auth_method": self.auth_method,
            "line_number": self.line_number,
            "raw_line": self.raw_line,
        }
        if self.weight > 1:
            data["repeat_count"] = self.weight
        if self.source:
            data["source"] = self.source
        return data


@dataclass(slots=True)
class SecurityAlert:
    alert_id: str
    alert_type: AlertType
    severity: Severity
    source_ip: str | None  # None for distributed alerts
    source_ips: list[str]
    pattern: str
    attempts: int
    window_seconds: int
    start_time: datetime
    end_time: datetime
    triggered_at: datetime
    target_usernames: list[str]
    ports: list[int]
    evidence: list[SshAuthEvent]
    evidence_truncated: bool = False
    escalation: bool = False
    total_failures_from_ip: int | None = None
    login_username: str | None = None
    login_method: str | None = None

    @property
    def block_candidates(self) -> list[str]:
        """IPs a remediation tool could act on for this alert."""
        if self.source_ip is not None:
            return [self.source_ip]
        return list(self.source_ips)

    @property
    def duration_seconds(self) -> float:
        return max((self.end_time - self.start_time).total_seconds(), 0.0)

    # Fang 1.x attribute names, kept so existing code and tests keep working.
    @property
    def failed_attempts_count(self) -> int:
        return self.attempts

    @property
    def evidence_events(self) -> list[SshAuthEvent]:
        return self.evidence

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "source_ips": self.source_ips,
            "pattern": self.pattern,
            "failed_attempts_count": self.attempts,
            "window_seconds": self.window_seconds,
            "time_range": {
                "start": self.start_time.isoformat(),
                "end": self.end_time.isoformat(),
                "duration_seconds": round(self.duration_seconds, 3),
            },
            "target_usernames": self.target_usernames,
            "ports": self.ports,
            "triggered_at": self.triggered_at.isoformat(),
            "escalation": self.escalation,
            "evidence_truncated": self.evidence_truncated,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.total_failures_from_ip is not None:
            data["total_failures_from_ip"] = self.total_failures_from_ip
        if self.login_username is not None:
            data["login_username"] = self.login_username
            data["login_method"] = self.login_method
        return data


@dataclass(slots=True)
class AnalysisStats:
    """Counters shared by the sources, parser, detector and reporters."""

    log_sources: list[str] = field(default_factory=list)
    lines_read: int = 0
    oversized_lines: int = 0
    invalid_ip_lines: int = 0
    suspicious_lines: int = 0
    events_parsed: int = 0
    failed_attempts: int = 0
    accepted_logins: int = 0
    allowlisted_events: int = 0
    unique_source_ips: int = 0
    unique_ips_capped: bool = False
    alerts_triggered: int = 0
    alerts_by_severity: dict[str, int] = field(default_factory=dict)
    alerts_by_type: dict[str, int] = field(default_factory=dict)
    suppressed_alerts: int = 0
    evicted_states: int = 0
    report_alerts_dropped: int = 0
    source_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scan_start: datetime | None = None
    scan_end: datetime | None = None

    @property
    def duration_seconds(self) -> float:
        if self.scan_start is None or self.scan_end is None:
            return 0.0
        return max((self.scan_end - self.scan_start).total_seconds(), 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_sources": self.log_sources,
            "total_lines_read": self.lines_read,
            "oversized_lines_skipped": self.oversized_lines,
            "invalid_ip_lines_skipped": self.invalid_ip_lines,
            "suspicious_lines": self.suspicious_lines,
            "total_events_parsed": self.events_parsed,
            "failed_attempts_count": self.failed_attempts,
            "accepted_logins_count": self.accepted_logins,
            "allowlisted_events": self.allowlisted_events,
            "unique_source_ips": self.unique_source_ips,
            "unique_source_ips_capped": self.unique_ips_capped,
            "alerts_triggered": self.alerts_triggered,
            "alerts_by_severity": dict(sorted(self.alerts_by_severity.items())),
            "alerts_by_type": dict(sorted(self.alerts_by_type.items())),
            "suppressed_alerts": self.suppressed_alerts,
            "evicted_states": self.evicted_states,
            "alerts_dropped_from_report": self.report_alerts_dropped,
            "source_errors": self.source_errors,
            "warnings": self.warnings,
            "scan_start_time": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end_time": self.scan_end.isoformat() if self.scan_end else None,
            "scan_duration_seconds": round(self.duration_seconds, 3),
        }

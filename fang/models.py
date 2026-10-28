"""
Core data models for SSH authentication events, alerts, and analysis summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Types of SSH authentication log events."""

    FAILED_PASSWORD = "FAILED_PASSWORD"
    INVALID_USER = "INVALID_USER"
    AUTH_FAILURE = "AUTH_FAILURE"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"
    ACCEPTED_PASSWORD = "ACCEPTED_PASSWORD"
    ACCEPTED_PUBLICKEY = "ACCEPTED_PUBLICKEY"
    DISCONNECTED = "DISCONNECTED"
    OTHER = "OTHER"

    @property
    def is_failure(self) -> bool:
        """Return True if this event represents an authentication failure."""
        return self in (
            EventType.FAILED_PASSWORD,
            EventType.INVALID_USER,
            EventType.AUTH_FAILURE,
        )

    @property
    def is_accepted(self) -> bool:
        """Return True if this event represents a successful authentication."""
        return self in (
            EventType.ACCEPTED_PASSWORD,
            EventType.ACCEPTED_PUBLICKEY,
        )


class AlertSeverity(str, Enum):
    """Severity classification for security alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SshAuthEvent:
    """Represents a single parsed SSH authentication event from the log."""

    timestamp: datetime
    event_type: EventType
    source_ip: str
    port: int | None = None
    username: str | None = None
    is_invalid_user: bool = False
    raw_line: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize event to a JSON-compatible dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "source_ip": self.source_ip,
            "port": self.port,
            "username": self.username,
            "is_invalid_user": self.is_invalid_user,
            "line_number": self.line_number,
            "raw_line": self.raw_line,
        }


@dataclass
class SecurityAlert:
    """Security alert representing detected suspicious activity (e.g. brute force)."""

    alert_id: str
    source_ip: str
    severity: AlertSeverity
    pattern: str
    failed_attempts_count: int
    window_seconds: int
    start_time: datetime
    end_time: datetime
    target_usernames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    evidence_events: list[SshAuthEvent] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize security alert to structured JSON format."""
        return {
            "alert_id": self.alert_id,
            "source_ip": self.source_ip,
            "severity": self.severity.value,
            "pattern": self.pattern,
            "failed_attempts_count": self.failed_attempts_count,
            "window_seconds": self.window_seconds,
            "time_range": {
                "start": self.start_time.isoformat(),
                "end": self.end_time.isoformat(),
                "duration_seconds": round(
                    (self.end_time - self.start_time).total_seconds(), 2
                ),
            },
            "target_usernames": sorted(list(set(self.target_usernames))),
            "ports": sorted(list(set(self.ports))),
            "detected_at": self.detected_at.isoformat(),
            "evidence": [ev.to_dict() for ev in self.evidence_events],
        }


@dataclass
class AnalysisSummary:
    """High-level summary of an execution run."""

    log_file_path: str
    total_lines_read: int = 0
    total_events_parsed: int = 0
    failed_attempts_count: int = 0
    unique_source_ips: int = 0
    alerts_triggered: int = 0
    scan_start_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scan_end_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to JSON-compatible dictionary."""
        duration = (
            (self.scan_end_time - self.scan_start_time).total_seconds()
            if self.scan_end_time
            else 0.0
        )
        return {
            "log_file_path": self.log_file_path,
            "total_lines_read": self.total_lines_read,
            "total_events_parsed": self.total_events_parsed,
            "failed_attempts_count": self.failed_attempts_count,
            "unique_source_ips": self.unique_source_ips,
            "alerts_triggered": self.alerts_triggered,
            "scan_start_time": self.scan_start_time.isoformat(),
            "scan_end_time": (
                self.scan_end_time.isoformat() if self.scan_end_time else None
            ),
            "scan_duration_seconds": round(duration, 3),
        }

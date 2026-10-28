"""
Sliding-window brute-force detection engine for SSH authentication events.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
import uuid

from fang.models import (
    AlertSeverity,
    SecurityAlert,
    SshAuthEvent,
)

# High-risk usernames that elevate alert severity
PRIVILEGED_USERS = {"root", "admin", "administrator", "wheel", "sudo"}


class BruteForceDetector:
    """
    Stateful sliding-window brute-force detector.
    Groups failed login attempts by source IP and triggers security alerts
    when the failure count reaches or exceeds the threshold within the configured time window.
    Also detects possible account compromises when accepted logins immediately follow failures.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
        detect_compromise: bool = True,
        min_failures_for_compromise: int = 2,
        escalate_privileged: bool = True,
        privileged_users: set[str] | None = None,
    ) -> None:
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        if window_seconds < 1:
            raise ValueError("Window seconds must be at least 1")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.detect_compromise = detect_compromise
        self.min_failures_for_compromise = min_failures_for_compromise
        self.escalate_privileged = escalate_privileged
        self.privileged_users = (
            {u.lower() for u in privileged_users}
            if privileged_users is not None
            else set(PRIVILEGED_USERS)
        )

        # Map: source_ip -> deque of SshAuthEvent
        self._ip_windows: dict[str, deque[SshAuthEvent]] = defaultdict(deque)
        # Map: source_ip -> last alert timestamp
        self._last_alert_times: dict[str, datetime] = {}
        # Count of total alerts triggered
        self.total_alerts: int = 0

    def process_event(self, event: SshAuthEvent) -> SecurityAlert | None:
        """
        Process a single SSH authentication event.
        Returns a SecurityAlert if a brute-force pattern is detected or
        if an accepted login occurs after repeated failures (possible compromise).
        """
        ip = event.source_ip
        window = self._ip_windows[ip]

        # Evict events older than current_event.timestamp - window_seconds
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while window and window[0].timestamp < cutoff:
            window.popleft()

        # Check for possible compromise: successful login following multiple failures
        if event.event_type.is_accepted:
            if (
                self.detect_compromise
                and len(window) >= self.min_failures_for_compromise
            ):
                alert = self._create_compromise_alert(ip, list(window), event)
                window.clear()
                self.total_alerts += 1
                return alert
            window.clear()
            return None

        if not event.event_type.is_failure:
            return None

        # Append new failure event
        window.append(event)

        # Check threshold
        if len(window) >= self.threshold:
            # Check cooldown
            last_alert = self._last_alert_times.get(ip)
            if last_alert is not None:
                elapsed = (event.timestamp - last_alert).total_seconds()
                if 0 <= elapsed < self.cooldown_seconds:
                    # Still in cooldown period for this IP
                    return None

            # Generate alert
            alert = self._create_alert(ip, list(window))
            self._last_alert_times[ip] = event.timestamp
            self.total_alerts += 1
            return alert

        return None

    def process_events(self, events: Iterable[SshAuthEvent]) -> Iterator[SecurityAlert]:
        """
        Process an iterable stream of events and yield detected SecurityAlerts.
        """
        for event in events:
            alert = self.process_event(event)
            if alert is not None:
                yield alert

    def _create_alert(
        self, source_ip: str, events: list[SshAuthEvent]
    ) -> SecurityAlert:
        """Construct SecurityAlert from the current window events."""
        events_sorted = sorted(events, key=lambda x: x.timestamp)
        start_time = events_sorted[0].timestamp
        end_time = events_sorted[-1].timestamp
        count = len(events_sorted)

        usernames = [ev.username for ev in events_sorted if ev.username]
        ports = [ev.port for ev in events_sorted if ev.port is not None]

        # Calculate severity
        severity = self._calculate_severity(count, usernames)

        alert_id = f"ALERT-FANG-{uuid.uuid4().hex[:8].upper()}"
        pattern = (
            f"SSH Brute-Force: {count} failed attempts in "
            f"{(end_time - start_time).total_seconds():.1f}s (Threshold: {self.threshold}/{self.window_seconds}s)"
        )

        return SecurityAlert(
            alert_id=alert_id,
            source_ip=source_ip,
            severity=severity,
            pattern=pattern,
            failed_attempts_count=count,
            window_seconds=self.window_seconds,
            start_time=start_time,
            end_time=end_time,
            target_usernames=usernames,
            ports=ports,
            evidence_events=events_sorted,
            detected_at=datetime.now(timezone.utc),
        )

    def _create_compromise_alert(
        self,
        source_ip: str,
        failed_events: list[SshAuthEvent],
        accepted_event: SshAuthEvent,
    ) -> SecurityAlert:
        """Construct a CRITICAL possible compromise alert."""
        events_sorted = sorted(failed_events, key=lambda x: x.timestamp)
        start_time = events_sorted[0].timestamp
        end_time = accepted_event.timestamp
        count = len(events_sorted)
        duration = max(0.1, (end_time - start_time).total_seconds())

        usernames = list(
            dict.fromkeys(
                [ev.username for ev in events_sorted if ev.username]
                + ([accepted_event.username] if accepted_event.username else [])
            )
        )
        ports = list(
            dict.fromkeys(
                [ev.port for ev in events_sorted if ev.port is not None]
                + ([accepted_event.port] if accepted_event.port is not None else [])
            )
        )

        alert_id = f"ALERT-FANG-COMPROMISE-{uuid.uuid4().hex[:8].upper()}"
        pattern = (
            f"Possible Compromise: Accepted login for '{accepted_event.username or 'unknown'}' "
            f"following {count} failed attempts in {duration:.1f}s"
        )

        return SecurityAlert(
            alert_id=alert_id,
            source_ip=source_ip,
            severity=AlertSeverity.CRITICAL,
            pattern=pattern,
            failed_attempts_count=count,
            window_seconds=self.window_seconds,
            start_time=start_time,
            end_time=end_time,
            target_usernames=usernames,
            ports=ports,
            evidence_events=events_sorted + [accepted_event],
            detected_at=datetime.now(timezone.utc),
        )

    def _calculate_severity(self, count: int, usernames: list[str]) -> AlertSeverity:
        """
        Determine severity based on attempt volume and sensitive target accounts.
        """
        has_privileged = self.escalate_privileged and any(
            u.lower() in self.privileged_users for u in usernames
        )

        if count >= 20 or (has_privileged and count >= 10):
            return AlertSeverity.CRITICAL
        if count >= 10 or has_privileged:
            return AlertSeverity.HIGH
        if count >= self.threshold:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def reset(self) -> None:
        """Clear all in-memory detection states."""
        self._ip_windows.clear()
        self._last_alert_times.clear()
        self.total_alerts = 0

"""
Sliding-window brute-force detection engine for SSH authentication events.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

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
    Also detects:
      - Possible account compromises when accepted logins immediately follow failures.
      - Distributed brute-force / password spraying targeting the same account across distinct IPs.
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
        detect_distributed: bool = True,
        distributed_threshold: int = 5,
        max_evidence_events: int = 50,
    ) -> None:
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        if window_seconds < 1:
            raise ValueError("Window seconds must be at least 1")
        if distributed_threshold < 2:
            raise ValueError("Distributed threshold must be at least 2")

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
        self.detect_distributed = detect_distributed
        self.distributed_threshold = distributed_threshold
        self.max_evidence_events = max_evidence_events

        # Map: source_ip -> deque of SshAuthEvent
        self._ip_windows: dict[str, deque[SshAuthEvent]] = defaultdict(deque)
        # Map: source_ip -> last alert timestamp
        self._last_alert_times: dict[str, datetime] = {}

        # Map: username (lowercase) -> deque of SshAuthEvent (for distributed attack detection)
        self._user_windows: dict[str, deque[SshAuthEvent]] = defaultdict(deque)
        # Map: username (lowercase) -> last distributed alert timestamp
        self._last_user_alert_times: dict[str, datetime] = {}

        # Count of total alerts triggered
        self.total_alerts: int = 0

    def process_event(self, event: SshAuthEvent) -> SecurityAlert | None:
        """
        Process a single SSH authentication event.
        Returns a SecurityAlert if:
          1. Single-source brute force threshold is met for the source IP.
          2. Successful login occurs after repeated failures from the same IP (possible compromise).
          3. Distributed password spray attack targets the same user across distinct IPs.
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

        # Append new failure event to IP window
        window.append(event)

        # 1. Check single-source threshold
        if len(window) >= self.threshold:
            last_alert = self._last_alert_times.get(ip)
            in_cooldown = False
            if last_alert is not None:
                elapsed = (event.timestamp - last_alert).total_seconds()
                if 0 <= elapsed < self.cooldown_seconds:
                    in_cooldown = True

            if not in_cooldown:
                alert = self._create_alert(ip, list(window))
                self._last_alert_times[ip] = event.timestamp
                self.total_alerts += 1
                return alert

        # 2. Check distributed attack across distinct IPs targeting the same user
        if self.detect_distributed and event.username:
            user_key = event.username.lower()
            u_window = self._user_windows[user_key]
            while u_window and u_window[0].timestamp < cutoff:
                u_window.popleft()
            u_window.append(event)

            distinct_ips = {ev.source_ip for ev in u_window}
            if len(distinct_ips) >= self.distributed_threshold:
                last_u_alert = self._last_user_alert_times.get(user_key)
                in_u_cooldown = False
                if last_u_alert is not None:
                    elapsed_u = (event.timestamp - last_u_alert).total_seconds()
                    if 0 <= elapsed_u < self.cooldown_seconds:
                        in_u_cooldown = True

                if not in_u_cooldown:
                    dist_alert = self._create_distributed_alert(
                        event.username, list(u_window)
                    )
                    self._last_user_alert_times[user_key] = event.timestamp
                    self.total_alerts += 1
                    return dist_alert

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
        duration = round((end_time - start_time).total_seconds(), 2)

        usernames = [ev.username for ev in events_sorted if ev.username]
        ports = [ev.port for ev in events_sorted if ev.port is not None]

        # Calculate severity and reasons
        severity, reasons = self._calculate_severity(count, usernames)
        reasons.insert(
            0,
            f"threshold_exceeded: {count} failures in {duration}s (window: {self.window_seconds}s)",
        )

        # Deterministic alert_id based on source_ip, start_time, and count
        seed = f"{source_ip}:{start_time.isoformat()}:{count}:{self.window_seconds}"
        alert_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
        alert_id = f"ALERT-FANG-{alert_hash}"

        pattern = (
            f"SSH Brute-Force: {count} failed attempts in "
            f"{duration:.1f}s (Threshold: {self.threshold}/{self.window_seconds}s)"
        )

        # Bound evidence events to prevent JSON bloat during volumetric floods
        evidence_truncated = False
        if len(events_sorted) > self.max_evidence_events:
            half = self.max_evidence_events // 2
            evidence_events = events_sorted[:half] + events_sorted[-half:]
            evidence_truncated = True
        else:
            evidence_events = events_sorted

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
            evidence_events=evidence_events,
            detected_at=datetime.now(timezone.utc),
            severity_reasons=reasons,
            category="brute_force",
            distinct_ips_count=1,
            source_ips=[source_ip],
            is_distributed=False,
            evidence_truncated=evidence_truncated,
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

        seed = (
            f"COMPROMISE:{source_ip}:{start_time.isoformat()}:{accepted_event.username}"
        )
        alert_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
        alert_id = f"ALERT-FANG-COMPROMISE-{alert_hash}"

        reasons = [
            (
                f"compromise_corroborated: accepted login for '{accepted_event.username or 'unknown'}' "
                f"following {count} failed attempts in {duration:.1f}s"
            )
        ]
        if (
            accepted_event.username
            and accepted_event.username.lower() in self.privileged_users
        ):
            reasons.append(
                f"privileged_account_compromised: '{accepted_event.username}'"
            )

        pattern = (
            f"Possible Compromise: Accepted login for '{accepted_event.username or 'unknown'}' "
            f"following {count} failed attempts in {duration:.1f}s"
        )

        all_events = events_sorted + [accepted_event]
        evidence_truncated = False
        if len(all_events) > self.max_evidence_events:
            half = self.max_evidence_events // 2
            evidence_events = all_events[:half] + all_events[-half:]
            evidence_truncated = True
        else:
            evidence_events = all_events

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
            evidence_events=evidence_events,
            detected_at=datetime.now(timezone.utc),
            severity_reasons=reasons,
            category="compromise",
            distinct_ips_count=1,
            source_ips=[source_ip],
            is_distributed=False,
            evidence_truncated=evidence_truncated,
        )

    def _create_distributed_alert(
        self, target_user: str, events: list[SshAuthEvent]
    ) -> SecurityAlert:
        """Construct a distributed spray attack alert across distinct IPs."""
        events_sorted = sorted(events, key=lambda x: x.timestamp)
        start_time = events_sorted[0].timestamp
        end_time = events_sorted[-1].timestamp
        count = len(events_sorted)
        distinct_ips = sorted({ev.source_ip for ev in events_sorted})
        num_ips = len(distinct_ips)
        duration = max(0.1, (end_time - start_time).total_seconds())

        is_priv = (
            target_user.lower() in self.privileged_users and self.escalate_privileged
        )
        if num_ips >= 15 or (is_priv and num_ips >= 10):
            severity = AlertSeverity.CRITICAL
        elif is_priv or num_ips >= 8:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM

        reasons = [
            f"distributed_spray: {count} attempts across {num_ips} distinct IPs targeting '{target_user}' in {duration:.1f}s"
        ]
        if is_priv:
            reasons.append(f"privileged_target: '{target_user}'")

        seed = f"DISTRIBUTED:{target_user}:{start_time.isoformat()}:{num_ips}"
        alert_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
        alert_id = f"ALERT-FANG-DISTRIBUTED-{alert_hash}"

        pattern = (
            f"Distributed SSH Attack: {count} failed attempts across "
            f"{num_ips} distinct IPs targeting '{target_user}' in {duration:.1f}s"
        )

        ports = sorted({ev.port for ev in events_sorted if ev.port is not None})

        evidence_truncated = False
        if len(events_sorted) > self.max_evidence_events:
            half = self.max_evidence_events // 2
            evidence_events = events_sorted[:half] + events_sorted[-half:]
            evidence_truncated = True
        else:
            evidence_events = events_sorted

        return SecurityAlert(
            alert_id=alert_id,
            source_ip="DISTRIBUTED",
            severity=severity,
            pattern=pattern,
            failed_attempts_count=count,
            window_seconds=self.window_seconds,
            start_time=start_time,
            end_time=end_time,
            target_usernames=[target_user],
            ports=ports,
            evidence_events=evidence_events,
            detected_at=datetime.now(timezone.utc),
            severity_reasons=reasons,
            category="distributed_attack",
            distinct_ips_count=num_ips,
            source_ips=distinct_ips,
            is_distributed=True,
            evidence_truncated=evidence_truncated,
        )

    def _calculate_severity(
        self, count: int, usernames: list[str]
    ) -> tuple[AlertSeverity, list[str]]:
        """
        Determine severity and explicit reasoning based on attempt volume and sensitive target accounts.
        """
        reasons: list[str] = []
        privileged_targeted = [
            u for u in usernames if u.lower() in self.privileged_users
        ]
        has_privileged = self.escalate_privileged and bool(privileged_targeted)

        if has_privileged:
            unique_priv = sorted(set(privileged_targeted))
            reasons.append(f"privileged_target_escalation: {', '.join(unique_priv)}")

        if count >= 20:
            reasons.append(f"high_volume_flood: {count} attempts")
            return AlertSeverity.CRITICAL, reasons
        if has_privileged and count >= 10:
            reasons.append(f"privileged_burst: {count} attempts")
            return AlertSeverity.CRITICAL, reasons
        if count >= 10:
            reasons.append(f"elevated_volume: {count} attempts")
            return AlertSeverity.HIGH, reasons
        if has_privileged:
            return AlertSeverity.HIGH, reasons
        if count >= self.threshold:
            reasons.append(f"threshold_met: {count} attempts >= {self.threshold}")
            return AlertSeverity.MEDIUM, reasons

        reasons.append("low_volume")
        return AlertSeverity.LOW, reasons

    def reset(self) -> None:
        """Clear all in-memory detection states."""
        self._ip_windows.clear()
        self._last_alert_times.clear()
        self._user_windows.clear()
        self._last_user_alert_times.clear()
        self.total_alerts = 0

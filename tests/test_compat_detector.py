"""
Unit tests for BruteForceDetector.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fang.detector import BruteForceDetector
from fang.models import AlertSeverity, EventType, SshAuthEvent


def make_event(
    ip: str,
    seconds_offset: int,
    user: str = "guest",
    event_type: EventType = EventType.FAILED_PASSWORD,
) -> SshAuthEvent:
    base = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
    return SshAuthEvent(
        timestamp=base + timedelta(seconds=seconds_offset),
        event_type=event_type,
        source_ip=ip,
        port=2222,
        username=user,
        is_invalid_user=False,
        raw_line=f"raw line {seconds_offset}",
        line_number=seconds_offset + 1,
    )


def test_detector_triggers_on_threshold() -> None:
    detector = BruteForceDetector(threshold=5, window_seconds=60, cooldown_seconds=300)
    alerts = []

    for i in range(5):
        ev = make_event("192.168.1.100", seconds_offset=i * 5, user="user")
        alert = detector.process_event(ev)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "192.168.1.100"
    assert alert.failed_attempts_count == 5
    assert len(alert.evidence_events) == 5
    assert alert.severity == AlertSeverity.MEDIUM


def test_detector_no_alert_below_threshold() -> None:
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    for i in range(4):
        ev = make_event("192.168.1.100", seconds_offset=i * 5)
        alert = detector.process_event(ev)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 0


def test_detector_window_eviction() -> None:
    # 5 attempts, but spaced 30 seconds apart in a 60-second window
    # Window will at most contain 3 attempts at any point
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    for i in range(5):
        ev = make_event("192.168.1.100", seconds_offset=i * 30)
        alert = detector.process_event(ev)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 0


def test_detector_multi_ip_isolation() -> None:
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    # Interleaved attempts between 10.0.0.1 and 10.0.0.2
    for i in range(4):
        detector.process_event(make_event("10.0.0.1", seconds_offset=i * 2))
        detector.process_event(make_event("10.0.0.2", seconds_offset=i * 2))

    # 5th attempt for 10.0.0.1 only
    alert = detector.process_event(make_event("10.0.0.1", seconds_offset=10))
    if alert:
        alerts.append(alert)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "10.0.0.1"
    assert alerts[0].failed_attempts_count == 5


def test_detector_cooldown_deduplication() -> None:
    detector = BruteForceDetector(threshold=5, window_seconds=60, cooldown_seconds=120)
    alerts = []

    # 1st to 5th attempt in 10 seconds -> triggers Alert #1
    for i in range(5):
        alert = detector.process_event(make_event("10.0.0.1", seconds_offset=i * 2))
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1

    # 6th attempt 10 seconds later (within 120s cooldown) -> suppressed
    suppressed = detector.process_event(make_event("10.0.0.1", seconds_offset=20))
    assert suppressed is None

    # New burst after cooldown (150 seconds later)
    for i in range(5):
        alert = detector.process_event(make_event("10.0.0.1", seconds_offset=150 + i * 2))
        if alert:
            alerts.append(alert)

    assert len(alerts) == 2


def test_detector_privileged_user_severity() -> None:
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    for i in range(5):
        user = "root" if i == 4 else "testuser"
        alert = detector.process_event(make_event("10.0.0.1", seconds_offset=i * 2, user=user))
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    # Targeting root elevates severity to HIGH
    assert alerts[0].severity == AlertSeverity.HIGH
    assert "root" in alerts[0].target_usernames

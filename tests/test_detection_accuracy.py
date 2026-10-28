"""
Detection accuracy, false-positive resistance, and edge-case boundary tests for Fang.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fang.detector import BruteForceDetector
from fang.models import EventType, SshAuthEvent
from fang.parser import SshLogParser


def make_event(
    ip: str,
    seconds_offset: int,
    user: str = "root",
    event_type: EventType = EventType.FAILED_PASSWORD,
    base_time: datetime | None = None,
) -> SshAuthEvent:
    if base_time is None:
        base_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta

    return SshAuthEvent(
        timestamp=base_time + timedelta(seconds=seconds_offset),
        event_type=event_type,
        source_ip=ip,
        port=22,
        username=user,
        is_invalid_user=False,
        raw_line=f"Sep 19 12:00:{seconds_offset:02d} srv sshd[1]: Failed password for {user} from {ip} port 22",
        line_number=1,
    )


def test_slow_attempts_produce_zero_false_positives() -> None:
    """
    Verify that slow, distributed-in-time failed attempts (e.g., 1 attempt every 6 minutes)
    do NOT trigger an alert when window is 60 seconds (True Negative / No False Positive).
    """
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    # 10 attempts spaced 120 seconds apart (each outside the 60s sliding window)
    for i in range(10):
        ev = make_event("198.51.100.1", seconds_offset=i * 120, user="admin")
        alert = detector.process_event(ev)
        if alert:
            alerts.append(alert)

    assert (
        len(alerts) == 0
    ), "Slow attempts outside window should never trigger false positives"


def test_interleaved_multi_ip_no_false_positive() -> None:
    """
    Verify that interleaved attempts from multiple IPs, where each IP is below threshold,
    do not cross-contaminate or trigger false alerts.
    """
    detector = BruteForceDetector(
        threshold=5, window_seconds=60, detect_distributed=False
    )
    alerts = []

    # 4 attempts from IP A, 4 from IP B, 4 from IP C interleaved
    ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    for i in range(4):
        for ip in ips:
            ev = make_event(ip, seconds_offset=i * 5, user="user")
            alert = detector.process_event(ev)
            if alert:
                alerts.append(alert)

    assert (
        len(alerts) == 0
    ), "Independent IPs below threshold must not cross-trigger alerts"


def test_cooldown_deduplication_and_rearm() -> None:
    """
    Verify that after an alert triggers, subsequent failures within cooldown are deduplicated,
    and a new alert is only generated after cooldown expires.
    """
    detector = BruteForceDetector(threshold=5, window_seconds=60, cooldown_seconds=180)

    # 1. Trigger first alert at t=0s .. 20s (5 failures)
    first_alert = None
    for i in range(5):
        res = detector.process_event(make_event("198.51.100.44", seconds_offset=i * 4))
        if res:
            first_alert = res

    assert first_alert is not None
    assert first_alert.source_ip == "198.51.100.44"

    # 2. More failures at t=30s, 60s, 100s (within 180s cooldown)
    suppressed_alerts = []
    for i in range(10):
        res = detector.process_event(
            make_event("198.51.100.44", seconds_offset=30 + i * 10)
        )
        if res:
            suppressed_alerts.append(res)

    assert len(suppressed_alerts) == 0, "Events within cooldown must be deduplicated"

    # 3. New burst after cooldown expires (at t=250s .. 270s)
    second_alert = None
    for i in range(5):
        res = detector.process_event(
            make_event("198.51.100.44", seconds_offset=250 + i * 4)
        )
        if res:
            second_alert = res

    assert second_alert is not None, "New alert must trigger after cooldown expires"
    assert (
        second_alert.alert_id != first_alert.alert_id
    ), "Alert IDs must reflect distinct time ranges"


def test_malformed_truncated_and_corrupt_logs_handled_safely() -> None:
    """
    Verify parser and detector resilience against truncated headers, control characters,
    ANSI escape sequences, and invalid IPs.
    """
    parser = SshLogParser(reference_year=2026)
    detector = BruteForceDetector(threshold=5, window_seconds=60)

    malformed_inputs = [
        "",  # Empty line
        "   \t\n",  # Whitespace only
        "Sep 19 12:00:01",  # Truncated before service
        "Sep 19 12:00:01 srv sshd[1]:",  # Empty message
        "Sep 19 12:00:01 srv sshd[1]: Failed password for root from 999.999.999.999 port 22",  # Invalid IP
        "Sep 19 12:00:01 srv sshd[1]: Failed password for root from not-an-ip port 22",  # Non-IP
        "\x1b[31;1mSep 19 12:00:01 srv sshd[1]: Failed password for \x00root from 192.0.2.1 port 22\x1b[0m",  # ANSI & Null bytes
        "2026-10-28T12:00:01.000000+00:00 srv kernel: [12345.678] some hardware warning",  # Non-SSH syslog
        "Sep 19 12:00:01 srv sshd[1]: Connection closed by 192.0.2.1 port 1234 [preauth]",  # Non-failure preauth
    ]

    events = []
    alerts = []
    for line in malformed_inputs:
        ev = parser.parse_line(line)
        if ev:
            events.append(ev)
            alert = detector.process_event(ev)
            if alert:
                alerts.append(alert)

    # Malformed/corrupt lines must never crash parser or trigger false alerts
    assert len(alerts) == 0


def test_benign_accepted_logins_zero_false_positives() -> None:
    """
    Verify that series of legitimate accepted publickey logins produce zero alerts.
    """
    detector = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = []

    for i in range(10):
        ev = make_event(
            "192.0.2.10",
            seconds_offset=i * 2,
            user="deploy",
            event_type=EventType.ACCEPTED_PUBLICKEY,
        )
        res = detector.process_event(ev)
        if res:
            alerts.append(res)

    assert (
        len(alerts) == 0
    ), "Accepted logins alone must never produce brute force alerts"

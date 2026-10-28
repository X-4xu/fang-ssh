"""
Tests for multi-IP distributed brute-force / password spraying detection.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fang.detector import BruteForceDetector
from fang.models import AlertSeverity, EventType, SshAuthEvent


def make_event(ip: str, seconds_offset: int, user: str = "root") -> SshAuthEvent:
    from datetime import timedelta

    base_time = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)
    return SshAuthEvent(
        timestamp=base_time + timedelta(seconds=seconds_offset),
        event_type=EventType.FAILED_PASSWORD,
        source_ip=ip,
        port=22,
        username=user,
        is_invalid_user=False,
        raw_line=f"Sep 19 12:00:{seconds_offset:02d} srv sshd[1]: Failed password for {user} from {ip} port 22",
        line_number=1,
    )


def test_distributed_attack_detected_across_distinct_ips() -> None:
    """
    Test that 5 different IPs sending 1 attempt each targeting 'root'
    triggers a DISTRIBUTED_ATTACK alert even though no single IP reached threshold=5.
    """
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
        detect_distributed=True,
        distributed_threshold=5,
    )

    ips = [
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
        "198.51.100.4",
        "198.51.100.5",
    ]
    alert = None

    for i, ip in enumerate(ips):
        ev = make_event(ip, seconds_offset=i * 2, user="root")
        res = detector.process_event(ev)
        if res:
            alert = res

    assert alert is not None
    assert alert.is_distributed is True
    assert alert.category == "distributed_attack"
    assert alert.target_usernames == ["root"]
    assert alert.distinct_ips_count == 5
    assert len(alert.source_ips) == 5
    assert alert.source_ip == "DISTRIBUTED"
    assert alert.severity == AlertSeverity.HIGH  # root account escalation
    assert any("distributed_spray" in r for r in alert.severity_reasons)
    assert any("privileged_target" in r for r in alert.severity_reasons)


def test_distributed_below_threshold_produces_no_alert() -> None:
    """
    Verify that 3 distinct IPs (below distributed_threshold=5) targeting the same user do not alert.
    """
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
        detect_distributed=True,
        distributed_threshold=5,
    )

    ips = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    alerts = []

    for i, ip in enumerate(ips):
        ev = make_event(ip, seconds_offset=i * 2, user="root")
        res = detector.process_event(ev)
        if res:
            alerts.append(res)

    assert len(alerts) == 0, "Attempts below distributed threshold must not alert"


def test_distributed_window_eviction() -> None:
    """
    Verify that attempts older than the window are evicted from the user window.
    """
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
        detect_distributed=True,
        distributed_threshold=5,
    )

    # 4 distinct IPs at t=0s
    for i in range(4):
        detector.process_event(
            make_event(f"198.51.100.{i+1}", seconds_offset=0, user="admin")
        )

    # 5th IP arrives at t=70s (first 4 have been evicted from 60s window)
    alert = detector.process_event(
        make_event("198.51.100.5", seconds_offset=70, user="admin")
    )
    assert (
        alert is None
    ), "Window eviction should prevent stale distinct IPs from triggering"


def test_distributed_cooldown_deduplication() -> None:
    """
    Verify cooldown suppresses duplicate distributed alerts for the same user.
    """
    detector = BruteForceDetector(
        threshold=5,
        window_seconds=60,
        cooldown_seconds=120,
        detect_distributed=True,
        distributed_threshold=5,
    )

    # Trigger first distributed alert
    for i in range(5):
        res = detector.process_event(
            make_event(f"198.51.100.{i+1}", seconds_offset=i * 2, user="deploy")
        )

    assert res is not None
    assert res.is_distributed is True

    # 5 more IPs within 120s cooldown
    suppressed = None
    for i in range(5, 10):
        res = detector.process_event(
            make_event(f"198.51.100.{i+1}", seconds_offset=15 + i * 2, user="deploy")
        )
        if res:
            suppressed = res

    assert suppressed is None, "Cooldown must prevent alert spam for the targeted user"

"""Detection engine: rules, severities, cooldown/escalation, memory bounds."""

from __future__ import annotations

import time

import pytest

from fang import detector as detector_module
from fang.detector import Detector, DetectorConfig
from fang.models import AlertType, EventType, Severity
from fang.util import Allowlist
from helpers import ev


def feed(det: Detector, events):  # type: ignore[no-untyped-def]
    alerts = []
    for e in events:
        alerts.extend(det.process(e))
    return alerts


def burst(ip: str, n: int, start: float = 0.0, step: float = 1.0, user: str = "alice", **kw):  # type: ignore[no-untyped-def]
    return [ev(ip, start + i * step, user, **kw) for i in range(n)]


# ------------------------------------------------------- fast brute-force


def test_alert_fires_exactly_at_threshold() -> None:
    det = Detector()
    assert feed(det, burst("192.0.2.1", 4)) == []
    alerts = det.process(ev("192.0.2.1", 4))
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.alert_type, a.severity, a.attempts, a.source_ip) == (
        AlertType.BRUTE_FORCE,
        Severity.MEDIUM,
        5,
        "192.0.2.1",
    )
    assert len(a.evidence) == 5
    assert not a.evidence_truncated
    assert a.block_candidates == ["192.0.2.1"]


def test_sliding_window_not_fixed_buckets() -> None:
    # 3 attempts at the end of one minute + 2 at the start of the next: 5 within 60s.
    events = [ev(t=t) for t in (55, 57, 59, 61, 63)]
    assert len(feed(Detector(), events)) == 1


def test_attempts_outside_window_do_not_count() -> None:
    assert feed(Detector(), burst("192.0.2.1", 5, step=30)) == []


def test_ips_are_tracked_independently() -> None:
    det = Detector()
    events = []
    for i in range(4):
        events += [ev("192.0.2.1", i), ev("192.0.2.2", i)]
    assert feed(det, events) == []
    alerts = det.process(ev("192.0.2.1", 5))
    assert [a.source_ip for a in alerts] == ["192.0.2.1"]


def test_severity_scales_with_attempts_and_privileged_users() -> None:
    cases = [
        (5, "alice", Severity.MEDIUM),
        (5, "root", Severity.HIGH),
        (10, "alice", Severity.HIGH),
        (10, "root", Severity.CRITICAL),
        (20, "alice", Severity.CRITICAL),
    ]
    for count, user, expected in cases:
        det = Detector()
        alerts = feed(det, burst("192.0.2.1", count, user=user))
        assert max(a.severity.rank for a in alerts) == expected.rank, (count, user)


def test_severity_scales_with_custom_threshold() -> None:
    det = Detector(DetectorConfig(threshold=3, spray_threshold=0))
    alerts = feed(det, burst("192.0.2.1", 12))
    assert alerts[-1].severity is Severity.CRITICAL


def test_privileged_user_list_is_configurable_and_case_insensitive() -> None:
    det = Detector(DetectorConfig(privileged_users=frozenset({"Postgres"})))
    alerts = feed(det, burst("192.0.2.1", 5, user="POSTGRES"))
    assert alerts[0].severity is Severity.HIGH


# ----------------------------------------------------- cooldown / escalation


def test_cooldown_suppresses_repeats_and_expires() -> None:
    det = Detector(DetectorConfig(cooldown=120, spray_threshold=0))
    first = feed(det, burst("192.0.2.1", 5, step=2))
    assert len(first) == 1
    assert feed(det, [ev("192.0.2.1", 20)]) == []  # same severity, inside cooldown
    assert det.stats.suppressed_alerts >= 1
    second = feed(det, burst("192.0.2.1", 5, start=200, step=2))
    assert len(second) == 1  # cooldown over, new burst


def test_escalation_bypasses_cooldown_exactly_once_per_level() -> None:
    det = Detector(DetectorConfig(spray_threshold=0))
    alerts = feed(det, burst("192.0.2.1", 30, step=0.5))
    assert [a.severity for a in alerts] == [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    assert [a.escalation for a in alerts] == [False, True, True]
    assert len({a.alert_id for a in alerts}) == 3


def test_zero_cooldown_alerts_every_event_past_threshold() -> None:
    det = Detector(DetectorConfig(cooldown=0, spray_threshold=0))
    assert len(feed(det, burst("192.0.2.1", 8))) == 4


def test_alert_ids_are_deterministic() -> None:
    a = feed(Detector(), burst("192.0.2.1", 6))
    b = feed(Detector(), burst("192.0.2.1", 6))
    assert [x.alert_id for x in a] == [x.alert_id for x in b]
    assert a[0].alert_id.startswith("ALERT-FANG-")


def test_evidence_is_capped_and_flagged() -> None:
    det = Detector(DetectorConfig(threshold=30, slow_threshold=0, evidence_limit=5, spray_threshold=0))
    alerts = feed(det, burst("192.0.2.1", 30, step=0.1))
    assert len(alerts) == 1
    assert len(alerts[0].evidence) <= 5
    assert alerts[0].evidence_truncated
    assert alerts[0].attempts == 30


# --------------------------------------------------------------- slow rule


def test_slow_brute_force_detected_once_per_history_window() -> None:
    det = Detector(DetectorConfig(spray_threshold=0))
    alerts = feed(det, burst("192.0.2.1", 30, step=150))  # never 5 within 60s
    assert [a.alert_type for a in alerts] == [AlertType.SLOW_BRUTE_FORCE]
    assert alerts[0].attempts == 20
    assert alerts[0].window_seconds == 3600


def test_slow_rule_stays_quiet_during_fast_attack() -> None:
    alerts = feed(Detector(DetectorConfig(spray_threshold=0)), burst("192.0.2.1", 25, step=1))
    assert {a.alert_type for a in alerts} == {AlertType.BRUTE_FORCE}


def test_slow_rule_can_be_disabled() -> None:
    det = Detector(DetectorConfig(slow_threshold=0, spray_threshold=0, compromise_failures=0))
    assert feed(det, burst("192.0.2.1", 60, step=100)) == []


# ------------------------------------------------------------- distributed


def spray(users: str, n: int, step: float = 5.0):  # type: ignore[no-untyped-def]
    return [ev(f"192.0.2.{i + 1}", i * step, users) for i in range(n)]


def test_distributed_attack_on_one_account() -> None:
    det = Detector()
    assert feed(det, spray("alice", 9)) == []
    alerts = det.process(ev("192.0.2.200", 50, "alice"))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type is AlertType.DISTRIBUTED_ATTACK
    assert a.source_ip is None
    assert len(a.source_ips) == 10
    assert a.target_usernames == ["alice"]
    assert a.severity is Severity.MEDIUM
    assert sorted(a.block_candidates) == sorted(a.source_ips)


def test_distributed_attack_severity() -> None:
    assert feed(Detector(), spray("root", 10))[0].severity is Severity.HIGH
    assert feed(Detector(), spray("alice", 20))[-1].severity is Severity.HIGH
    assert feed(Detector(), spray("alice", 40))[-1].severity is Severity.CRITICAL


def test_distributed_window_expiry_and_different_accounts() -> None:
    assert feed(Detector(), spray("alice", 10, step=100)) == []  # spans 900s > 600s window
    mixed = [ev(f"192.0.2.{i + 1}", i, f"user{i}") for i in range(30)]
    assert feed(Detector(), mixed) == []


def test_distributed_rule_disabled() -> None:
    assert feed(Detector(DetectorConfig(spray_threshold=0)), spray("alice", 30)) == []


# ------------------------------------------------------------- compromise


def compromise_events(kind: EventType, failures: int = 3, gap: float = 5.0):  # type: ignore[no-untyped-def]
    return [
        *burst("192.0.2.1", failures, step=gap, user="bob"),
        ev("192.0.2.1", failures * gap + 1, "bob", kind),
    ]


def test_success_after_failures_is_critical_for_password_logins() -> None:
    det = Detector(DetectorConfig(threshold=50, slow_threshold=0, spray_threshold=0))
    alerts = feed(det, compromise_events(EventType.ACCEPTED_PASSWORD))
    assert [a.alert_type for a in alerts] == [AlertType.POSSIBLE_COMPROMISE]
    a = alerts[0]
    assert a.severity is Severity.CRITICAL
    assert (a.login_username, a.login_method, a.attempts) == ("bob", "password", 3)
    assert a.evidence[-1].event_type is EventType.ACCEPTED_PASSWORD
    assert "same account" in a.pattern


def test_publickey_success_is_high_not_critical() -> None:
    det = Detector(DetectorConfig(threshold=50, slow_threshold=0, spray_threshold=0))
    a = feed(det, compromise_events(EventType.ACCEPTED_PUBLICKEY))[0]
    assert a.severity is Severity.HIGH


def test_no_compromise_alert_below_failure_count_or_for_other_ip_or_when_old() -> None:
    cfg = DetectorConfig(threshold=50, slow_threshold=0, spray_threshold=0)
    assert feed(Detector(cfg), compromise_events(EventType.ACCEPTED_PASSWORD, failures=2)) == []
    other = [*burst("192.0.2.1", 5, user="bob"), ev("192.0.2.99", 6, "bob", EventType.ACCEPTED_PASSWORD)]
    assert feed(Detector(cfg), other) == []
    old = [*burst("192.0.2.1", 5, user="bob"), ev("192.0.2.1", 7200, "bob", EventType.ACCEPTED_PASSWORD)]
    assert feed(Detector(cfg), old) == []


def test_compromise_rule_can_be_disabled_and_allowlist_suppresses() -> None:
    off = DetectorConfig(threshold=50, slow_threshold=0, spray_threshold=0, compromise_failures=0)
    assert feed(Detector(off), compromise_events(EventType.ACCEPTED_PASSWORD)) == []
    trusted = DetectorConfig(
        threshold=50, slow_threshold=0, spray_threshold=0, allowlist=Allowlist(["192.0.2.0/24"])
    )
    det = Detector(trusted)
    assert feed(det, compromise_events(EventType.ACCEPTED_PASSWORD)) == []
    assert det.stats.allowlisted_events == 4


def test_accepted_logins_are_counted() -> None:
    det = Detector()
    det.process(ev(kind=EventType.ACCEPTED_PUBLICKEY))
    assert det.stats.accepted_logins == 1


# ------------------------------------------------------- what is counted


def test_informational_events_never_count() -> None:
    det = Detector()
    informational = (EventType.FAILED_NONE, EventType.INVALID_USER, EventType.AUTH_FAILURE)
    events = [ev("192.0.2.1", i, kind=informational[i % 3]) for i in range(30)]
    assert feed(det, events) == []
    assert det.stats.failed_attempts == 0


def test_one_connection_counts_once_when_it_has_both_failure_and_teardown_lines() -> None:
    det = Detector()
    events = []
    for i in range(3):  # 3 connections: failed password + preauth disconnect + max-auth, same client port
        port = 5000 + i
        events += [
            ev("192.0.2.1", i * 3, kind=EventType.FAILED_PASSWORD, port=port),
            ev("192.0.2.1", i * 3 + 1, kind=EventType.MAX_AUTH_EXCEEDED, port=port),
            ev("192.0.2.1", i * 3 + 2, kind=EventType.PREAUTH_DISCONNECT, port=port),
        ]
    assert feed(det, events) == []
    assert det.stats.failed_attempts == 3


def test_teardown_alone_counts_once_per_connection() -> None:
    det = Detector()
    events = []
    for i in range(5):
        port = 6000 + i
        events += [
            ev("192.0.2.1", i, kind=EventType.MAX_AUTH_EXCEEDED, port=port),
            ev("192.0.2.1", i, kind=EventType.PREAUTH_DISCONNECT, port=port),
        ]
    alerts = feed(det, events)
    assert len(alerts) == 1
    assert det.stats.failed_attempts == 5


def test_preauth_counting_can_be_disabled() -> None:
    det = Detector(DetectorConfig(count_preauth_disconnects=False))
    assert (
        feed(det, [ev("192.0.2.1", i, kind=EventType.PREAUTH_DISCONNECT, port=7000 + i) for i in range(10)])
        == []
    )


def test_repeat_weight_counts_every_repetition() -> None:
    alerts = feed(Detector(), [ev(weight=5)])
    assert len(alerts) == 1
    assert alerts[0].attempts == 5
    assert alerts[0].evidence_truncated is False


# --------------------------------------------------------------- allowlist


def test_allowlisted_addresses_never_alert() -> None:
    det = Detector(DetectorConfig(allowlist=Allowlist(["192.0.2.0/24", "2001:db8::/32"])))
    assert feed(det, burst("192.0.2.77", 50)) == []
    assert feed(det, burst("2001:db8::5", 50)) == []
    assert det.stats.allowlisted_events == 100
    assert feed(det, burst("198.51.100.1", 5))  # not allow-listed


# --------------------------------------------------------- bounds / hygiene


def test_tracked_ips_are_bounded_by_lru() -> None:
    det = Detector(DetectorConfig(max_tracked_ips=100, max_tracked_users=100, spray_threshold=0))
    for i in range(1000):
        det.process(ev(f"10.{i // 256}.{i % 256}.1", i, f"u{i}"))
    assert det.tracked_ips <= 100
    assert det.stats.evicted_states >= 900
    assert len(det.top_offenders(5)) == 5  # retired state still feeds the offender board


def test_active_attacker_survives_eviction_pressure() -> None:
    det = Detector(DetectorConfig(max_tracked_ips=100, spray_threshold=0))
    alerts = []
    for i in range(600):
        alerts += det.process(ev(f"10.1.{i // 256}.{i % 256}", i * 0.01))
        if i % 3 == 0:
            alerts += det.process(ev("192.0.2.1", i * 0.01))
    assert any(a.source_ip == "192.0.2.1" for a in alerts)


def test_idle_state_is_pruned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector_module, "_PRUNE_EVERY", 50)
    det = Detector(DetectorConfig(spray_threshold=0))
    for i in range(50):
        det.process(ev(f"10.0.0.{i + 1}", i))
    assert det.tracked_ips == 50
    for i in range(50):  # two hours later: everything above is idle
        det.process(ev("192.0.2.1", 7200 + i))
    assert det.tracked_ips <= 2
    assert {o["ip"] for o in det.top_offenders(100)} >= {f"10.0.0.{i + 1}" for i in range(50)}


def test_out_of_order_events_are_tolerated() -> None:
    det = Detector()
    times = [0, 2, 1, 4, 3, 100, 99, 101, 98]
    feed(det, [ev(t=t) for t in times])  # must not raise
    assert det.stats.failed_attempts == len(times)


def test_flood_stays_bounded_and_fast() -> None:
    det = Detector(DetectorConfig(spray_threshold=0))
    start = time.perf_counter()
    for i in range(50_000):
        det.process(ev("192.0.2.1", i * 0.001, "root"))
    assert time.perf_counter() - start < 15
    assert det.stats.failed_attempts == 50_000
    ip_state = next(iter(det._ips.values()))
    assert len(ip_state.fast.items) <= det.config.max_events_per_window
    assert len(ip_state.evidence) <= det.config.evidence_limit


def test_top_offenders_ranking() -> None:
    det = Detector(DetectorConfig(threshold=1000, spray_threshold=0, slow_threshold=0, compromise_failures=0))
    feed(det, burst("192.0.2.1", 3) + burst("192.0.2.2", 7, user="root") + burst("192.0.2.3", 5))
    top = det.top_offenders(2)
    assert [o["ip"] for o in top] == ["192.0.2.2", "192.0.2.3"]
    assert top[0]["failed_attempts"] == 7
    assert top[0]["usernames"] == ["root"]


def test_finalize_reports_unique_ips() -> None:
    det = Detector()
    feed(det, [ev("192.0.2.1", 0), ev("192.0.2.2", 1), ev("192.0.2.1", 2)])
    assert det.finalize().unique_source_ips == 2


# -------------------------------------------------------- config validation


@pytest.mark.parametrize(
    "kwargs",
    [
        {"threshold": 0},
        {"threshold": -1},
        {"window": 0},
        {"cooldown": -1},
        {"slow_threshold": 3},  # would mislabel fast bursts as slow
        {"spray_threshold": 1},
        {"history_window": 30, "window": 60},
        {"max_tracked_ips": 5},
        {"evidence_limit": 0},
        {"threshold": True},
        {"window": 10**9},
    ],
)
def test_invalid_configuration_is_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"must|between|threshold|lower than"):
        DetectorConfig(**kwargs)  # type: ignore[arg-type]


def test_config_to_dict_is_json_friendly() -> None:
    import json

    cfg = DetectorConfig(allowlist=Allowlist(["10.0.0.0/8"]))
    data = json.loads(json.dumps(cfg.to_dict()))
    assert data["allowlist"] == ["10.0.0.0/8"]
    assert data["privileged_users"] == sorted(cfg.privileged_users)

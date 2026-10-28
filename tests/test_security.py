"""Adversarial inputs: regex denial of service, injection and resource exhaustion."""

from __future__ import annotations

import time

import pytest

from fang.detector import Detector
from fang.parser import MAX_LINE_LENGTH, SshLogParser

HEAD = "Sep 19 10:00:10 host sshd[1]: "


def timed_parse(line: str) -> float:
    parser = SshLogParser(reference_year=2026)
    start = time.perf_counter()
    parser.parse_line(line)
    return time.perf_counter() - start


@pytest.mark.parametrize(
    "message",
    [
        "Failed password for invalid user " + "a " * 1900 + "from 1.2.3.4 port 1 ssh2",
        "Failed password for " + " from x port 1" * 280,
        "Failed password for " + "from " * 700 + "port 1",
        "Accepted publickey for " + "port 1 from 1.2.3.4 " * 190,
        "Invalid user " + " from 1.2.3.4" * 300,
        "Connection closed by authenticating user " + "a port 1 [preauth] " * 200,
        "error: maximum authentication attempts exceeded for " + "x from 1.2.3.4 port 1 " * 170,
        "Failed password for root from " + "1" * 3500 + " port 22",
        "Failed password for root from 1.2.3.4 port " + "9" * 3500,
        "message repeated 3 times: [ " + "Failed password for " * 180 + "]",
        "pam_unix(sshd:auth): authentication failure; " + "rhost= " * 500,
        " " * 4000 + "sshd",
    ],
)
def test_pathological_messages_parse_in_bounded_time(message: str) -> None:
    line = (HEAD + message)[:MAX_LINE_LENGTH]
    assert timed_parse(line) < 0.25


def test_pathological_headers_parse_in_bounded_time() -> None:
    for header in ("Sep" + " " * 4000, "2026-09-19T10:00:10" + "9" * 4000, "Sep 19 10:00:10 " + "h" * 4000):
        assert timed_parse(header[:MAX_LINE_LENGTH] + " sshd[1]: x") < 0.25


def test_many_pathological_lines_total_time() -> None:
    parser = SshLogParser(reference_year=2026)
    line = (
        HEAD + "Failed password for invalid user " + "a from b port 1 " * 200 + "from 192.0.2.1 port 22 ssh2"
    )[:MAX_LINE_LENGTH]
    start = time.perf_counter()
    for _ in range(500):
        parser.parse_line(line)
    assert time.perf_counter() - start < 5


def test_forged_source_cannot_cause_a_victim_to_be_flagged() -> None:
    """An attacker names their account after a victim's address; only the attacker's IP is tracked."""
    parser = SshLogParser(reference_year=2026)
    det = Detector()
    flagged: set[str] = set()
    for i in range(30):
        e = parser.parse_line(
            f"{HEAD}Failed password for invalid user x from 192.0.2.250 port 22 from 198.51.100.7 port {4000 + i} ssh2"
        )
        assert e is not None
        for alert in det.process(e):
            flagged.update(alert.source_ips)
    assert flagged == {"198.51.100.7"}
    assert "192.0.2.250" not in {o["ip"] for o in det.top_offenders(50)}


def test_username_flood_cannot_grow_memory_without_bound() -> None:
    det = Detector()
    cap = det.config.max_tracked_users
    parser = SshLogParser(reference_year=2026)
    for i in range(cap + 5000):
        e = parser.parse_line(
            f"{HEAD}Failed password for invalid user u{i} from 192.0.2.1 port {1024 + i % 60000} ssh2"
        )
        assert e is not None
        det.process(e)
    assert len(det._users) <= cap
    assert det.tracked_ips == 1


def test_many_source_addresses_cannot_grow_memory_without_bound() -> None:
    det = Detector()
    parser = SshLogParser(reference_year=2026)
    cap = det.config.max_tracked_ips
    for i in range(cap + 3000):
        ip = f"{(i >> 16) & 255 or 1}.{(i >> 8) & 255}.{i & 255}.7"
        e = parser.parse_line(f"{HEAD}Failed password for root from {ip} port 22 ssh2")
        if e is not None:
            det.process(e)
    assert det.tracked_ips <= cap
    assert det.stats.evicted_states >= 3000

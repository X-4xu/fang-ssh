"""
Unit tests for SshLogParser.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from fang.models import EventType
from fang.parser import SshLogParser


def test_parse_classic_syslog_failed_password() -> None:
    parser = SshLogParser(reference_year=2026)
    line = "Sep 19 10:00:10 web-server sshd[2001]: Failed password for invalid user admin from 192.168.1.100 port 40001 ssh2"
    event = parser.parse_line(line, line_number=1)

    assert event is not None
    assert event.event_type == EventType.FAILED_PASSWORD
    assert event.source_ip == "192.168.1.100"
    assert event.port == 40001
    assert event.username == "admin"
    assert event.is_invalid_user is True
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 19
    assert event.timestamp.hour == 10
    assert event.line_number == 1


def test_parse_classic_syslog_valid_user_failure() -> None:
    parser = SshLogParser(reference_year=2026)
    line = "Sep 19 10:00:22 web-server sshd[2004]: Failed password for root from 192.168.1.100 port 40004 ssh2"
    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == EventType.FAILED_PASSWORD
    assert event.source_ip == "192.168.1.100"
    assert event.username == "root"
    assert event.is_invalid_user is False


def test_parse_rfc3339_timestamp() -> None:
    parser = SshLogParser()
    line = "2026-09-19T08:12:00.100000+00:00 bastion sshd[3001]: Failed password for root from 203.0.113.42 port 51000 ssh2"
    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == EventType.FAILED_PASSWORD
    assert event.source_ip == "203.0.113.42"
    assert event.username == "root"
    assert event.port == 51000
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 9
    assert event.timestamp.day == 19
    assert event.timestamp.hour == 8
    assert event.timestamp.tzinfo is not None


def test_parse_journalctl_short_iso_timestamp() -> None:
    parser = SshLogParser()
    line = "2026-10-28T12:00:01+0000 srv sshd[1001]: Failed password for root from 198.51.100.22 port 22 ssh2"
    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == EventType.FAILED_PASSWORD
    assert event.source_ip == "198.51.100.22"
    assert event.username == "root"
    assert event.timestamp.year == 2026
    assert event.timestamp.month == 10
    assert event.timestamp.day == 28
    assert event.timestamp.hour == 12


def test_parse_pam_failure() -> None:
    parser = SshLogParser()
    line = "2026-09-19T08:12:15.700000+00:00 bastion sshd[3007]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.42  user=admin"
    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.source_ip == "203.0.113.42"
    assert event.username == "admin"


def test_parse_accepted_login() -> None:
    parser = SshLogParser(reference_year=2026)
    line = "Sep 19 10:10:00 web-server sshd[2008]: Accepted publickey for devops from 192.168.1.50 port 35000 ssh2: RSA SHA256:abc123xyz"
    event = parser.parse_line(line)

    assert event is not None
    assert event.event_type == EventType.ACCEPTED_PUBLICKEY
    assert event.source_ip == "192.168.1.50"
    assert event.username == "devops"
    assert not event.event_type.is_failure


def test_parse_ipv6() -> None:
    parser = SshLogParser(reference_year=2026)
    line = "Sep 19 10:00:10 host sshd[1]: Failed password for root from 2001:db8::1 port 2222 ssh2"
    event = parser.parse_line(line)

    assert event is not None
    assert event.source_ip == "2001:db8::1"


def test_malformed_and_irrelevant_lines(malformed_log_path: Path) -> None:
    parser = SshLogParser()
    events = list(parser.parse_file(malformed_log_path))
    # Malformed lines with invalid IPs or non-SSH messages should be gracefully ignored
    for ev in events:
        assert ev.source_ip != "999.999.999.999"


def test_parse_file_classic(classic_log_path: Path) -> None:
    parser = SshLogParser(reference_year=2026)
    events = list(parser.parse_file(classic_log_path))
    assert len(events) >= 8
    failed = [e for e in events if e.event_type.is_failure]
    assert len(failed) >= 7


def test_parse_file_gzip(gzip_log_path: Path) -> None:
    parser = SshLogParser(reference_year=2026)
    events = list(parser.parse_file(gzip_log_path))
    assert len(events) >= 8


def test_missing_file_raises_error() -> None:
    parser = SshLogParser()
    with pytest.raises(FileNotFoundError):
        list(parser.parse_file("non_existent_file.log"))


def test_follow_file_appends(tmp_path: Path) -> None:
    import threading
    import time

    log_file = tmp_path / "auth_follow.log"
    log_file.write_text(
        "Sep 19 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n",
        encoding="utf-8",
    )

    parser = SshLogParser(reference_year=2026)
    stop_event = threading.Event()
    collected = []

    def tail_worker():
        for ev in parser.follow_file(
            log_file, poll_interval=0.05, stop_event=stop_event
        ):
            collected.append(ev)

    t = threading.Thread(target=tail_worker, daemon=True)
    t.start()

    time.sleep(0.15)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(
            "Sep 19 10:00:05 srv sshd[2]: Failed password for admin from 192.0.2.1 port 22 ssh2\n"
        )
        f.flush()

    time.sleep(0.15)
    stop_event.set()
    t.join(timeout=2.0)

    assert len(collected) == 2
    assert collected[0].username == "root"
    assert collected[1].username == "admin"


def test_follow_file_truncation(tmp_path: Path) -> None:
    import threading
    import time

    log_file = tmp_path / "auth_trunc.log"
    # Write a longer initial log line
    log_file.write_text(
        "Sep 19 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.2 port 22 ssh2 [initial long line padding abcdefghijklmnopqrstuvwxyz]\n",
        encoding="utf-8",
    )

    parser = SshLogParser(reference_year=2026)
    stop_event = threading.Event()
    collected = []

    def tail_worker():
        for ev in parser.follow_file(
            log_file, poll_interval=0.05, stop_event=stop_event
        ):
            collected.append(ev)

    t = threading.Thread(target=tail_worker, daemon=True)
    t.start()

    time.sleep(0.15)
    # Truncate and write a shorter new line
    log_file.write_text(
        "Sep 19 10:00:10 srv sshd[3]: Failed password for user1 from 192.0.2.2 port 22 ssh2\n",
        encoding="utf-8",
    )

    time.sleep(0.15)
    stop_event.set()
    t.join(timeout=2.0)

    assert len(collected) == 2
    assert collected[1].username == "user1"

"""Parser behaviour: formats, normalization, sanitizing and injection resistance."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from fang.models import AnalysisStats, EventType
from fang.parser import MAX_REPEAT, SshLogParser


def parse(line: str, **kwargs: object):  # type: ignore[no-untyped-def]
    return SshLogParser(reference_year=2026, **kwargs).parse_line(line)  # type: ignore[arg-type]


FAILED = "Sep 19 10:00:10 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"


def test_basic_failed_password() -> None:
    e = parse(FAILED)
    assert e is not None
    assert (e.event_type, e.source_ip, e.username, e.port, e.pid, e.host) == (
        EventType.FAILED_PASSWORD, "192.0.2.1", "root", 22, 1, "host",
    )  # fmt: skip
    assert e.auth_method == "password"
    assert e.timestamp == datetime(2026, 9, 19, 10, 0, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("message", "kind"),
    [
        ("Failed publickey for root from 192.0.2.1 port 22 ssh2: RSA SHA256:abc", EventType.FAILED_PUBLICKEY),
        ("Failed keyboard-interactive/pam for root from 192.0.2.1 port 22 ssh2", EventType.FAILED_OTHER),
        ("Failed none for invalid user x from 192.0.2.1 port 22 ssh2", EventType.FAILED_NONE),
        ("Accepted password for bob from 192.0.2.1 port 22 ssh2", EventType.ACCEPTED_PASSWORD),
        ("Accepted publickey for bob from 192.0.2.1 port 22 ssh2: ED25519 SHA256:abc", EventType.ACCEPTED_PUBLICKEY),
        ("Accepted keyboard-interactive/pam for bob from 192.0.2.1 port 22 ssh2", EventType.ACCEPTED_OTHER),
        ("Invalid user admin from 192.0.2.1 port 4000", EventType.INVALID_USER),
        ("Invalid user admin from 192.0.2.1", EventType.INVALID_USER),
        ("Connection closed by authenticating user root 192.0.2.1 port 22 [preauth]", EventType.PREAUTH_DISCONNECT),
        ("Disconnected from invalid user admin 192.0.2.1 port 22 [preauth]", EventType.PREAUTH_DISCONNECT),
        ("error: maximum authentication attempts exceeded for root from 192.0.2.1 port 22 ssh2 [preauth]", EventType.MAX_AUTH_EXCEEDED),
        ("error: maximum authentication attempts exceeded for invalid user a from 192.0.2.1 port 22 ssh2", EventType.MAX_AUTH_EXCEEDED),
    ],
)  # fmt: skip
def test_message_variants(message: str, kind: EventType) -> None:
    e = parse(f"Sep 19 10:00:10 host sshd[1]: {message}")
    assert e is not None
    assert e.event_type is kind
    assert e.source_ip == "192.0.2.1"


@pytest.mark.parametrize(
    "message",
    [
        "Connection closed by 192.0.2.1 port 22 [preauth]",  # no user: health checks / port scans
        "Disconnected from user bob 192.0.2.1 port 22",  # normal logout
        "Connection closed by authenticating user root 192.0.2.1 port 22",  # post-auth, no [preauth]
        "Server listening on 0.0.0.0 port 22.",
        "Did not receive identification string from 192.0.2.1 port 22",
    ],
)
def test_irrelevant_messages_are_ignored(message: str) -> None:
    assert parse(f"Sep 19 10:00:10 host sshd[1]: {message}") is None


def test_pam_line_is_informational_event() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.9  user=admin"
    )
    assert e is not None
    assert (e.event_type, e.source_ip, e.username) == (EventType.AUTH_FAILURE, "192.0.2.9", "admin")
    assert e.event_type.is_failure


def test_pam_line_cannot_spoof_rhost_through_username() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.9  user=x rhost=6.6.6.6  user=y"
    )
    assert e is not None
    assert e.source_ip == "192.0.2.9"


def test_pam_more_failures_line() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: PAM 2 more authentication failures; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.9  user=root"
    )
    assert e is not None
    assert e.event_type is EventType.AUTH_FAILURE


# --------------------------------------------------------------- timestamps


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-09-19T08:12:34.567890+00:00",
        "2026-09-19T08:12:34.567890+0000",  # journalctl -o short-iso-precise
        "2026-09-19T08:12:34+00",
        "2026-09-19T08:12:34Z",
        "2026-09-19T08:12:34.123456789Z",  # nanoseconds
        "2026-09-19 08:12:34,5+00:00",
    ],
)
def test_iso_timestamp_variants(stamp: str) -> None:
    e = SshLogParser().parse_line(
        f"{stamp} host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert e.timestamp.utcoffset() == timedelta(0)
    assert (e.timestamp.hour, e.timestamp.minute, e.timestamp.second) == (8, 12, 34)


def test_iso_timestamp_with_offset_is_preserved() -> None:
    e = SshLogParser().parse_line(
        "2026-09-19T11:12:34+03:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert e.timestamp == datetime(2026, 9, 19, 8, 12, 34, tzinfo=timezone.utc)


def test_iso_timestamp_without_offset_uses_assumed_tz() -> None:
    tz = ZoneInfo("Asia/Baghdad")
    e = SshLogParser(assume_tz=tz).parse_line(
        "2026-09-19T11:12:34 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert e.timestamp == datetime(2026, 9, 19, 8, 12, 34, tzinfo=timezone.utc)


def test_invalid_timestamp_offsets_and_dates_are_rejected() -> None:
    p = SshLogParser()
    tail = "host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    assert p.parse_line(f"2026-09-19T08:12:34+25:00 {tail}") is None
    assert p.parse_line(f"2026-13-45T08:12:34Z {tail}") is None
    assert p.parse_line(f"Sep 32 10:00:10 {tail}") is None
    assert SshLogParser(reference_year=2026).parse_line(f"Xyz 19 10:00:10 {tail}") is None


def test_year_inference_across_new_year() -> None:
    ref = datetime(2027, 1, 3, tzinfo=timezone.utc)
    p = SshLogParser(reference_time=ref)
    tail = "host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    dec = p.parse_line(f"Dec 31 23:59:59 {tail}")
    jan = p.parse_line(f"Jan  2 00:00:01 {tail}")
    assert dec is not None
    assert jan is not None
    assert dec.timestamp.year == 2026
    assert jan.timestamp.year == 2027
    assert dec.timestamp < jan.timestamp


def test_year_inference_leap_day() -> None:
    p = SshLogParser(reference_time=datetime(2026, 3, 10, tzinfo=timezone.utc))
    e = p.parse_line("Feb 29 10:00:00 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2")
    assert e is not None
    assert e.timestamp.year == 2024


def test_year_inference_tolerates_one_day_of_clock_skew() -> None:
    p = SshLogParser(reference_time=datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
    tail = "host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    near = p.parse_line(f"Oct 26 08:00:00 {tail}")
    far = p.parse_line(f"Nov 20 08:00:00 {tail}")
    assert near is not None
    assert far is not None
    assert near.timestamp.year == 2026
    assert far.timestamp.year == 2025


def test_padded_day_with_two_spaces() -> None:
    e = parse("Sep  9 10:00:10 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2")
    assert e is not None
    assert e.timestamp.day == 9


# ------------------------------------------------------------- program tags


@pytest.mark.parametrize("prog", ["sshd", "sshd-session", "sshd-auth", "/usr/sbin/sshd"])
def test_accepted_program_names(prog: str) -> None:
    e = parse(f"Sep 19 10:00:10 host {prog}[1]: Failed password for root from 192.0.2.1 port 22 ssh2")
    assert e is not None


@pytest.mark.parametrize("prog", ["sudo", "notsshd", "sshd2", "mysshd-wrapper"])
def test_other_programs_are_ignored(prog: str) -> None:
    assert (
        parse(f"Sep 19 10:00:10 host {prog}[1]: Failed password for root from 192.0.2.1 port 22 ssh2") is None
    )


def test_pid_is_optional_and_pri_prefix_is_stripped() -> None:
    e = parse("<38>Sep 19 10:00:10 host sshd: Failed password for root from 192.0.2.1 port 22 ssh2")
    assert e is not None
    assert e.pid is None


def test_lines_without_a_valid_header_are_ignored() -> None:
    assert parse("Failed password for root from 192.0.2.1 port 22 ssh2 sshd") is None
    assert parse("sshd: Failed password for root from 192.0.2.1 port 22 ssh2") is None
    assert parse("") is None


# ------------------------------------------------------------ repeat counts


def test_rsyslog_repeated_message_sets_weight() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: message repeated 7 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]"
    )
    assert e is not None
    assert e.weight == 7
    assert e.to_dict()["repeat_count"] == 7


def test_repeat_weight_is_capped() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: message repeated 999999 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]"
    )
    assert e is not None
    assert e.weight == MAX_REPEAT


def test_repeated_wrapper_around_garbage_is_ignored() -> None:
    assert parse("Sep 19 10:00:10 host sshd[1]: message repeated 3 times: [ something else entirely]") is None


# ------------------------------------------------------------- IP handling


def test_invalid_ips_are_dropped_and_counted() -> None:
    stats = AnalysisStats()
    p = SshLogParser(reference_year=2026, stats=stats)
    for bad in ("999.999.999.999", "not-an-ip", "1.2.3", "01.02.03.04", "1.2.3.4.5", "", "a" * 100):
        assert (
            p.parse_line(f"Sep 19 10:00:10 host sshd[1]: Failed password for root from {bad} port 22 ssh2")
            is None
        )
    assert stats.invalid_ip_lines >= 5


def test_ipv6_and_normalization() -> None:
    def ip_of(addr: str) -> str | None:
        e = parse(f"Sep 19 10:00:10 host sshd[1]: Failed password for root from {addr} port 22 ssh2")
        return e.source_ip if e else None

    assert ip_of("2001:db8::1") == "2001:db8::1"
    assert ip_of("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert ip_of("::ffff:192.0.2.7") == "192.0.2.7"
    assert ip_of("fe80::1%eth0") == "fe80::1"


def test_invalid_port_becomes_none() -> None:
    e = parse("Sep 19 10:00:10 host sshd[1]: Failed password for root from 192.0.2.1 port 99999 ssh2")
    assert e is not None
    assert e.port is None


# --------------------------------------------------- hostile content / safety


def test_username_cannot_forge_the_source_address() -> None:
    stats = AnalysisStats()
    p = SshLogParser(reference_year=2026, stats=stats)
    e = p.parse_line(
        "Sep 19 10:00:10 host sshd[1]: Failed password for invalid user x from 6.6.6.6 port 1 "
        "from 192.0.2.50 port 4444 ssh2"
    )
    assert e is not None
    assert e.source_ip == "192.0.2.50"
    assert e.port == 4444
    assert e.username == "x from 6.6.6.6 port 1"
    assert stats.suspicious_lines == 1


def test_forged_address_in_username_for_every_message_type() -> None:
    forged = "x from 6.6.6.6 port 1"
    messages = [
        f"Failed password for {forged} from 192.0.2.50 port 4444 ssh2",
        f"Accepted password for {forged} from 192.0.2.50 port 4444 ssh2",
        f"Invalid user {forged} from 192.0.2.50 port 4444",
        f"Connection closed by authenticating user {forged} 192.0.2.50 port 4444 [preauth]",
        f"error: maximum authentication attempts exceeded for {forged} from 192.0.2.50 port 4444 ssh2 [preauth]",
    ]
    for message in messages:
        e = parse(f"Sep 19 10:00:10 host sshd[1]: {message}")
        assert e is not None, message
        assert e.source_ip == "192.0.2.50", message


def test_usernames_with_spaces_are_preserved() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: Failed password for invalid user a b  c from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert e.username == "a b  c"


def test_control_escape_and_bidi_characters_are_stripped() -> None:
    nasty = "\x1b[31mroot‮​\x07\x00"
    e = parse(
        f"Sep 19 10:00:10 host sshd[1]: Failed password for invalid user {nasty} from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    for text in (e.username, e.raw_line, e.host):
        assert "\x1b" not in text
        assert "‮" not in text
        assert "​" not in text
        assert "\x00" not in text
        assert text.isprintable()


def test_non_ascii_printable_usernames_are_kept() -> None:
    e = parse(
        "Sep 19 10:00:10 host sshd[1]: Failed password for invalid user حسن from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert e.username == "حسن"


def test_long_username_is_truncated() -> None:
    e = parse(
        f"Sep 19 10:00:10 host sshd[1]: Failed password for invalid user {'a' * 500} from 192.0.2.1 port 22 ssh2"
    )
    assert e is not None
    assert len(e.username) <= 128


def test_oversized_line_is_rejected_and_counted() -> None:
    stats = AnalysisStats()
    p = SshLogParser(reference_year=2026, stats=stats)
    line = (
        "Sep 19 10:00:10 host sshd[1]: Failed password for invalid user "
        + "a" * 5000
        + " from 192.0.2.1 port 22 ssh2"
    )
    assert p.parse_line(line) is None
    assert stats.oversized_lines == 1


# ----------------------------------------------------------------- journald


def journal(
    message: object = "Failed password for root from 192.0.2.1 port 22 ssh2", **override: object
) -> str:
    obj: dict[str, object] = {
        "__REALTIME_TIMESTAMP": "1789000000123456",
        "_HOSTNAME": "node1",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "321",
        "MESSAGE": message,
    }
    obj.update(override)
    return json.dumps(obj)


def test_journald_json_line() -> None:
    e = SshLogParser().parse_line(journal())
    assert e is not None
    assert (e.source_ip, e.username, e.host, e.pid) == ("192.0.2.1", "root", "node1", 321)
    assert e.timestamp == datetime.fromtimestamp(1789000000.123456, tz=timezone.utc)


@pytest.mark.parametrize(
    "line",
    [
        journal(message=["binary", 1, 2]),  # journald encodes non-UTF-8 messages as arrays
        journal(**{"SYSLOG_IDENTIFIER": "cron"}),
        journal(**{"__REALTIME_TIMESTAMP": "abc"}),
        journal(**{"__REALTIME_TIMESTAMP": "9" * 30}),
        journal(**{"__REALTIME_TIMESTAMP": None}),
        '{"MESSAGE": "sshd", ',
        "{" + '"a":[' * 10000 + "sshd",
        "[1,2,3] sshd",
        '{"SYSLOG_IDENTIFIER": "sshd"}',
    ],
)
def test_malformed_journald_json_is_ignored(line: str) -> None:
    assert SshLogParser().parse_line(line) is None


def test_journald_falls_back_to_comm_field() -> None:
    line = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1789000000000000",
            "_COMM": "sshd",
            "MESSAGE": "Failed password for root from 192.0.2.1 port 22 ssh2",
        }
    )
    assert SshLogParser().parse_line(line) is not None


# ---------------------------------------------------------------- robustness


def test_parser_never_raises_on_random_input() -> None:
    rng = random.Random(1234)
    alphabet = "sshd[]:<>{}\"' fromportFailedpasswordforinvaliduser0123456789.:%-\x00\x1b‮\n"
    p = SshLogParser(reference_year=2026)
    prefixes = ["", "Sep 19 10:00:10 h sshd[1]: ", "2026-09-19T10:00:10Z h sshd[1]: ", "{"]
    for _ in range(3000):
        body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        p.parse_line(rng.choice(prefixes) + body)


def test_parse_file_sets_source_label(classic_log_path) -> None:  # type: ignore[no-untyped-def]
    events = list(SshLogParser(reference_year=2026).parse_file(classic_log_path))
    assert events
    assert all(e.source == str(classic_log_path) for e in events)

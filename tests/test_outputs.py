"""Console, JSONL, blocklist, dry-run hook, report and file-safety helpers."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

import pytest

from fang.analyzer import Analyzer
from fang.console import ConsoleAlertHandler, render_alert, render_summary, use_color
from fang.detector import Detector, DetectorConfig
from fang.handlers import BlocklistHandler, JsonlAlertHandler, NetAccessControllerHook
from fang.models import AlertType, EventType, SecurityAlert, Severity
from fang.report import SCHEMA_VERSION, build_report, write_report
from fang.util import Allowlist, atomic_write_text, is_protected_ip, normalize_ip, sanitize_text
from helpers import ev


def alert_for(ip: str = "192.0.2.1", n: int = 5, user: str = "alice") -> SecurityAlert:
    det = Detector(DetectorConfig(spray_threshold=0))
    alerts = []
    for i in range(n):
        alerts += det.process(ev(ip, i, user))
    assert alerts
    return alerts[-1]


def spray_alert() -> SecurityAlert:
    det = Detector()
    alerts = []
    for i in range(10):
        alerts += det.process(ev(f"192.0.2.{i + 1}", i, "root"))
    return next(a for a in alerts if a.alert_type is AlertType.DISTRIBUTED_ATTACK)


# ------------------------------------------------------------------ util


def test_sanitize_text() -> None:
    assert sanitize_text("plain text 123") == "plain text 123"
    assert sanitize_text("a\x1b[31mb‮c​d\x00e\tf") == "a?[31mb?c?d?e?f"
    assert sanitize_text("x" * 500, 10) == "x" * 10
    assert sanitize_text("\ud800") == "?"  # lone surrogate would crash print()/encode()
    assert sanitize_text("مرحبا") == "مرحبا"


def test_normalize_and_protected_ips() -> None:
    assert normalize_ip("::ffff:192.0.2.1") == "192.0.2.1"
    assert normalize_ip("fe80::1%eth0") == "fe80::1"
    assert normalize_ip("2001:DB8::0001") == "2001:db8::1"
    for bad in ("", "1.2.3", "300.1.1.1", "01.1.1.1", "host.example", "x" * 80):
        assert normalize_ip(bad) is None
    for ip in ("127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1", "240.0.0.1"):
        assert is_protected_ip(ip), ip
    for ip in ("192.0.2.1", "10.0.0.1", "192.168.1.1", "2001:db8::1"):
        assert not is_protected_ip(ip), ip
    assert is_protected_ip("garbage")


def test_allowlist_matching_and_validation() -> None:
    allow = Allowlist(
        ["10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "203.0.113.5/24"]
    )  # host bits are tolerated
    assert "10.9.8.7" in allow
    assert "192.0.2.7" in allow
    assert "192.0.2.8" not in allow
    assert "2001:db8:1::1" in allow
    assert "::ffff:10.1.1.1" in allow  # mapped form is the same host
    assert "203.0.113.200" in allow
    assert "not an ip" not in allow
    assert 5 not in allow
    assert len(allow) == 4
    assert "10.0.0.0/8" in list(allow)
    for bad in ("", "  ", "10.0.0.0/33", "banana", "::ffff:10.0.0.0/104"):
        with pytest.raises(ValueError, match="allowlist|empty|IPv4"):
            Allowlist([bad])


def test_atomic_write_text_permissions_and_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "out.txt"
    atomic_write_text(target, "one\n")
    assert target.read_text() == "one\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    atomic_write_text(target, "two\n")
    assert target.read_text() == "two\n"
    with pytest.raises(OSError):  # target is a directory -> failure must not leave temp files behind
        atomic_write_text(tmp_path, "x")
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".fang-")]


def test_atomic_write_replaces_symlink_instead_of_following_it(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    link = tmp_path / "report.json"
    link.symlink_to(victim)
    atomic_write_text(link, "new content")
    assert victim.read_text() == "precious"
    assert not link.is_symlink()
    assert link.read_text() == "new content"


# --------------------------------------------------------------- console


def test_console_panel_contents() -> None:
    text = render_alert(alert_for("192.0.2.1", 5, "root"))
    for needle in ("FANG ALERT: SSH BRUTE-FORCE [HIGH]", "192.0.2.1", "root", "ALERT-FANG-", "Pattern"):
        assert needle in text
    assert "\x1b" not in text


def test_console_marks_escalations_and_distributed_alerts() -> None:
    det = Detector(DetectorConfig(spray_threshold=0))
    alerts = []
    for i in range(10):
        alerts += det.process(ev("192.0.2.1", i * 0.5))
    assert "ESCALATED HIGH" in render_alert(alerts[-1])
    text = render_alert(spray_alert())
    assert "DISTRIBUTED ATTACK" in text
    assert "10 IPs" in text


def test_hostile_log_content_cannot_inject_terminal_sequences() -> None:
    from fang.parser import SshLogParser

    parser = SshLogParser(reference_year=2026)
    det = Detector()
    alerts = []
    for i in range(5):
        e = parser.parse_line(
            f"Sep 19 10:00:{i:02d} host sshd[1]: Failed password for invalid user "
            f"\x1b]8;;http://evil.example\x07click\x1b]8;;\x07‮[bold red]X[/] from 192.0.2.1 port {2000 + i} ssh2"
        )
        assert e is not None
        alerts += det.process(e)
    out = render_alert(alerts[0], color=False)
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "‮" not in out


def test_console_handler_quiet_and_unencodable_stream() -> None:
    buf = io.StringIO()
    ConsoleAlertHandler(buf, quiet=True).handle(alert_for())
    assert buf.getvalue() == ""

    class AsciiStream(io.StringIO):
        def write(self, s: str) -> int:
            s.encode("ascii")  # behaves like a C-locale terminal
            return super().write(s)

    stream = AsciiStream()
    alert = alert_for(user="حسن")
    ConsoleAlertHandler(stream).handle(alert)  # must not raise UnicodeEncodeError
    assert "ALERT-FANG" in stream.getvalue()


def test_use_color_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert use_color(Tty())
    assert not use_color(io.StringIO())
    assert not use_color(Tty(), disabled=True)
    monkeypatch.setenv("NO_COLOR", "1")
    assert not use_color(Tty())
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert not use_color(Tty())


def test_summary_rendering() -> None:
    det = Detector()
    analyzer = Analyzer(det, [])
    analyzer.run(ev("192.0.2.1", i) for i in range(6))
    text = render_summary(det.stats, analyzer.alerts, det.top_offenders(3))
    for needle in ("Failed login attempts", "6", "Detected incidents", "Top offenders", "192.0.2.1"):
        assert needle in text


# ----------------------------------------------------------------- JSONL


def test_jsonl_handler_writes_one_json_object_per_alert(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    handler = JsonlAlertHandler(path)
    handler.handle(alert_for())
    handler.handle(alert_for("192.0.2.2"))
    handler.close()
    handler.close()  # idempotent
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["source_ip"] for r in rows] == ["192.0.2.1", "192.0.2.2"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="closed"):
        handler.handle(alert_for())


def test_jsonl_handler_appends_and_refuses_symlinks_and_non_files(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    for _ in range(2):
        h = JsonlAlertHandler(path)
        h.handle(alert_for())
        h.close()
    assert len(path.read_text().splitlines()) == 2

    victim = tmp_path / "victim"
    victim.write_text("precious")
    link = tmp_path / "link.jsonl"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        JsonlAlertHandler(link)
    assert victim.read_text() == "precious"

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(OSError):  # must fail fast instead of blocking
        JsonlAlertHandler(fifo)


# -------------------------------------------------------------- blocklist


def test_blocklist_threshold_protection_and_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "block.txt"
    handler = BlocklistHandler(path, Allowlist(["192.0.2.99"]), Severity.HIGH)
    handler.handle(alert_for("192.0.2.1", 5, "alice"))  # MEDIUM: ignored
    assert not path.exists()
    handler.handle(alert_for("192.0.2.2", 5, "root"))  # HIGH
    handler.handle(alert_for("192.0.2.99", 5, "root"))  # allow-listed
    handler.handle(alert_for("127.0.0.1", 5, "root"))  # protected
    handler.handle(alert_for("2001:db8::bad", 5, "root"))
    lines = [x for x in path.read_text().splitlines() if not x.startswith("#")]
    assert lines == ["192.0.2.2", "2001:db8::bad"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_blocklist_merges_existing_entries_and_ignores_junk(tmp_path: Path) -> None:
    path = tmp_path / "block.txt"
    path.write_text("# comment\n198.51.100.1  # trailing\n127.0.0.1\nnot-an-ip\n\n198.51.100.1\n10.0.0.5\n")
    handler = BlocklistHandler(path, Allowlist(["10.0.0.0/8"]))
    assert handler.entries == {"198.51.100.1"}  # loopback, junk and allow-listed entries dropped
    handler.handle(alert_for("192.0.2.2", 5, "root"))
    lines = [x for x in path.read_text().splitlines() if not x.startswith("#")]
    assert lines == ["192.0.2.2", "198.51.100.1"] or lines == ["198.51.100.1", "192.0.2.2"]
    assert sorted(lines, key=lambda s: tuple(map(int, s.split(".")))) == lines  # numeric order


def test_blocklist_handles_distributed_alerts(tmp_path: Path) -> None:
    path = tmp_path / "block.txt"
    handler = BlocklistHandler(path, min_severity=Severity.MEDIUM)
    handler.handle(spray_alert())
    assert len([x for x in path.read_text().splitlines() if not x.startswith("#")]) == 10


def test_blocklist_refuses_fifo_instead_of_hanging(tmp_path: Path) -> None:
    fifo = tmp_path / "block.txt"
    os.mkfifo(fifo)
    with pytest.raises(OSError, match="not a regular file"):
        BlocklistHandler(fifo)


def test_blocklist_does_not_follow_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("precious")
    link = tmp_path / "block.txt"
    link.symlink_to(victim)
    BlocklistHandler(link, min_severity=Severity.MEDIUM).handle(alert_for())
    assert victim.read_text() == "precious"
    assert "192.0.2.1" in link.read_text()


# ------------------------------------------------------------------- hook


def test_net_access_controller_payload_and_dry_run_output() -> None:
    alert = alert_for("192.0.2.1", 10, "root")
    payload = NetAccessControllerHook.build_block_payload(alert)
    assert payload == {
        "schema_version": "1.0",
        "action": "BLOCK_IP",
        "target_ip": "192.0.2.1",
        "reason": alert.pattern,
        "severity": alert.severity.value,
        "suggested_duration_seconds": 86400,
        "evidence": {
            "alert_id": alert.alert_id,
            "failed_attempts": alert.attempts,
            "time_window_seconds": 60,
            "targeted_usernames": ["root"],
        },
        "triggered_by": "fang",
    }
    out = io.StringIO()
    hook = NetAccessControllerHook(Allowlist(["192.0.2.50"]), out)
    hook.handle(alert)
    hook.handle(alert_for("192.0.2.50"))  # allow-listed
    hook.handle(alert_for("127.0.0.1"))  # protected
    assert [p["target_ip"] for p in hook.payloads] == ["192.0.2.1"]
    assert out.getvalue().startswith("[dry-run] net-access-controller payload: {")
    assert out.getvalue().count("\n") == 1


def test_hook_durations_follow_severity() -> None:
    medium = alert_for("192.0.2.1", 5, "alice")
    assert NetAccessControllerHook.build_block_payload(medium)["suggested_duration_seconds"] == 3600
    assert (
        NetAccessControllerHook.build_block_payload(alert_for("192.0.2.2", 5, "root"))[
            "suggested_duration_seconds"
        ]
        == 14400
    )


# ----------------------------------------------------------------- report


def test_report_structure_and_atomic_permissions(tmp_path: Path) -> None:
    det = Detector()
    analyzer = Analyzer(det, [])
    analyzer.run(ev("192.0.2.1", i, "root") for i in range(12))
    report = build_report(analyzer.alerts, det.stats, det.config.to_dict(), det.top_offenders(5))
    path = tmp_path / "report.json"
    write_report(path, report)
    data = json.loads(path.read_text())
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["alerts_count"] == len(data["alerts"]) >= 2
    assert data["summary"]["failed_attempts_count"] == 12
    assert data["summary"]["alerts_by_severity"]
    assert data["config"]["threshold"] == 5
    assert data["top_offenders"][0]["ip"] == "192.0.2.1"
    first = data["alerts"][0]
    assert {"alert_id", "alert_type", "severity", "source_ip", "time_range", "evidence"} <= set(first)
    assert first["evidence"][0]["event_type"] == "FAILED_PASSWORD"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ----------------------------------------------------------- analyzer glue


class Exploding(JsonlAlertHandler):
    def __init__(self) -> None:  # no file needed
        pass

    def handle(self, alert: SecurityAlert) -> None:
        raise RuntimeError("disk full")

    def close(self) -> None:
        return None


def test_failing_handler_does_not_stop_detection_or_other_handlers() -> None:
    det = Detector()
    seen: list[str] = []

    class Recorder(JsonlAlertHandler):
        def __init__(self) -> None:
            pass

        def handle(self, alert: SecurityAlert) -> None:
            seen.append(alert.alert_id)

        def close(self) -> None:
            return None

    analyzer = Analyzer(det, [Exploding(), Recorder()])
    analyzer.run(ev("192.0.2.1", i) for i in range(5))
    assert len(seen) == 1
    assert any("failed: disk full" in w for w in det.stats.warnings)
    assert len([w for w in det.stats.warnings if "Exploding" in w]) == 1  # reported once, not per alert


def test_report_alert_cap_is_enforced() -> None:
    det = Detector(DetectorConfig(cooldown=0, spray_threshold=0))
    analyzer = Analyzer(det, [], max_report_alerts=3)
    analyzer.run(ev("192.0.2.1", i * 0.01) for i in range(30))
    assert len(analyzer.alerts) == 3
    assert det.stats.report_alerts_dropped == det.stats.alerts_triggered - 3


def test_event_type_helpers() -> None:
    assert EventType.FAILED_PASSWORD.is_failure
    assert EventType.AUTH_FAILURE.is_failure
    assert not EventType.INVALID_USER.is_failure
    assert EventType.ACCEPTED_PUBLICKEY.is_accepted
    assert not EventType.ACCEPTED_PUBLICKEY.is_failure
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


def test_enum_members_keep_str_methods() -> None:
    # Regression: a property named `title` once shadowed str.title() on this str-based enum.
    assert AlertType.BRUTE_FORCE.title() == "Brute_Force"
    assert AlertType.BRUTE_FORCE.label == "SSH BRUTE-FORCE"

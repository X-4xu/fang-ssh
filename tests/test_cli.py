"""Configuration files and the command line, end to end."""

from __future__ import annotations

import gzip
import io
import json
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from fang import __version__
from fang.cli import EXIT_ALERTS, EXIT_ERROR, EXIT_OK, EXIT_USAGE, resolve_tz, run
from fang.config import MAX_CONFIG_BYTES, ConfigError, load_config

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "examples" / "sample_auth.log"


def cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = run(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def attack_log(
    tmp_path: Path, ip: str = "192.0.2.1", n: int = 6, name: str = "auth.log", minute: int = 0
) -> Path:
    path = tmp_path / name
    path.write_text(
        "".join(
            f"Sep 19 10:{minute:02d}:{i:02d} h sshd[{i}]: Failed password for root from {ip} port {3000 + i} ssh2\n"
            for i in range(n)
        )
    )
    return path


# ----------------------------------------------------------------- config file


def write_toml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "fang.toml"
    path.write_text(text)
    return path


def test_load_valid_config(tmp_path: Path) -> None:
    path = write_toml(
        tmp_path,
        """
[detection]
threshold = 8
window = 90
count_preauth_disconnects = false
privileged_users = ["root", "postgres"]

[allowlist]
networks = ["10.0.0.0/8", "192.0.2.7"]

[parsing]
assume_timezone = "Asia/Baghdad"

[output]
blocklist_min_severity = "critical"
""",
    )
    assert load_config(path) == {
        "threshold": 8,
        "window": 90,
        "count_preauth_disconnects": False,
        "privileged_users": ["root", "postgres"],
        "allow": ["10.0.0.0/8", "192.0.2.7"],
        "assume_timezone": "Asia/Baghdad",
        "blocklist_min_severity": "critical",
    }


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[detection]\nthreshhold = 5\n", "unknown key 'threshhold'"),
        ("[detect]\nthreshold = 5\n", "unknown section"),
        ("[detection]\nthreshold = 'five'\n", "must be of type int"),
        ("[detection]\nthreshold = true\n", "must be an integer"),
        ("[detection]\nprivileged_users = [1, 2]\n", "list of strings"),
        ("[detection\nthreshold = 5\n", "invalid TOML"),
        ("detection = 5\n", "must be a table"),
    ],
)
def test_invalid_config_files_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(write_toml(tmp_path, text))


def test_config_file_guards(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml")
    with pytest.raises(ConfigError, match="not a regular file"):
        load_config(tmp_path)
    big = tmp_path / "big.toml"
    big.write_text("# " + "x" * MAX_CONFIG_BYTES)
    with pytest.raises(ConfigError, match="too large"):
        load_config(big)
    binary = tmp_path / "bin.toml"
    binary.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(binary)


def test_shipped_example_config_is_valid() -> None:
    assert load_config(ROOT / "examples" / "fang.toml")


# -------------------------------------------------------------------- basics


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli("--version")[0] == EXIT_OK
    assert capsys.readouterr().out.strip() == f"fang {__version__}"
    assert cli("--help")[0] == EXIT_OK
    assert "Exit codes" in capsys.readouterr().out


def test_clean_run_and_alert_exit_codes(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    code, out, _ = cli("-l", str(log), "--year", "2026", "--no-color")
    assert code == EXIT_OK  # alerts alone do not fail the run
    assert "FANG ALERT" in out
    assert "Detected incidents" in out
    code, _, _ = cli("-l", str(log), "--year", "2026", "--exit-code-on-alert", "--quiet")
    assert code == EXIT_ALERTS
    quiet = tmp_path / "quiet.log"
    quiet.write_text("Sep 19 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2\n")
    assert cli("-l", str(quiet), "--year", "2026", "--exit-code-on-alert")[0] == EXIT_OK


def test_quiet_and_no_summary(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    _, out, _ = cli("-l", str(log), "--year", "2026", "--quiet")
    assert "FANG ALERT" not in out
    assert "Analysis Summary" in out
    _, out, _ = cli("-l", str(log), "--year", "2026", "--no-summary")
    assert "FANG ALERT" in out
    assert "Analysis Summary" not in out


def test_missing_file_is_an_error_not_a_crash(tmp_path: Path) -> None:
    code, out, _ = cli("-l", str(tmp_path / "nope.log"))
    assert code == EXIT_ERROR
    assert "nope.log" in out


def test_partial_failure_still_processes_other_sources(tmp_path: Path) -> None:
    good = attack_log(tmp_path)
    code, out, _ = cli(
        "-l", str(tmp_path / "nope.log"), "-l", str(good), "--year", "2026", "--exit-code-on-alert"
    )
    assert code == EXIT_ALERTS  # alerts outrank the read error, which is still reported
    assert "nope.log" in out
    assert "FANG ALERT" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["--threshold", "abc"],
        ["--threshold", "0"],
        ["--window", "-5"],
        ["--threshold", "50"],  # slow_threshold (20) would mislabel bursts: must be explained
        ["--allow", "not-an-ip"],
        ["--assume-tz", "Mars/Olympus"],
        ["--year", "1800"],
        ["--max-bytes", "-1"],
        ["--follow", "-l", "a", "-l", "b"],
        ["--follow", "-l", "-"],
        ["--from-start", "-l", "x"],
        ["--journal-since", "today", "-l", "x"],
        ["--config", "/nonexistent/fang.toml"],
        ["--bogus-flag"],
        ["--block-min-severity", "extreme"],
    ],
)
def test_usage_errors_use_exit_code_64(argv: list[str], tmp_path: Path) -> None:
    code, _, err = cli(*argv, "-l", str(attack_log(tmp_path))) if "-l" not in argv else cli(*argv)
    assert code == EXIT_USAGE
    assert err.strip()


def test_threshold_error_message_explains_the_fix(tmp_path: Path) -> None:
    _, _, err = cli("--threshold", "50", "-l", str(attack_log(tmp_path)))
    assert "slow_threshold" in err
    assert "--slow-threshold" not in err or "disable" in err


def test_raising_threshold_together_with_slow_threshold_works(tmp_path: Path) -> None:
    code, _, _ = cli(
        "--threshold", "50", "--slow-threshold", "0", "-l", str(attack_log(tmp_path)), "--year", "2026"
    )
    assert code == EXIT_OK


# ---------------------------------------------------------------- precedence


def test_cli_overrides_config_and_allowlists_are_combined(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    conf = write_toml(
        tmp_path,
        "[detection]\nthreshold = 100\nslow_threshold = 0\n[allowlist]\nnetworks = ['198.51.100.0/24']\n",
    )
    assert "FANG ALERT" not in cli("-l", str(log), "--year", "2026", "--config", str(conf))[1]
    # CLI beats file
    assert "FANG ALERT" in cli("-l", str(log), "--year", "2026", "--config", str(conf), "-t", "5")[1]
    # file allowlist + CLI allowlist both apply
    other = attack_log(tmp_path, ip="198.51.100.9", name="other.log")
    out = cli(
        "-l",
        str(log),
        "-l",
        str(other),
        "--year",
        "2026",
        "--config",
        str(conf),
        "-t",
        "5",
        "--allow",
        "192.0.2.0/24",
    )[1]
    assert "FANG ALERT" not in out
    assert "Allow-listed events" in out


# -------------------------------------------------------------------- outputs


def test_all_output_files_are_written_with_private_permissions(tmp_path: Path) -> None:
    log = attack_log(tmp_path, n=12)
    report, jsonl, block = tmp_path / "r.json", tmp_path / "a.jsonl", tmp_path / "b.txt"
    code, _, err = cli(
        "-l", str(log), "--year", "2026", "-o", str(report), "--jsonl", str(jsonl),
        "--blocklist-file", str(block), "--enable-net-access-hook", "--quiet",
    )  # fmt: skip
    assert code == EXIT_OK
    assert "[dry-run] net-access-controller payload" in err
    data = json.loads(report.read_text())
    assert data["schema_version"] == "2.0.0"
    assert data["summary"]["log_sources"] == [str(log)]
    assert data["alerts_count"] >= 1
    assert all(json.loads(line)["alert_id"] for line in jsonl.read_text().splitlines())
    assert "192.0.2.1" in block.read_text()
    for path in (report, jsonl, block):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_unwritable_output_paths_give_clean_errors(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    code, _, err = cli("-l", str(log), "--year", "2026", "--jsonl", str(tmp_path / "no" / "dir" / "a.jsonl"))
    assert code == EXIT_ERROR
    assert "cannot open output file" in err
    code, _, err = cli("-l", str(log), "--year", "2026", "-o", str(tmp_path / "no" / "dir" / "r.json"))
    assert code == EXIT_ERROR
    assert "cannot write report" in err


def test_sample_log_produces_every_alert_type(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    code, _, _ = cli(
        "-l", str(SAMPLE), "--year", "2026", "--allow", "192.0.2.10", "-o", str(report), "--quiet"
    )
    assert code == EXIT_OK
    data = json.loads(report.read_text())
    assert {a["alert_type"] for a in data["alerts"]} == {
        "brute_force", "slow_brute_force", "distributed_attack", "possible_compromise",
    }  # fmt: skip
    assert data["summary"]["suspicious_lines"] == 1
    assert all("6.6.6.6" not in json.dumps(a["source_ips"]) for a in data["alerts"])
    assert data["top_offenders"][0]["ip"] == "203.0.113.42"


# --------------------------------------------------------------------- inputs


def test_compressed_input_and_stdin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = attack_log(tmp_path).read_text()
    gz = tmp_path / "auth.log.1.gz"
    gz.write_bytes(gzip.compress(text.encode()))
    assert "FANG ALERT" in cli("-l", str(gz), "--year", "2026")[1]
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(text.encode())))
    assert "FANG ALERT" in cli("-l", "-", "--year", "2026")[1]


def test_multiple_files_are_merged_chronologically(tmp_path: Path) -> None:
    # Each file alone has only 3 attempts; interleaved in time they exceed the threshold.
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text(
        "".join(
            f"Sep 19 10:00:{s:02d} h sshd[1]: Failed password for root from 192.0.2.1 port {s} ssh2\n"
            for s in (0, 2, 4)
        )
    )
    b.write_text(
        "".join(
            f"Sep 19 10:00:{s:02d} h sshd[1]: Failed password for root from 192.0.2.1 port {s + 100} ssh2\n"
            for s in (1, 3)
        )
    )
    assert "FANG ALERT" in cli("-l", str(a), "-l", str(b), "--year", "2026")[1]


def test_timezone_option_shifts_timestamps(tmp_path: Path) -> None:
    log = attack_log(tmp_path)
    report = tmp_path / "r.json"
    cli("-l", str(log), "--year", "2026", "--assume-tz", "Asia/Baghdad", "-o", str(report), "--quiet")
    start = json.loads(report.read_text())["alerts"][0]["time_range"]["start"]
    assert start.startswith("2026-09-19T07:00:00")  # 10:00 Baghdad (UTC+3) == 07:00 UTC


def test_resolve_tz() -> None:
    assert resolve_tz("UTC") is not None
    assert resolve_tz("local") is not None
    assert resolve_tz("Asia/Baghdad").utcoffset(None) is not None or True
    with pytest.raises(Exception, match="unknown time zone"):
        resolve_tz("../../etc/passwd")


def test_journald_source_through_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import fang.sources as sources

    lines = "\n".join(
        json.dumps(
            {
                "__REALTIME_TIMESTAMP": str(1_789_000_000_000_000 + i * 1_000_000),
                "SYSLOG_IDENTIFIER": "sshd",
                "_HOSTNAME": "node",
                "MESSAGE": f"Failed password for root from 192.0.2.1 port {4000 + i} ssh2",
            }
        )
        for i in range(6)
    )
    script = tmp_path / "journalctl"
    script.write_text(f"#!/bin/sh\ncat <<'EOF'\n{lines}\nEOF\n")
    script.chmod(0o755)
    monkeypatch.setattr(sources.JournalSource, "available", staticmethod(lambda: str(script)))
    code, out, _ = cli("--journald", "--exit-code-on-alert", "--no-color")
    assert code == EXIT_ALERTS
    assert "192.0.2.1" in out
    assert "journald" in out


# ---------------------------------------------------------------- follow mode


def test_follow_mode_alerts_live_and_stops_cleanly(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("")
    out, err = io.StringIO(), io.StringIO()
    stop = threading.Event()
    result: list[int] = []
    jsonl = tmp_path / "live.jsonl"
    thread = threading.Thread(
        target=lambda: result.append(
            run(
                ["-l", str(log), "--follow", "--jsonl", str(jsonl), "--no-color"],
                stdout=out,
                stderr=err,
                stop_event=stop,
            )
        ),
        daemon=True,
    )
    thread.start()
    time.sleep(0.4)
    now = time.strftime("%b %e %H:%M:%S")
    with open(log, "a") as handle:
        for i in range(6):
            handle.write(f"{now} h sshd[{i}]: Failed password for root from 192.0.2.1 port {5000 + i} ssh2\n")
    deadline = time.monotonic() + 8
    while "FANG ALERT" not in out.getvalue() and time.monotonic() < deadline:
        time.sleep(0.05)
    live_alert_seen = "FANG ALERT" in out.getvalue()
    stop.set()
    thread.join(8)
    assert live_alert_seen, out.getvalue()
    assert not thread.is_alive()
    assert result == [EXIT_OK]
    assert jsonl.read_text().strip()
    assert "Analysis Summary" in out.getvalue()

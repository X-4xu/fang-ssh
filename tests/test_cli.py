"""
Integration tests for CLI functionality.
"""

from __future__ import annotations

import json
from pathlib import Path

from fang.cli import main, run_analyzer


def test_run_analyzer_classic_fixture(classic_log_path: Path, tmp_path: Path) -> None:
    output_json = tmp_path / "classic_report.json"
    summary, alerts = run_analyzer(
        log_file=str(classic_log_path),
        threshold=5,
        window=60,
        output_path=str(output_json),
        quiet=True,
    )

    assert summary.total_lines_read == 11
    assert summary.total_events_parsed >= 8
    assert summary.failed_attempts_count >= 7
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.source_ip == "192.168.1.100"
    assert alert.failed_attempts_count >= 5
    assert output_json.exists()

    with open(output_json, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["alerts_count"] == 1
    assert report["alerts"][0]["source_ip"] == "192.168.1.100"


def test_run_analyzer_rfc3339_fixture(rfc3339_log_path: Path) -> None:
    _summary, alerts = run_analyzer(
        log_file=str(rfc3339_log_path),
        threshold=5,
        window=60,
        quiet=True,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "203.0.113.42"
    assert "root" in alert.target_usernames
    assert alert.severity.value in ("high", "critical")


def test_cli_main_success(classic_log_path: Path, tmp_path: Path) -> None:
    output_json = tmp_path / "cli_out.json"
    exit_code = main(
        [
            "--log-file",
            str(classic_log_path),
            "--threshold",
            "5",
            "--window",
            "60",
            "--output",
            str(output_json),
            "--quiet",
        ]
    )
    assert exit_code == 0
    assert output_json.exists()


def test_cli_main_exit_code_on_alert(classic_log_path: Path) -> None:
    exit_code = main(
        [
            "--log-file",
            str(classic_log_path),
            "--threshold",
            "5",
            "--window",
            "60",
            "--exit-code-on-alert",
            "--quiet",
        ]
    )
    # Expect exit code 2 because an alert was detected
    assert exit_code == 2


def test_cli_main_file_not_found() -> None:
    exit_code = main(["--log-file", "non_existent_file_xyz.log"])
    assert exit_code == 1


def test_cli_stdin_reading(monkeypatch, classic_log_path: Path) -> None:
    import io

    with open(classic_log_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    monkeypatch.setattr("sys.stdin", io.StringIO(log_content))
    summary, alerts = run_analyzer(log_file="-", threshold=5, window=60, quiet=True)

    assert summary.log_file_path == "<stdin>"
    assert summary.total_lines_read == 11
    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.168.1.100"


def test_cli_journalctl_mock(monkeypatch) -> None:
    from unittest.mock import MagicMock

    sample_journald_lines = (
        "2026-10-28T12:00:01+0000 host sshd[1001]: Failed password for root from 198.51.100.22 port 22 ssh2\n"
        "2026-10-28T12:00:05+0000 host sshd[1002]: Failed password for root from 198.51.100.22 port 22 ssh2\n"
        "2026-10-28T12:00:10+0000 host sshd[1003]: Failed password for root from 198.51.100.22 port 22 ssh2\n"
        "2026-10-28T12:00:15+0000 host sshd[1004]: Failed password for root from 198.51.100.22 port 22 ssh2\n"
        "2026-10-28T12:00:20+0000 host sshd[1005]: Failed password for root from 198.51.100.22 port 22 ssh2\n"
    )

    mock_proc = MagicMock()
    mock_proc.stdout = sample_journald_lines.splitlines(keepends=True)
    mock_proc.wait.return_value = 0

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: mock_proc)

    summary, alerts = run_analyzer(
        use_journalctl=True, threshold=5, window=60, quiet=True
    )
    assert summary.log_file_path == "<journalctl>"
    assert summary.total_lines_read == 5
    assert len(alerts) == 1
    assert alerts[0].source_ip == "198.51.100.22"
    assert alerts[0].failed_attempts_count == 5


def test_run_analyzer_follow_mode(tmp_path: Path) -> None:
    import threading
    import time

    log_file = tmp_path / "follow_cli.log"
    log_file.write_text(
        "Sep 19 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.55 port 22 ssh2\n",
        encoding="utf-8",
    )

    stop_event = threading.Event()
    results = {}

    def run_worker():
        s, a = run_analyzer(
            log_file=str(log_file),
            threshold=2,
            window=60,
            follow=True,
            stop_event=stop_event,
            quiet=True,
        )
        results["summary"] = s
        results["alerts"] = a

    t = threading.Thread(target=run_worker, daemon=True)
    t.start()

    time.sleep(0.15)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(
            "Sep 19 10:00:05 srv sshd[2]: Failed password for root from 192.0.2.55 port 22 ssh2\n"
        )
        f.flush()

    time.sleep(0.15)
    stop_event.set()
    t.join(timeout=2.0)

    assert "summary" in results
    assert results["summary"].total_lines_read == 2
    assert len(results["alerts"]) == 1
    assert results["alerts"][0].source_ip == "192.0.2.55"

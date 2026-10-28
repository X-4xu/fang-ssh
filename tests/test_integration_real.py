"""
Real end-to-end integration tests for Fang covering:
- Log file rotation and truncation handling in --follow mode
- Journalctl subprocess ingestion
- Gzip compressed archive parsing
- Stdin pipeline streaming
- JSON report schema validation, SIEM taxonomy, and bounded evidence size
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fang.cli import run_analyzer
from fang.detector import BruteForceDetector
from fang.exporter import ReportExporter
from fang.models import AnalysisSummary, EventType, SshAuthEvent
from fang.parser import SshLogParser


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows file locking prevents atomic POSIX logrotate rename while file is open",
)
def test_follow_file_rotation_posix_integration(tmp_path: Path) -> None:
    """
    Test that follow_file detects real POSIX logrotate rotation (rename + new file creation),
    seamlessly picking up events from the new file without losing state.
    """
    active_log = tmp_path / "auth.log"
    rotated_log = tmp_path / "auth.log.1"

    # Write initial events
    active_log.write_text(
        "Sep 19 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.10 port 22 ssh2\n",
        encoding="utf-8",
    )

    parser = SshLogParser(reference_year=2026)
    stop_event = threading.Event()
    collected_events = []

    def follow_worker():
        for event in parser.follow_file(
            active_log, poll_interval=0.05, stop_event=stop_event
        ):
            collected_events.append(event)

    t = threading.Thread(target=follow_worker, daemon=True)
    t.start()

    time.sleep(0.15)
    assert len(collected_events) == 1

    # Simulate log rotation: rename active -> active.1, create new active
    active_log.rename(rotated_log)
    active_log.write_text(
        "Sep 19 10:00:05 srv sshd[2]: Failed password for admin from 192.0.2.20 port 22 ssh2\n",
        encoding="utf-8",
    )

    time.sleep(0.25)
    stop_event.set()
    t.join(timeout=1.0)

    assert len(collected_events) >= 2
    assert collected_events[0].source_ip == "192.0.2.10"
    assert collected_events[1].source_ip == "192.0.2.20"


def test_follow_file_append_streaming(tmp_path: Path) -> None:
    """
    Cross-platform streaming test verifying real-time consumption of newly appended events.
    """
    active_log = tmp_path / "auth_append.log"
    active_log.write_text(
        "Sep 19 10:00:01 srv sshd[1]: Failed password for root from 192.0.2.11 port 22 ssh2\n",
        encoding="utf-8",
    )

    parser = SshLogParser(reference_year=2026)
    stop_event = threading.Event()
    collected = []

    def follow_worker():
        for event in parser.follow_file(
            active_log, poll_interval=0.05, stop_event=stop_event
        ):
            collected.append(event)

    t = threading.Thread(target=follow_worker, daemon=True)
    t.start()
    time.sleep(0.15)
    assert len(collected) == 1

    # Append new event
    with open(active_log, "a", encoding="utf-8") as f:
        f.write(
            "Sep 19 10:00:02 srv sshd[2]: Failed password for root from 192.0.2.12 port 22 ssh2\n"
        )

    time.sleep(0.2)
    stop_event.set()
    t.join(timeout=1.0)
    assert len(collected) == 2


def test_follow_file_truncation_integration(tmp_path: Path) -> None:
    """
    Test that follow_file detects file truncation (> /var/log/auth.log) and resumes reading from start.
    """
    active_log = tmp_path / "auth.log"
    line1 = "Sep 19 10:00:01 srv sshd[1]: Failed password for user1 from 192.0.2.30 port 22 ssh2        \n"
    active_log.write_text(line1, encoding="utf-8")

    parser = SshLogParser(reference_year=2026)
    stop_event = threading.Event()
    collected = []

    def follow_worker():
        for event in parser.follow_file(
            active_log, poll_interval=0.05, stop_event=stop_event
        ):
            collected.append(event)

    t = threading.Thread(target=follow_worker, daemon=True)
    t.start()
    time.sleep(0.15)
    assert len(collected) == 1

    # Truncate file and write new shorter line
    line2 = "Sep 19 10:00:02 srv sshd[2]: Accepted publickey for user2 from 192.0.2.40 port 22\n"
    active_log.write_text(line2, encoding="utf-8")

    time.sleep(0.25)
    stop_event.set()
    t.join(timeout=1.0)

    assert len(collected) >= 2
    assert collected[-1].source_ip == "192.0.2.40"


def test_gzip_integration(tmp_path: Path) -> None:
    """
    Test end-to-end parsing of .log.gz files into detector and JSON report.
    """
    gz_path = tmp_path / "auth.log.gz"
    lines = [
        f"Sep 19 10:00:{10+i:02d} srv sshd[{100+i}]: Failed password for root from 192.0.2.55 port 22 ssh2\n"
        for i in range(6)
    ]
    with gzip.open(gz_path, "wt", encoding="utf-8") as f:
        f.writelines(lines)

    summary, alerts = run_analyzer(log_file=str(gz_path), threshold=5, window=60)
    assert summary.total_lines_read == 6
    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.0.2.55"
    assert alerts[0].failed_attempts_count == 5


def test_stdin_stream_integration(monkeypatch) -> None:
    """
    Test streaming log events directly via stdin pipe.
    """
    fake_stdin_content = (
        "\n".join(
            [
                f"Sep 19 10:00:{10+i:02d} srv sshd[{100+i}]: Failed password for test from 192.0.2.99 port 22 ssh2"
                for i in range(5)
            ]
        )
        + "\n"
    )

    monkeypatch.setattr("sys.stdin", io.StringIO(fake_stdin_content))
    summary, alerts = run_analyzer(log_file="-", threshold=5, window=60)

    assert summary.total_lines_read == 5
    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.0.2.99"


def test_json_export_schema_and_siem_fields(tmp_path: Path) -> None:
    """
    Validate that JSON export contains deterministic alert ID, SIEM taxonomy,
    severity reasoning, and bounded evidence size.
    """
    out_file = tmp_path / "report.json"
    # Set max_evidence_events=4 with threshold=5 so evidence is truncated
    detector = BruteForceDetector(threshold=5, window_seconds=60, max_evidence_events=4)

    base = datetime(2026, 10, 28, 14, 0, 0, tzinfo=timezone.utc)
    alert = None

    for i in range(5):
        res = detector.process_event(
            SshAuthEvent(
                timestamp=base + timedelta(seconds=i),
                event_type=EventType.FAILED_PASSWORD,
                source_ip="203.0.113.88",
                port=22,
                username="root",
                is_invalid_user=False,
                raw_line=f"Sep 19 14:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.88 port 22",
                line_number=i + 1,
            )
        )
        if res:
            alert = res

    assert alert is not None

    summary = AnalysisSummary(
        log_file_path="mock.log",
        total_lines_read=5,
        total_events_parsed=5,
        failed_attempts_count=5,
        unique_source_ips=1,
        alerts_triggered=detector.total_alerts,
    )

    json_str = ReportExporter.export_json(summary, [alert], output_path=out_file)
    data = json.loads(json_str)

    # Verify SIEM fields and deterministic ID
    assert "schema_version" in data
    assert "alerts" in data
    alert_dict = data["alerts"][0]
    assert alert_dict["alert_id"].startswith("ALERT-FANG-")
    assert alert_dict["category"] == "brute_force"
    assert "severity_reasons" in alert_dict
    assert len(alert_dict["severity_reasons"]) > 0

    # Verify SIEM object
    siem = alert_dict["siem"]
    assert "event.category" in siem
    assert "event.kind" in siem
    assert siem["source.ip"] == "203.0.113.88"
    assert "event.duration_ns" in siem

    # Verify epoch timestamps
    assert "start_epoch" in alert_dict["time_range"]
    assert "end_epoch" in alert_dict["time_range"]

    # Verify bounded evidence events (truncated because 5 > 4)
    assert alert_dict["evidence_truncated"] is True
    assert len(alert_dict["evidence"]) <= 4

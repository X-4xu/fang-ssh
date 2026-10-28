"""
Unit tests for ReportExporter and ActionHandlers.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fang.exporter import ReportExporter
from fang.handlers.net_access import NetAccessControllerHook
from fang.models import (
    AlertSeverity,
    AnalysisSummary,
    EventType,
    SecurityAlert,
    SshAuthEvent,
)


def sample_alert() -> SecurityAlert:
    now = datetime(2026, 9, 19, 14, 0, 0, tzinfo=timezone.utc)
    ev = SshAuthEvent(
        timestamp=now,
        event_type=EventType.FAILED_PASSWORD,
        source_ip="192.168.1.100",
        port=45678,
        username="admin",
        is_invalid_user=True,
        raw_line="raw line",
        line_number=10,
    )
    return SecurityAlert(
        alert_id="ALERT-TEST-001",
        source_ip="192.168.1.100",
        severity=AlertSeverity.HIGH,
        pattern="SSH Brute-Force: 5 failed attempts in 20.0s",
        failed_attempts_count=5,
        window_seconds=60,
        start_time=now,
        end_time=now,
        target_usernames=["admin"],
        ports=[45678],
        evidence_events=[ev],
        detected_at=now,
    )


def test_export_json_structure(tmp_path: Path) -> None:
    summary = AnalysisSummary(
        log_file_path="/var/log/auth.log",
        total_lines_read=100,
        total_events_parsed=50,
        failed_attempts_count=20,
        unique_source_ips=3,
        alerts_triggered=1,
    )
    alert = sample_alert()
    output_file = tmp_path / "subdir" / "report.json"

    json_output = ReportExporter.export_json(summary, [alert], output_path=output_file)
    assert output_file.exists()

    data = json.loads(json_output)
    assert data["schema_version"] == "1.0.0"
    assert data["summary"]["log_file_path"] == "/var/log/auth.log"
    assert data["alerts_count"] == 1

    alert_data = data["alerts"][0]
    assert alert_data["source_ip"] == "192.168.1.100"
    assert alert_data["severity"] == "high"
    assert alert_data["failed_attempts_count"] == 5
    assert "time_range" in alert_data
    assert alert_data["target_usernames"] == ["admin"]
    assert len(alert_data["evidence"]) == 1
    assert alert_data["evidence"][0]["username"] == "admin"


def test_net_access_controller_hook_payload() -> None:
    hook = NetAccessControllerHook(enabled=True, dry_run=True)
    alert = sample_alert()

    payload = hook.build_block_payload(alert)
    assert payload["action"] == "BLOCK_IP"
    assert payload["target_ip"] == "192.168.1.100"
    assert payload["severity"] == "high"
    assert payload["suggested_duration_seconds"] == 14400  # 4 hours for HIGH
    assert payload["triggered_by"] == "fang"

    # Verify dry-run dispatch
    result = hook.dispatch_block(payload)
    assert result["status"] == "dry_run"
    assert "not active in v1.0.0" in result["message"]


def test_net_access_controller_hook_whitelist() -> None:
    hook = NetAccessControllerHook(enabled=True, dry_run=True)
    # Localhost / loopback should be refused
    assert hook.is_whitelisted("127.0.0.1") is True
    assert hook.is_whitelisted("::1") is True
    assert hook.is_whitelisted("localhost") is True
    assert hook.is_whitelisted("203.0.113.5") is False

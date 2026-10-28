"""Test helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fang.models import EventType, SshAuthEvent

BASE = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)


def ev(
    ip: str = "192.0.2.1",
    t: float = 0.0,
    user: str = "alice",
    kind: EventType = EventType.FAILED_PASSWORD,
    port: int | None = 2222,
    weight: int = 1,
    host: str = "h",
    method: str | None = None,
) -> SshAuthEvent:
    if method is None:
        method = {
            EventType.ACCEPTED_PASSWORD: "password",
            EventType.ACCEPTED_PUBLICKEY: "publickey",
            EventType.FAILED_PASSWORD: "password",
            EventType.FAILED_PUBLICKEY: "publickey",
        }.get(kind, "")
    return SshAuthEvent(
        timestamp=BASE + timedelta(seconds=t),
        event_type=kind,
        source_ip=ip,
        username=user,
        host=host,
        port=port,
        auth_method=method,
        weight=weight,
        line_number=int(t) + 1,
        raw_line=f"raw {t}",
    )

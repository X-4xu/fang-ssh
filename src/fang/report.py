"""Structured JSON report export."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from ._version import __version__
from .models import AnalysisStats, SecurityAlert
from .util import atomic_write_text

SCHEMA_VERSION = "2.0.0"


def build_report(
    alerts: Sequence[SecurityAlert],
    stats: AnalysisStats,
    config: dict[str, Any],
    offenders: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "analyzer_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "summary": stats.to_dict(),
        "top_offenders": list(offenders),
        "alerts_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


def write_report(path: str | os.PathLike[str], report: dict[str, Any]) -> None:
    """Atomically write ``report`` (mode 0600; a symlink at ``path`` is replaced, not followed)."""
    atomic_write_text(path, json.dumps(report, indent=2, ensure_ascii=True) + "\n", mode=0o600)

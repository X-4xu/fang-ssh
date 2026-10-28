"""
Tests for synthetic log generation and benchmark utility.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.benchmark_synthetic import generate_synthetic_logs, run_benchmark


def test_generate_synthetic_logs_count() -> None:
    lines = generate_synthetic_logs(150)
    assert len(lines) == 150
    # Assert lines are non-empty strings
    assert all(isinstance(l, str) and len(l) > 10 for l in lines)


def test_run_benchmark_metrics() -> None:
    lines = generate_synthetic_logs(200)
    results = run_benchmark(lines)
    assert results["total_lines"] == 200
    assert results["parsed_events"] > 0
    assert results["elapsed_seconds"] >= 0
    assert results["lines_per_second"] > 0

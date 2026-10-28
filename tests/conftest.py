"""
Pytest configuration and shared fixtures for ssh-log-analyzer tests.
"""

from __future__ import annotations

import gzip
from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def classic_log_path(fixtures_dir: Path) -> Path:
    """Return path to classic syslog fixture."""
    return fixtures_dir / "auth_classic.log"


@pytest.fixture(scope="session")
def rfc3339_log_path(fixtures_dir: Path) -> Path:
    """Return path to RFC 3339 fixture."""
    return fixtures_dir / "auth_rfc3339.log"


@pytest.fixture(scope="session")
def malformed_log_path(fixtures_dir: Path) -> Path:
    """Return path to malformed fixture."""
    return fixtures_dir / "auth_malformed.log"


@pytest.fixture(scope="session")
def gzip_log_path(tmp_path_factory: pytest.TempPathFactory, classic_log_path: Path) -> Path:
    """Create a temporary .gz version of classic_log for testing compressed parsing."""
    tmp_dir = tmp_path_factory.mktemp("fixtures")
    gz_path = tmp_dir / "auth_classic.log.gz"
    with open(classic_log_path, "rb") as f_in:
        with gzip.open(gz_path, "wb") as f_out:
            f_out.writelines(f_in)
    return gz_path

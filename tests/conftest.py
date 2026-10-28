"""Shared fixtures. All data is synthetic and uses RFC 5737 / RFC 3849 documentation addresses."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

CLASSIC_LOG = """\
Sep 19 10:00:05 web-server sshd[2000]: Accepted publickey for devops from 192.168.1.50 port 35000 ssh2: RSA SHA256:abc123xyz
Sep 19 10:00:10 web-server sshd[2001]: Failed password for invalid user admin from 192.168.1.100 port 40001 ssh2
Sep 19 10:00:13 web-server sshd[2002]: Failed password for invalid user test from 192.168.1.100 port 40002 ssh2
Sep 19 10:00:16 web-server sshd[2003]: Failed password for invalid user guest from 192.168.1.100 port 40003 ssh2
Sep 19 10:00:19 web-server sshd[2004]: Failed password for root from 192.168.1.100 port 40004 ssh2
Sep 19 10:00:22 web-server sshd[2005]: Failed password for root from 192.168.1.100 port 40005 ssh2
Sep 19 10:00:25 web-server sshd[2006]: Failed password for oracle from 192.168.1.100 port 40006 ssh2
Sep 19 10:00:28 web-server sshd[2007]: Failed publickey for root from 192.168.1.100 port 40007 ssh2: RSA SHA256:zzz
Sep 19 10:00:30 web-server CRON[2008]: pam_unix(cron:session): session opened for user root
Sep 19 10:10:00 web-server sshd[2009]: Accepted password for devops from 192.168.1.50 port 35001 ssh2
"""

MALFORMED_LOG = (
    "Sep 19 10:00:10 host sshd[1]: Failed password for root from 999.999.999.999 port 22 ssh2\n"
    "Sep 19 10:00:11 host sshd[2]: Failed password for root from not-an-ip port 22 ssh2\n"
    "this is not a syslog line at all\n"
    "Sep 19 10:00:12 host sshd[3]: Failed password for root from 1.2.3.4 port 99999 ssh2\n"
    "Sep 32 25:61:61 host sshd[4]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    "Sep 19 10:00:13 host sudo[5]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    "\x00\x01\x02 binary junk \xff\xfe\n"
    "Sep 19 10:00:14 host sshd[6]: Failed password for\n"
    "\n"
)


@pytest.fixture
def classic_log_path(tmp_path: Path) -> Path:
    path = tmp_path / "auth.log"
    path.write_text(CLASSIC_LOG, encoding="utf-8")
    return path


@pytest.fixture
def gzip_log_path(tmp_path: Path) -> Path:
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(path, "wb") as handle:
        handle.write(CLASSIC_LOG.encode("utf-8"))
    return path


@pytest.fixture
def malformed_log_path(tmp_path: Path) -> Path:
    path = tmp_path / "malformed.log"
    path.write_bytes(MALFORMED_LOG.encode("utf-8", "surrogateescape"))
    return path

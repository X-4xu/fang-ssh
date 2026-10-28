"""
Safe and resilient SSH log parser supporting Syslog and RFC 3339 formats,
compressed .gz log files, and strict IP/event validation.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
import gzip
import ipaddress
import logging
from pathlib import Path
import re
from typing import TextIO

from fang.models import EventType, SshAuthEvent

logger = logging.getLogger(__name__)

# Maximum allowed line length to prevent ReDoS / memory exhaustion on corrupted files
MAX_LINE_LENGTH = 4096

# Regex for standard RFC 3339 / ISO 8601 timestamp at start of line
# e.g.: 2026-09-19T08:12:34.567890+00:00 or 2026-09-19T08:12:34Z
RE_RFC3339_PREFIX = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
)

# Regex for traditional Syslog timestamp
# e.g.: Sep 19 14:32:10 or Oct  5 09:05:01
RE_SYSLOG_PREFIX = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")

# Regex patterns for SSH authentication events
# Pattern 1: Failed password for [invalid user] <username> from <ip> port <port>
RE_FAILED_PASSWORD = re.compile(
    r"sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# Pattern 2: Invalid user <username> from <ip> port <port>
RE_INVALID_USER = re.compile(
    r"sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)

# Pattern 3: PAM authentication failure (pam_unix)
RE_PAM_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication failure;.*?\brhost=(?P<ip>\S+)(?:.*?\buser=(?P<user>\S+))?"
)

# Pattern 4: Connection closed/reset [preauth]
RE_CONNECTION_CLOSED = re.compile(
    r"sshd\[\d+\]:\s+Connection (?:closed|reset) by (?:authenticating user |invalid user )?(?P<user>\S+)?\s*(?P<ip>\S+) port (?P<port>\d+)\s+\[preauth\]"
)

# Pattern 5: Accepted password/publickey
RE_ACCEPTED = re.compile(
    r"sshd\[\d+\]:\s+Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


class SshLogParser:
    """
    Parses SSH log events line-by-line from auth.log files.
    Ensures safe, bounded execution and sanitization of all untrusted fields.
    """

    def __init__(
        self, reference_year: int | None = None, tz: timezone = timezone.utc
    ) -> None:
        self.reference_year = reference_year or datetime.now(timezone.utc).year
        self.tz = tz
        self.lines_read = 0

    def parse_file(self, file_path: str | Path) -> Iterator[SshAuthEvent]:
        """
        Stream events from an auth.log file or stdin.
        Supports plaintext, gzip-compressed (.gz) files, and stdin ('-').
        """
        if str(file_path) == "-":
            import sys

            yield from self.parse_stream(sys.stdin)
            return

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        try:
            if path.suffix == ".gz":
                with gzip.open(
                    path, mode="rt", encoding="utf-8", errors="replace"
                ) as f:
                    yield from self.parse_stream(f)
            else:
                with open(path, mode="r", encoding="utf-8", errors="replace") as f:
                    yield from self.parse_stream(f)
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied accessing log file {path}: {e}"
            ) from e
        except Exception as e:
            logger.error("Error reading log file %s: %s", path, e)
            raise

    def parse_stream(self, stream: TextIO) -> Iterator[SshAuthEvent]:
        """Parse events line-by-line from any text stream."""
        for line_number, line in enumerate(stream, start=1):
            self.lines_read = line_number
            event = self.parse_line(line, line_number=line_number)
            if event is not None:
                yield event

    def parse_line(self, raw_line: str, line_number: int = 0) -> SshAuthEvent | None:
        """
        Safely parse a single log line into an SshAuthEvent.
        Returns None if the line does not contain an SSH authentication event.
        """
        if not raw_line or len(raw_line) > MAX_LINE_LENGTH:
            return None

        clean_line = raw_line.strip()
        if not clean_line:
            return None

        # 1. Parse timestamp and remaining content
        ts, content = self._parse_timestamp(clean_line)
        if ts is None:
            return None

        # 2. Check SSH authentication patterns
        return self._match_event(clean_line, content, ts, line_number)

    def _parse_timestamp(self, line: str) -> tuple[datetime | None, str]:
        """Extract and parse timestamp from the start of the line."""
        # Check RFC 3339 / ISO 8601 first
        m_rfc = RE_RFC3339_PREFIX.match(line)
        if m_rfc:
            ts_str = m_rfc.group(1).replace("Z", "+00:00")
            if len(ts_str) >= 5 and ts_str[-5] in "+-" and ts_str[-3] != ":":
                ts_str = ts_str[:-2] + ":" + ts_str[-2:]
            try:
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=self.tz)
                return dt, line[m_rfc.end() :]
            except ValueError:
                pass

        # Check standard BSD Syslog format: "Sep 19 14:32:10"
        m_syslog = RE_SYSLOG_PREFIX.match(line)
        if m_syslog:
            ts_str = m_syslog.group(1)
            try:
                # Parse month, day, time with reference year
                dt_naive = datetime.strptime(
                    f"{self.reference_year} {ts_str}", "%Y %b %d %H:%M:%S"
                )
                # Handle year rollover if log is from Dec and current year is Jan
                now = datetime.now(timezone.utc)
                if dt_naive.month == 12 and now.month == 1:
                    dt_naive = dt_naive.replace(year=self.reference_year - 1)
                dt = dt_naive.replace(tzinfo=self.tz)
                return dt, line[m_syslog.end() :]
            except ValueError:
                pass

        return None, line

    def _match_event(
        self, raw_line: str, content: str, timestamp: datetime, line_number: int
    ) -> SshAuthEvent | None:
        """Match event details and construct SshAuthEvent."""
        # 1. Failed password
        m = RE_FAILED_PASSWORD.search(content)
        if m:
            is_invalid = bool(m.group(1))
            ip = self._sanitize_ip(m.group("ip"))
            if not ip:
                return None
            user = self._sanitize_username(m.group("user"))
            port = self._safe_int(m.group("port"))
            return SshAuthEvent(
                timestamp=timestamp,
                event_type=EventType.FAILED_PASSWORD,
                source_ip=ip,
                port=port,
                username=user,
                is_invalid_user=is_invalid,
                raw_line=raw_line,
                line_number=line_number,
            )

        # 2. Invalid user
        m = RE_INVALID_USER.search(content)
        if m:
            ip = self._sanitize_ip(m.group("ip"))
            if not ip:
                return None
            user = self._sanitize_username(m.group("user"))
            port = self._safe_int(m.group("port"))
            return SshAuthEvent(
                timestamp=timestamp,
                event_type=EventType.INVALID_USER,
                source_ip=ip,
                port=port,
                username=user,
                is_invalid_user=True,
                raw_line=raw_line,
                line_number=line_number,
            )

        # 3. PAM authentication failure
        m = RE_PAM_FAILURE.search(content)
        if m:
            ip = self._sanitize_ip(m.group("ip"))
            if not ip:
                return None
            user = self._sanitize_username(m.group("user")) if m.group("user") else None
            return SshAuthEvent(
                timestamp=timestamp,
                event_type=EventType.AUTH_FAILURE,
                source_ip=ip,
                port=None,
                username=user,
                is_invalid_user=False,
                raw_line=raw_line,
                line_number=line_number,
            )

        # 4. Connection closed/reset preauth
        m = RE_CONNECTION_CLOSED.search(content)
        if m:
            ip = self._sanitize_ip(m.group("ip"))
            if not ip:
                return None
            raw_user = m.group("user")
            user = (
                self._sanitize_username(raw_user)
                if raw_user and not self._is_ip(raw_user)
                else None
            )
            port = self._safe_int(m.group("port"))
            return SshAuthEvent(
                timestamp=timestamp,
                event_type=EventType.CONNECTION_CLOSED,
                source_ip=ip,
                port=port,
                username=user,
                is_invalid_user="invalid" in content,
                raw_line=raw_line,
                line_number=line_number,
            )

        # 5. Accepted logins
        m = RE_ACCEPTED.search(content)
        if m:
            ip = self._sanitize_ip(m.group("ip"))
            if not ip:
                return None
            method = m.group("method")
            ev_type = (
                EventType.ACCEPTED_PUBLICKEY
                if method == "publickey"
                else EventType.ACCEPTED_PASSWORD
            )
            user = self._sanitize_username(m.group("user"))
            port = self._safe_int(m.group("port"))
            return SshAuthEvent(
                timestamp=timestamp,
                event_type=ev_type,
                source_ip=ip,
                port=port,
                username=user,
                is_invalid_user=False,
                raw_line=raw_line,
                line_number=line_number,
            )

        return None

    @staticmethod
    def _sanitize_ip(ip_str: str | None) -> str | None:
        """Validate and return normalized IP address string, or None if invalid."""
        if not ip_str:
            return None
        clean = ip_str.strip().strip("[]()")
        try:
            addr = ipaddress.ip_address(clean)
            return str(addr)
        except ValueError:
            return None

    @staticmethod
    def _is_ip(candidate: str) -> bool:
        """Check if candidate string is a valid IP address."""
        try:
            ipaddress.ip_address(candidate.strip("[]()"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _sanitize_username(user_str: str | None) -> str | None:
        """Sanitize username to alphanumeric + standard symbols, max 64 chars."""
        if not user_str:
            return None
        # Strip control characters
        cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", user_str).strip()
        # Cap length to 64 chars
        return cleaned[:64] if cleaned else None

    @staticmethod
    def _safe_int(val: str | None) -> int | None:
        """Safely parse integer or return None."""
        if not val:
            return None
        try:
            return int(val)
        except ValueError:
            return None

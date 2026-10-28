"""sshd log parser: syslog (BSD / RFC 3339 / journalctl short-iso) and journald JSON.

Everything read from a log is attacker-influenced (usernames, key comments,
even whole lines on shared hosts). The parser therefore

* only accepts lines with a complete, valid syslog header,
* anchors every message regex to the *end* of the line, so a username such as
  ``x from 6.6.6.6 port 1`` can never replace the real source address,
* validates every address with :mod:`ipaddress`,
* strips control, bidi and other non-printable characters from every string,
* enforces hard length limits before any regex runs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone, tzinfo
from os import PathLike
from typing import NamedTuple

from .models import AnalysisStats, EventType, SshAuthEvent
from .util import normalize_ip, sanitize_text

#: Maximum accepted length of a syslog line (characters).
MAX_LINE_LENGTH = 4096
#: Maximum accepted length of a journald JSON line (characters).
MAX_JSON_LINE_LENGTH = 65536
#: Upper bound for "message repeated N times" weights.
MAX_REPEAT = 100_000

_USERNAME_MAX = 128
_RAW_LINE_MAX = 1024
_FUTURE_SLACK = timedelta(days=1)

_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

_PRI = re.compile(r"^<\d{1,3}>")
_SSHD_PROG = re.compile(r"^sshd(?:-session|-auth)?$")

_TAG = r"(?P<prog>[\w./-]{1,64})(?:\[(?P<pid>\d{1,10})\])?:\s(?P<msg>.*)$"
_BSD_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s{1,2}(?P<day>\d{1,2})\s"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s(?P<host>\S{1,255})\s" + _TAG
)
_ISO_HEADER = re.compile(
    r"^(?P<Y>\d{4})-(?P<M>\d{2})-(?P<D>\d{2})[T ]"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?:[.,](?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|[+-]\d{2}(?::?\d{2})?)?\s(?P<host>\S{1,255})\s" + _TAG
)

# Message patterns. Each ends with ``$`` and uses a greedy username group, so
# the *last* "from <ip> port <n>" in the line is always the real one.
_PORT = r"(?P<port>\d{1,5})"
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port " + _PORT + r"(?: ssh\d)?(?::.*)?$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.+) from (?P<ip>\S+) port " + _PORT + r"(?: ssh\d)?(?::.*)?$"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.+) from (?P<ip>\S+)(?: port " + _PORT + r")?$")
_PREAUTH = re.compile(
    r"^(?:Connection closed by|Disconnected from) (?P<kind>invalid|authenticating) user "
    r"(?P<user>.+) (?P<ip>\S+) port " + _PORT + r" \[preauth\]$"
)
_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    r"(?P<user>.+) from (?P<ip>\S+) port " + _PORT + r"(?: ssh\d)?(?: \[preauth\])?$"
)
# pam_unix: ``rhost=`` precedes the attacker-controlled ``user=`` field, so the
# leftmost match is the trustworthy one.
_PAM = re.compile(r"authentication failures?;.*?\brhost=(?P<ip>\S+)\s+user=(?P<user>.*)$")
_REPEATED = re.compile(r"^message repeated (?P<n>\d{1,6}) times: \[ ?(?P<inner>.+?) ?\]$")

_PASSWORD_METHODS = frozenset({"password"})
_PUBLICKEY_METHODS = frozenset({"publickey"})


class _Fields(NamedTuple):
    event_type: EventType
    method: str
    user: str
    invalid: bool
    ip: str
    port: str | None


class SshLogParser:
    """Turn sshd log lines into :class:`SshAuthEvent` objects.

    Args:
        reference_time: "Now" for the log being parsed (usually the file's
            mtime). Used to infer the missing year of BSD syslog timestamps:
            the most recent year that does not put the line in the future.
        reference_year: Force a fixed year for BSD timestamps (disables
            inference). Name kept from Fang 1.x.
        assume_tz: Time zone of timestamps that carry no offset.
        source: Label stored on every event (usually the file name).
        stats: Optional shared counters.
        max_line_length: Syslog line length limit.
    """

    def __init__(
        self,
        *,
        reference_time: datetime | None = None,
        reference_year: int | None = None,
        assume_tz: tzinfo = timezone.utc,
        source: str = "",
        stats: AnalysisStats | None = None,
        max_line_length: int = MAX_LINE_LENGTH,
    ) -> None:
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)
        elif reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)
        self._ref = reference_time
        self._fixed_year = reference_year
        self._tz = assume_tz
        self._source = source
        self.stats = stats if stats is not None else AnalysisStats()
        self.max_line_length = max_line_length

    # ------------------------------------------------------------------ API

    def parse_file(self, path: str | PathLike[str]) -> Iterator[SshAuthEvent]:
        """Parse a whole log file (plain, gzip, bzip2 or xz). Convenience API."""
        from .sources import FileSource  # local import: sources has no parser dependency

        source = FileSource(path, stats=self.stats)
        previous = self._source
        self._source = self._source or source.name
        try:
            for number, line in source.lines():
                event = self.parse_line(line, number)
                if event is not None:
                    yield event
        finally:
            self._source = previous

    def parse_line(self, line: str, line_number: int = 0) -> SshAuthEvent | None:
        """Parse one log line. Never raises; returns ``None`` if not relevant."""
        try:
            if line.startswith("{"):
                return self._parse_journal_json(line, line_number)
            return self._parse_syslog(line, line_number)
        except (ValueError, OverflowError):  # pragma: no cover - defensive
            return None

    # ---------------------------------------------------------- syslog path

    def _parse_syslog(self, line: str, line_number: int) -> SshAuthEvent | None:
        if "sshd" not in line:
            return None
        if len(line) > self.max_line_length:
            self.stats.oversized_lines += 1
            return None
        line = line.rstrip("\r\n")
        if line.startswith("<"):
            line = _PRI.sub("", line, count=1)
        if not line:
            return None

        if line[0].isdigit():
            header = _ISO_HEADER.match(line)
            if header is None:
                return None
            timestamp = self._iso_timestamp(header)
        else:
            header = _BSD_HEADER.match(line)
            if header is None:
                return None
            timestamp = self._bsd_timestamp(header)
        if timestamp is None:
            return None

        prog = header["prog"].rsplit("/", 1)[-1]
        if _SSHD_PROG.match(prog) is None:
            return None
        pid = int(header["pid"]) if header["pid"] else None
        return self._event_from_message(
            header["msg"],
            timestamp=timestamp,
            host=header["host"],
            pid=pid,
            line_number=line_number,
            raw=line,
        )

    def _bsd_timestamp(self, m: re.Match[str]) -> datetime | None:
        month = _MONTHS.get(m["mon"])
        if month is None:
            return None
        day, hour, minute, second = int(m["day"]), int(m["hh"]), int(m["mm"]), int(m["ss"])
        if self._fixed_year is not None:
            return _build(self._fixed_year, month, day, hour, minute, second, self._tz)
        ref = self._ref
        # Try the reference year first, then walk back (covers Dec/Jan
        # rollover and Feb 29 within a four-year cycle).
        for year in range(ref.year, ref.year - 5, -1):
            candidate = _build(year, month, day, hour, minute, second, self._tz)
            if candidate is not None and candidate <= ref + _FUTURE_SLACK:
                return candidate
        return None

    def _iso_timestamp(self, m: re.Match[str]) -> datetime | None:
        tz_text = m["tz"]
        tz: tzinfo = self._tz
        if tz_text:
            if tz_text == "Z":
                tz = timezone.utc
            else:
                digits = tz_text[1:].replace(":", "")
                hours = int(digits[:2])
                minutes = int(digits[2:4]) if len(digits) >= 4 else 0
                if hours > 23 or minutes > 59:
                    return None
                offset = timedelta(hours=hours, minutes=minutes)
                tz = timezone(-offset if tz_text[0] == "-" else offset)
        micro = int((m["frac"] or "0").ljust(6, "0")[:6])
        return _build(
            int(m["Y"]), int(m["M"]), int(m["D"]), int(m["hh"]), int(m["mm"]), int(m["ss"]), tz, micro
        )

    # ------------------------------------------------------- journald path

    def _parse_journal_json(self, line: str, line_number: int) -> SshAuthEvent | None:
        if "sshd" not in line:
            return None
        if len(line) > MAX_JSON_LINE_LENGTH:
            self.stats.oversized_lines += 1
            return None
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        ident = obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM")
        message = obj.get("MESSAGE")
        stamp = obj.get("__REALTIME_TIMESTAMP")
        if not isinstance(ident, str) or _SSHD_PROG.match(ident) is None:
            return None
        if not isinstance(message, str) or len(message) > self.max_line_length:
            return None
        if not isinstance(stamp, str) or not stamp.isdigit() or len(stamp) > 18:
            return None
        try:
            timestamp = datetime.fromtimestamp(int(stamp) / 1_000_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        host = obj.get("_HOSTNAME")
        host = host if isinstance(host, str) else ""
        pid_raw = obj.get("_PID") or obj.get("SYSLOG_PID")
        pid = int(pid_raw) if isinstance(pid_raw, str) and pid_raw.isdigit() and len(pid_raw) <= 10 else None
        raw = f"{timestamp.isoformat()} {host} {ident}[{pid if pid is not None else '-'}]: {message}"
        return self._event_from_message(
            message, timestamp=timestamp, host=host, pid=pid, line_number=line_number, raw=raw
        )

    # ------------------------------------------------------------- messages

    @staticmethod
    def _match_message(message: str) -> _Fields | None:
        """Classify one sshd message (without syslog header)."""
        if message.startswith("Failed "):
            m = _FAILED.match(message)
            if m is None:
                return None
            method = m["method"]
            if method == "none":
                kind = EventType.FAILED_NONE
            elif method in _PASSWORD_METHODS:
                kind = EventType.FAILED_PASSWORD
            elif method in _PUBLICKEY_METHODS:
                kind = EventType.FAILED_PUBLICKEY
            else:
                kind = EventType.FAILED_OTHER
            return _Fields(kind, method, m["user"], bool(m["invalid"]), m["ip"], m["port"])
        if message.startswith("Accepted "):
            m = _ACCEPTED.match(message)
            if m is None:
                return None
            method = m["method"]
            if method == "password":
                kind = EventType.ACCEPTED_PASSWORD
            elif method == "publickey":
                kind = EventType.ACCEPTED_PUBLICKEY
            else:
                kind = EventType.ACCEPTED_OTHER
            return _Fields(kind, method, m["user"], False, m["ip"], m["port"])
        if message.startswith("Invalid user "):
            m = _INVALID_USER.match(message)
            if m is None:
                return None
            return _Fields(EventType.INVALID_USER, "", m["user"], True, m["ip"], m["port"])
        if message.startswith(("Connection closed by ", "Disconnected from ")):
            m = _PREAUTH.match(message)
            if m is None:
                return None
            return _Fields(
                EventType.PREAUTH_DISCONNECT, "", m["user"], m["kind"] == "invalid", m["ip"], m["port"]
            )
        if message.startswith("error: maximum authentication attempts exceeded"):
            m = _MAX_AUTH.match(message)
            if m is None:
                return None
            return _Fields(EventType.MAX_AUTH_EXCEEDED, "", m["user"], bool(m["invalid"]), m["ip"], m["port"])
        if message.startswith(("pam_unix(", "PAM ")):
            m = _PAM.search(message)
            if m is None:
                return None
            return _Fields(EventType.AUTH_FAILURE, "pam", m["user"], False, m["ip"], None)
        return None

    def _event_from_message(
        self,
        message: str,
        *,
        timestamp: datetime,
        host: str,
        pid: int | None,
        line_number: int,
        raw: str,
    ) -> SshAuthEvent | None:
        weight = 1
        repeated = _REPEATED.match(message)
        if repeated is not None:
            weight = min(int(repeated["n"]), MAX_REPEAT)
            message = repeated["inner"]
        fields = self._match_message(message)
        if fields is None:
            return None

        ip = normalize_ip(fields.ip)
        if ip is None:
            self.stats.invalid_ip_lines += 1
            return None
        port: int | None = None
        if fields.port is not None:
            value = int(fields.port)
            port = value if 1 <= value <= 65535 else None

        if " from " in fields.user or " port " in fields.user:
            self.stats.suspicious_lines += 1

        return SshAuthEvent(
            timestamp=timestamp,
            event_type=fields.event_type,
            source_ip=ip,
            username=sanitize_text(fields.user, _USERNAME_MAX),
            host=sanitize_text(host, 64),
            pid=pid,
            port=port,
            is_invalid_user=fields.invalid,
            auth_method=sanitize_text(fields.method, 32),
            weight=max(weight, 1),
            line_number=line_number,
            raw_line=sanitize_text(raw, _RAW_LINE_MAX),
            source=self._source,
        )


def _build(
    year: int,
    month: int,
    day: int,
    hour: int,
    minute: int,
    second: int,
    tz: tzinfo,
    micro: int = 0,
) -> datetime | None:
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None

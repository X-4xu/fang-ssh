"""Line sources: plain/compressed files, stdin, journald and live file following.

All sources yield ``(line_number, text)`` pairs and share the same safety
rules: lines are read in bounded chunks (a multi-gigabyte line cannot exhaust
memory), compression is detected from magic bytes rather than file names, and
only regular files are opened.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import lzma
import os
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import IO, Any, Protocol, cast

from .models import AnalysisStats

#: Longest line (bytes) that is ever buffered. Longer lines are skipped.
MAX_LINE_BYTES = 65536
_SECURE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class SourceError(Exception):
    """A log source could not be read to completion."""


class LineSource(Protocol):
    name: str

    @property
    def reference_time(self) -> datetime | None: ...

    def lines(self) -> Iterator[tuple[int, str]]: ...


def iter_binary_lines(
    handle: IO[bytes],
    stats: AnalysisStats,
    *,
    max_line: int = MAX_LINE_BYTES,
    max_bytes: int = 0,
) -> Iterator[tuple[int, str]]:
    """Yield decoded lines from a binary stream with a hard per-line cap."""
    number = 0
    total = 0
    while True:
        chunk = handle.readline(max_line + 1)
        if not chunk:
            return
        total += len(chunk)
        if max_bytes and total > max_bytes:
            raise SourceError(f"input exceeds the --max-bytes limit ({max_bytes} bytes)")
        number += 1
        if len(chunk) > max_line and not chunk.endswith(b"\n"):
            # Oversized line: drop it, then discard the rest up to the newline.
            stats.oversized_lines += 1
            stats.lines_read += 1
            while True:
                rest = handle.readline(max_line)
                total += len(rest)
                if max_bytes and total > max_bytes:
                    raise SourceError(f"input exceeds the --max-bytes limit ({max_bytes} bytes)")
                if not rest or rest.endswith(b"\n"):
                    break
            continue
        stats.lines_read += 1
        yield number, chunk.decode("utf-8", "replace").rstrip("\r\n")


def _open_maybe_compressed(path: str, stack: contextlib.ExitStack) -> IO[bytes]:
    raw = stack.enter_context(open(path, "rb"))  # noqa: SIM115 - managed by stack
    magic = raw.read(6)
    raw.seek(0)
    if magic[:2] == b"\x1f\x8b":
        return cast(IO[bytes], stack.enter_context(gzip.GzipFile(fileobj=raw)))
    if magic[:3] == b"BZh":
        return cast(IO[bytes], stack.enter_context(bz2.BZ2File(raw)))
    if magic[:6] == b"\xfd7zXZ\x00":
        return cast(IO[bytes], stack.enter_context(lzma.LZMAFile(raw)))
    if magic[:4] == b"\x28\xb5\x2f\xfd":
        raise SourceError(f"{path}: zstd archives are not supported; decompress first or pipe via stdin")
    return raw


class FileSource:
    """A regular log file; gzip, bzip2 and xz are detected automatically."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        stats: AnalysisStats | None = None,
        max_bytes: int = 0,
    ) -> None:
        self.path = os.fspath(path)
        self.name = self.path
        self.stats = stats if stats is not None else AnalysisStats()
        self.max_bytes = max_bytes

    @property
    def reference_time(self) -> datetime | None:
        try:
            return datetime.fromtimestamp(os.stat(self.path).st_mtime, tz=timezone.utc)
        except OSError:
            return None

    def lines(self) -> Iterator[tuple[int, str]]:
        info = os.stat(self.path)  # raises FileNotFoundError / PermissionError
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"{self.path}: not a regular file")
        with contextlib.ExitStack() as stack:
            handle = _open_maybe_compressed(self.path, stack)
            try:
                yield from iter_binary_lines(handle, self.stats, max_bytes=self.max_bytes)
            except (gzip.BadGzipFile, EOFError, lzma.LZMAError, OSError, ValueError) as exc:
                raise SourceError(f"{self.path}: corrupted or truncated input ({exc})") from exc


class StreamSource:
    """A binary stream such as ``sys.stdin.buffer``."""

    def __init__(
        self,
        stream: IO[bytes],
        *,
        name: str = "<stdin>",
        stats: AnalysisStats | None = None,
        max_bytes: int = 0,
    ) -> None:
        self.stream = stream
        self.name = name
        self.stats = stats if stats is not None else AnalysisStats()
        self.max_bytes = max_bytes

    @property
    def reference_time(self) -> datetime | None:
        return None

    def lines(self) -> Iterator[tuple[int, str]]:
        yield from iter_binary_lines(self.stream, self.stats, max_bytes=self.max_bytes)


class FollowSource:
    """``tail -F`` for a plain log file.

    Survives logrotate (new inode) and truncation. Partial lines are buffered
    until their newline arrives. Stops promptly when ``stop_event`` is set.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        stats: AnalysisStats | None = None,
        from_start: bool = False,
        poll_interval: float = 0.5,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.path = os.fspath(path)
        self.name = self.path
        self.stats = stats if stats is not None else AnalysisStats()
        self.from_start = from_start
        self.poll_interval = poll_interval
        self.stop_event = stop_event if stop_event is not None else threading.Event()

    @property
    def reference_time(self) -> datetime | None:
        return None  # live: "now"

    def _open(self) -> IO[bytes]:
        info = os.stat(self.path)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError(f"{self.path}: not a regular file")
        return open(self.path, "rb")  # noqa: SIM115 - closed by the generator

    def _rotated(self, handle: IO[bytes]) -> bool:
        try:
            current = os.stat(self.path)
        except OSError:
            return False  # file is briefly missing during rotation; keep waiting
        opened = os.fstat(handle.fileno())
        return (current.st_ino, current.st_dev) != (opened.st_ino, opened.st_dev)

    def lines(self) -> Iterator[tuple[int, str]]:
        stop = self.stop_event
        handle = self._open()
        number = 0
        pending = b""
        discarding = False
        try:
            if not self.from_start:
                handle.seek(0, os.SEEK_END)
            while not stop.is_set():
                chunk = handle.read(65536)
                if chunk:
                    parts = (pending + chunk).split(b"\n")
                    pending = parts.pop()
                    for part in parts:
                        number += 1
                        self.stats.lines_read += 1
                        if discarding:
                            discarding = False
                            continue
                        if len(part) > MAX_LINE_BYTES:
                            self.stats.oversized_lines += 1
                            continue
                        yield number, part.decode("utf-8", "replace").rstrip("\r")
                    if len(pending) > MAX_LINE_BYTES:
                        self.stats.oversized_lines += 1
                        pending = b""
                        discarding = True
                    continue
                # EOF: check for rotation / truncation, then wait.
                if self._rotated(handle):
                    handle.close()
                    handle = self._open_after_rotation()
                    pending, discarding = b"", False
                    continue
                if os.fstat(handle.fileno()).st_size < handle.tell():
                    handle.seek(0)
                    pending = b""
                    continue
                stop.wait(self.poll_interval)
        finally:
            handle.close()

    def _open_after_rotation(self) -> IO[bytes]:
        while not self.stop_event.is_set():
            try:
                return self._open()
            except FileNotFoundError:
                self.stop_event.wait(self.poll_interval)
        return open(os.devnull, "rb")  # noqa: SIM115 - stop requested; closed by caller


class JournalSource:
    """sshd records from systemd-journald via ``journalctl -o json``."""

    IDENTIFIERS = ("sshd", "sshd-session", "sshd-auth")

    def __init__(
        self,
        *,
        stats: AnalysisStats | None = None,
        since: str | None = None,
        follow: bool = False,
        stop_event: threading.Event | None = None,
        journalctl: str | None = None,
    ) -> None:
        self.name = "journald"
        self.stats = stats if stats is not None else AnalysisStats()
        self.since = since
        self.follow = follow
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.journalctl = journalctl
        self.warnings: list[str] = []
        if since is not None and (not since.strip() or len(since) > 64 or not since.isprintable()):
            raise ValueError("invalid --since value")

    @property
    def reference_time(self) -> datetime | None:
        return None

    @staticmethod
    def available() -> str | None:
        return shutil.which("journalctl", path=_SECURE_PATH)

    def command(self) -> list[str]:
        binary = self.journalctl or self.available()
        if binary is None:
            raise SourceError("journalctl was not found (is systemd installed?)")
        cmd = [binary, "--no-pager", "--quiet", "--output=json"]
        if self.since:
            cmd.append(f"--since={self.since}")  # '=' form: value can never be parsed as an option
        if self.follow:
            cmd.append("--follow")
            if not self.since:
                cmd.append("--lines=0")
        cmd.extend(f"SYSLOG_IDENTIFIER={name}" for name in self.IDENTIFIERS)
        return cmd

    def lines(self) -> Iterator[tuple[int, str]]:
        cmd = self.command()
        env = {"PATH": _SECURE_PATH, "LC_ALL": "C"}
        with tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                    cmd, stdout=subprocess.PIPE, stderr=err, env=env, shell=False
                )
            except OSError as exc:
                raise SourceError(f"cannot run journalctl: {exc}") from exc
            assert proc.stdout is not None
            finished = threading.Event()
            watcher = threading.Thread(target=self._watch, args=(proc, finished), daemon=True)
            watcher.start()
            try:
                yield from iter_binary_lines(proc.stdout, self.stats)
            finally:
                finished.set()
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover - stuck child
                    proc.kill()
                    proc.wait()
                proc.stdout.close()
            err.seek(0)
            message = err.read(4096).decode("utf-8", "replace").strip()
            stopped = self.stop_event.is_set()
            if proc.returncode not in (0, None) and not stopped and proc.returncode >= 0:
                raise SourceError(f"journalctl exited with status {proc.returncode}: {message[:300]}")
            lowered = message.lower()
            if "insufficient permissions" in lowered or "not seeing messages" in lowered:
                self.warnings.append(
                    "journalctl reports insufficient permissions: add the user to the "
                    "'systemd-journal' (or 'adm') group, otherwise sshd entries are invisible"
                )

    def _watch(self, proc: Any, finished: threading.Event) -> None:
        while not finished.is_set():
            if self.stop_event.wait(0.2):
                if proc.poll() is None:
                    with contextlib.suppress(OSError):
                        proc.terminate()
                return

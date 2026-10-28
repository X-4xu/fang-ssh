"""Sources: compression detection, size limits, follow/rotation, journald."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from fang.models import AnalysisStats
from fang.sources import (
    MAX_LINE_BYTES,
    FileSource,
    FollowSource,
    JournalSource,
    SourceError,
    StreamSource,
    iter_binary_lines,
)

LINE = "Sep 19 10:00:10 host sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"


def read_all(source) -> list[str]:  # type: ignore[no-untyped-def]
    return [text for _, text in source.lines()]


# ---------------------------------------------------------------- line reader


def test_oversized_line_is_skipped_without_losing_the_next_line() -> None:
    stats = AnalysisStats()
    data = b"first\n" + b"x" * (MAX_LINE_BYTES * 3 + 17) + b"\nthird\n"
    lines = list(iter_binary_lines(io.BytesIO(data), stats))
    assert [text for _, text in lines] == ["first", "third"]
    assert [n for n, _ in lines] == [1, 3]
    assert stats.oversized_lines == 1
    assert stats.lines_read == 3


def test_line_of_exactly_the_limit_is_kept_and_crlf_is_stripped() -> None:
    stats = AnalysisStats()
    # The limit counts the line terminator: MAX-1 content bytes + CRLF is the longest accepted line.
    data = b"a" * (MAX_LINE_BYTES - 1) + b"\r\n" + b"short\r\n"
    out = [t for _, t in iter_binary_lines(io.BytesIO(data), stats)]
    assert out == ["a" * (MAX_LINE_BYTES - 1), "short"]
    assert stats.oversized_lines == 0


def test_last_line_without_newline_and_invalid_utf8() -> None:
    out = [t for _, t in iter_binary_lines(io.BytesIO(b"ok\n\xff\xfebad"), AnalysisStats())]
    assert out == ["ok", "��bad"]


def test_max_bytes_budget() -> None:
    with pytest.raises(SourceError, match="max-bytes"):
        list(iter_binary_lines(io.BytesIO(b"line\n" * 1000), AnalysisStats(), max_bytes=100))
    with pytest.raises(SourceError, match="max-bytes"):
        list(iter_binary_lines(io.BytesIO(b"x" * (MAX_LINE_BYTES * 4)), AnalysisStats(), max_bytes=1000))


# ----------------------------------------------------------------- FileSource


@pytest.mark.parametrize(
    "opener",
    [gzip.open, bz2.open, lzma.open, open],
    ids=["gzip", "bzip2", "xz", "plain"],
)
def test_compression_is_detected_from_magic_bytes_not_file_name(
    tmp_path: Path, opener: Callable[..., object]
) -> None:
    path = tmp_path / "auth.log"  # deliberately no .gz/.bz2/.xz suffix
    with opener(path, "wb") as handle:  # type: ignore[operator]
        handle.write(f"{LINE}\n{LINE}\n".encode())  # type: ignore[attr-defined]
    assert read_all(FileSource(path)) == [LINE, LINE]


def test_multi_member_gzip(tmp_path: Path) -> None:
    path = tmp_path / "multi.gz"
    path.write_bytes(gzip.compress(f"{LINE}\n".encode()) + gzip.compress(f"{LINE}\n".encode()))
    assert len(read_all(FileSource(path))) == 2


def test_truncated_archive_yields_partial_data_then_source_error(tmp_path: Path) -> None:
    path = tmp_path / "cut.gz"
    blob = gzip.compress(("\n".join(f"{LINE} {i}" for i in range(5000)) + "\n").encode())
    path.write_bytes(blob[: len(blob) // 2])
    got: list[str] = []
    with pytest.raises(SourceError, match="corrupted or truncated"):
        for _, text in FileSource(path).lines():
            got.append(text)
    assert got  # data before the corruption was still delivered


def test_missing_file_and_non_regular_files(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_all(FileSource(tmp_path / "nope.log"))
    with pytest.raises(SourceError, match="not a regular file"):
        read_all(FileSource(tmp_path))
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(SourceError, match="not a regular file"):  # must not block forever
        read_all(FileSource(fifo))


def test_decompression_bomb_is_stopped_by_max_bytes(tmp_path: Path) -> None:
    path = tmp_path / "bomb.gz"
    with gzip.open(path, "wb") as handle:
        for _ in range(200):
            handle.write(b"a" * 100_000 + b"\n")  # 20 MB of text from a tiny archive
    assert path.stat().st_size < 200_000
    with pytest.raises(SourceError, match="max-bytes"):
        read_all(FileSource(path, max_bytes=1_000_000))


def test_reference_time_is_the_file_mtime(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    path.write_text("x\n")
    os.utime(path, (1_700_000_000, 1_700_000_000))
    ref = FileSource(path).reference_time
    assert ref is not None
    assert ref.timestamp() == 1_700_000_000
    assert FileSource(tmp_path / "missing").reference_time is None


def test_stream_source() -> None:
    src = StreamSource(io.BytesIO(f"{LINE}\n".encode()))
    assert read_all(src) == [LINE]
    assert src.reference_time is None


# ---------------------------------------------------------------- FollowSource


class Follower:
    """Runs FollowSource in a thread and collects lines."""

    def __init__(self, path: Path, **kwargs: object) -> None:
        self.stop = threading.Event()
        self.lines: list[str] = []
        self.source = FollowSource(path, poll_interval=0.02, stop_event=self.stop, **kwargs)  # type: ignore[arg-type]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.error: BaseException | None = None
        self.thread.start()

    def _run(self) -> None:
        try:
            for _, text in self.source.lines():
                self.lines.append(text)
        except BaseException as exc:  # pragma: no cover - surfaced by the test
            self.error = exc

    def wait_for(self, count: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self.lines) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(self.lines) >= count, self.lines

    def close(self) -> None:
        self.stop.set()
        self.thread.join(5)
        assert not self.thread.is_alive()
        assert self.error is None


def append(path: Path, text: str) -> None:
    with open(path, "ab") as handle:
        handle.write(text.encode())


def test_follow_reads_only_new_lines_by_default(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("old line\n")
    f = Follower(path)
    time.sleep(0.1)
    append(path, "new 1\nnew 2\n")
    f.wait_for(2)
    f.close()
    assert f.lines == ["new 1", "new 2"]


def test_follow_from_start_and_partial_lines(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("old\n")
    f = Follower(path, from_start=True)
    f.wait_for(1)
    append(path, "half a li")
    time.sleep(0.1)
    assert f.lines == ["old"]  # incomplete line is held back
    append(path, "ne\n")
    f.wait_for(2)
    f.close()
    assert f.lines == ["old", "half a line"]


def test_follow_survives_logrotate_rename(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    f = Follower(path)
    time.sleep(0.1)
    append(path, "before rotation\n")
    f.wait_for(1)
    os.rename(path, tmp_path / "auth.log.1")
    time.sleep(0.15)  # file briefly missing
    path.write_text("after rotation\n")
    f.wait_for(2)
    f.close()
    assert f.lines == ["before rotation", "after rotation"]


def test_follow_survives_truncation(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    f = Follower(path)
    time.sleep(0.1)
    append(path, "one\ntwo\nthree\n")
    f.wait_for(3)
    path.write_text("")  # copytruncate-style rotation
    time.sleep(0.15)
    append(path, "four\n")
    f.wait_for(4)
    f.close()
    assert f.lines[-1] == "four"


def test_follow_drops_oversized_line_and_recovers(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    f = Follower(path)
    time.sleep(0.1)
    append(path, "x" * (MAX_LINE_BYTES * 2))
    time.sleep(0.15)
    append(path, "still junk\nclean\n")
    f.wait_for(1)
    f.close()
    assert f.lines == ["clean"]
    assert f.source.stats.oversized_lines >= 1


def test_follow_stops_promptly_and_rejects_bad_targets(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    f = Follower(path)
    started = time.monotonic()
    f.close()
    assert time.monotonic() - started < 2
    with pytest.raises(FileNotFoundError):
        read_all(FollowSource(tmp_path / "missing.log"))
    with pytest.raises(SourceError):
        read_all(FollowSource(tmp_path))


# ---------------------------------------------------------------- JournalSource


def fake_journalctl(tmp_path: Path, body: str) -> str:
    script = tmp_path / "journalctl"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def test_journal_command_is_a_fixed_argv_without_shell_injection() -> None:
    src = JournalSource(journalctl="/usr/bin/journalctl", since="1 hour ago; touch /tmp/x")
    cmd = src.command()
    assert cmd[0] == "/usr/bin/journalctl"
    assert "--since=1 hour ago; touch /tmp/x" in cmd  # one argv element, '=' form, never a shell string
    assert "--output=json" in cmd
    assert {"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth"} <= set(
        cmd
    )
    follow = JournalSource(journalctl="/x", follow=True).command()
    assert "--follow" in follow
    assert "--lines=0" in follow
    assert "--lines=0" not in JournalSource(journalctl="/x", follow=True, since="today").command()


@pytest.mark.parametrize("bad", ["", "   ", "x" * 100, "a\nb", "a\x00b"])
def test_journal_rejects_bad_since_values(bad: str) -> None:
    with pytest.raises(ValueError, match="since"):
        JournalSource(since=bad)


def test_journal_reads_json_lines_from_the_subprocess(tmp_path: Path) -> None:
    jc = fake_journalctl(tmp_path, 'echo \'{"MESSAGE": "one"}\'\necho \'{"MESSAGE": "two"}\'\n')
    assert read_all(JournalSource(journalctl=jc)) == ['{"MESSAGE": "one"}', '{"MESSAGE": "two"}']


def test_journal_failure_and_permission_hint(tmp_path: Path) -> None:
    failing = fake_journalctl(tmp_path, "echo 'boom' >&2\nexit 3\n")
    with pytest.raises(SourceError, match="status 3.*boom"):
        read_all(JournalSource(journalctl=failing))

    hint = tmp_path / "hint"
    hint.mkdir()
    quiet = fake_journalctl(
        hint, "echo 'Hint: You are currently not seeing messages from other users and the system.' >&2\n"
    )
    src = JournalSource(journalctl=quiet)
    assert read_all(src) == []
    assert any("systemd-journal" in w for w in src.warnings)


def test_journal_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="cannot run journalctl"):
        read_all(JournalSource(journalctl=str(tmp_path / "does-not-exist")))


def test_journal_follow_stops_when_asked(tmp_path: Path) -> None:
    jc = fake_journalctl(tmp_path, 'echo \'{"MESSAGE": "x"}\'\nexec sleep 60\n')
    stop = threading.Event()
    src = JournalSource(journalctl=jc, follow=True, stop_event=stop)
    got: list[str] = []

    def run() -> None:
        got.extend(text for _, text in src.lines())

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.4)
    started = time.monotonic()
    stop.set()
    t.join(8)
    assert not t.is_alive()
    assert time.monotonic() - started < 6
    assert got == ['{"MESSAGE": "x"}']

"""Small, dependency-free helpers: sanitizing, IP handling, safe file writes."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import tempfile
from collections.abc import Iterable, Iterator

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def sanitize_text(value: str, max_len: int = 256) -> str:
    """Make untrusted text safe to print or store.

    Anything that is not printable (C0/C1 controls, ESC, bidi overrides,
    zero-width and other format characters, lone surrogates, ...) is replaced
    with ``?`` and the result is truncated to ``max_len`` characters.
    """
    if len(value) > max_len:
        value = value[:max_len]
    if value.isascii() and value.isprintable():
        return value
    return "".join(ch if ch.isprintable() else "?" for ch in value)


def normalize_ip(value: str) -> str | None:
    """Return the canonical form of ``value`` or ``None`` if it is not an IP.

    * IPv6 zone ids (``fe80::1%eth0``) are dropped.
    * IPv4-mapped IPv6 addresses (``::ffff:1.2.3.4``) become plain IPv4 so the
      same host is never tracked (or allow-listed) under two identities.
    """
    if not value or len(value) > 64:
        return None
    candidate = value.split("%", 1)[0]
    try:
        ip: IPAddress = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def is_protected_ip(ip: str) -> bool:
    """Addresses that must never be proposed for blocking."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved
    )


class Allowlist:
    """A set of trusted IPs / CIDR ranges that never raise alerts or blocks."""

    _CACHE_LIMIT = 4096

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._networks: list[IPNetwork] = []
        self._cache: dict[str, bool] = {}
        for entry in entries:
            self.add(entry)

    def add(self, entry: str) -> None:
        text = entry.strip()
        if not text:
            raise ValueError("empty allowlist entry")
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid allowlist entry {entry!r}: {exc}") from None
        if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped is not None:
            raise ValueError(f"use plain IPv4 notation instead of IPv4-mapped {entry!r}")
        self._networks.append(network)
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._networks)

    def __iter__(self) -> Iterator[str]:
        return (str(n) for n in self._networks)

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str) or not self._networks:
            return False
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        normalized = normalize_ip(ip)
        result = False
        if normalized is not None:
            addr = ipaddress.ip_address(normalized)
            result = any(addr in net for net in self._networks if net.version == addr.version)
        if len(self._cache) >= self._CACHE_LIMIT:
            self._cache.clear()
        self._cache[ip] = result
        return result


def atomic_write_text(path: str | os.PathLike[str], text: str, mode: int = 0o600) -> None:
    """Write ``text`` to ``path`` atomically with restrictive permissions.

    The data goes to a freshly created, exclusively owned temporary file in the
    same directory and is then renamed over the target. If ``path`` is a
    symlink the *link* is replaced, never followed, so a hostile symlink in a
    shared directory cannot redirect a root-owned write.
    """
    target = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(target)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".fang-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

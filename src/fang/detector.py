"""Detection engine.

Rules (all evaluated on *event time*, so replaying an old log gives the same
result as watching it live):

``brute_force``         >= threshold failed attempts from one IP within ``window`` seconds
``slow_brute_force``    >= slow_threshold attempts from one IP within ``history_window``
                        (catches "low and slow" attackers that stay under the fast rule)
``distributed_attack``  >= spray_threshold distinct IPs failing against the *same account*
                        within ``spray_window`` (password spraying / botnets)
``possible_compromise`` a successful login from an IP that had >= compromise_failures
                        recent failures

Memory is bounded: tracked IPs/accounts live in capped LRU maps, windows have
hard length limits, evidence per alert is capped, and idle state is pruned.
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import (
    ACCEPTED_TYPES,
    STRONG_FAILURES,
    WEAK_FAILURES,
    AlertType,
    AnalysisStats,
    EventType,
    SecurityAlert,
    Severity,
    SshAuthEvent,
)
from .util import Allowlist

log = logging.getLogger("fang.detector")

DEFAULT_PRIVILEGED_USERS = frozenset({"root", "admin", "administrator", "wheel"})
_MAX_SEEN_IPS = 1_000_000
_PRUNE_EVERY = 10_000
_CONNECTION_TTL = 3600.0
_MAX_LISTED = 50
_BOARD_SIZE = 100
_MAX_WINDOW_SECONDS = 7 * 86400

_PASSWORD_LIKE = frozenset(
    {"password", "keyboard-interactive/pam", "keyboard-interactive", "challenge-response"}
)


@dataclass
class DetectorConfig:
    """Tunable detection parameters. Set a threshold to 0 to disable a rule."""

    threshold: int = 5
    window: int = 60
    cooldown: int = 300
    slow_threshold: int = 20
    history_window: int = 3600
    spray_threshold: int = 10
    spray_window: int = 600
    compromise_failures: int = 3
    count_preauth_disconnects: bool = True
    privileged_users: frozenset[str] = DEFAULT_PRIVILEGED_USERS
    allowlist: Allowlist = field(default_factory=Allowlist)
    max_tracked_ips: int = 25_000
    max_tracked_users: int = 25_000
    max_events_per_window: int = 5_000
    evidence_limit: int = 20

    def __post_init__(self) -> None:
        self.privileged_users = frozenset(u.strip().lower() for u in self.privileged_users if u.strip())
        self.validate()

    def validate(self) -> None:
        def check(name: str, value: int, low: int, high: int) -> None:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high} (got {value})")

        check("threshold", self.threshold, 1, 1_000_000)
        check("window", self.window, 1, _MAX_WINDOW_SECONDS)
        check("cooldown", self.cooldown, 0, _MAX_WINDOW_SECONDS)
        check("slow_threshold", self.slow_threshold, 0, 10_000_000)
        check("history_window", self.history_window, 1, _MAX_WINDOW_SECONDS)
        check("spray_threshold", self.spray_threshold, 0, 1_000_000)
        check("spray_window", self.spray_window, 1, _MAX_WINDOW_SECONDS)
        check("compromise_failures", self.compromise_failures, 0, 1_000_000)
        check("max_tracked_ips", self.max_tracked_ips, 100, 10_000_000)
        check("max_tracked_users", self.max_tracked_users, 100, 10_000_000)
        check("max_events_per_window", self.max_events_per_window, 10, 1_000_000)
        check("evidence_limit", self.evidence_limit, 1, 1000)
        if self.spray_threshold == 1:
            raise ValueError("spray_threshold must be 0 (disabled) or at least 2")
        if self.slow_threshold and self.slow_threshold < self.threshold:
            raise ValueError(
                f"slow_threshold ({self.slow_threshold}) is lower than threshold ({self.threshold}), "
                "which would flag fast bursts as 'low-and-slow': raise slow_threshold "
                "or set it to 0 to disable the slow rule"
            )
        if (self.slow_threshold or self.compromise_failures) and self.history_window < self.window:
            raise ValueError("history_window must be >= window")

    def to_dict(self) -> dict[str, object]:
        return {
            "threshold": self.threshold,
            "window": self.window,
            "cooldown": self.cooldown,
            "slow_threshold": self.slow_threshold,
            "history_window": self.history_window,
            "spray_threshold": self.spray_threshold,
            "spray_window": self.spray_window,
            "compromise_failures": self.compromise_failures,
            "count_preauth_disconnects": self.count_preauth_disconnects,
            "privileged_users": sorted(self.privileged_users),
            "allowlist": list(self.allowlist),
            "max_tracked_ips": self.max_tracked_ips,
            "max_tracked_users": self.max_tracked_users,
            "evidence_limit": self.evidence_limit,
        }


# --------------------------------------------------------------- internals

_Item = tuple[float, int, str, "int | None", bool]  # ts, weight, user, port, privileged


class _Window:
    """Time-ordered window with a running weighted total and a hard size cap."""

    __slots__ = ("items", "maxlen", "priv", "total")

    def __init__(self, maxlen: int) -> None:
        self.items: deque[_Item] = deque()
        self.total = 0
        self.priv = 0
        self.maxlen = maxlen

    def _pop(self) -> None:
        _, weight, _, _, priv = self.items.popleft()
        self.total -= weight
        if priv:
            self.priv -= weight

    def push(self, ts: float, weight: int, user: str, port: int | None, priv: bool) -> None:
        if len(self.items) >= self.maxlen:
            self._pop()
        self.items.append((ts, weight, user, port, priv))
        self.total += weight
        if priv:
            self.priv += weight

    def evict(self, cutoff: float) -> None:
        items = self.items
        while items and items[0][0] < cutoff:
            self._pop()


class _IpState:
    __slots__ = ("evidence", "fast", "first_ts", "hist", "last_ts", "total", "users")

    def __init__(self, cfg: DetectorConfig, track_history: bool) -> None:
        self.fast = _Window(cfg.max_events_per_window)
        self.hist: _Window | None = _Window(cfg.max_events_per_window) if track_history else None
        self.evidence: deque[SshAuthEvent] = deque(maxlen=cfg.evidence_limit)
        self.total = 0
        self.first_ts = float("inf")
        self.last_ts = float("-inf")
        self.users: set[str] = set()


class _UserState:
    __slots__ = ("evidence", "ips", "items", "last_ts", "privileged", "total")

    def __init__(self, cfg: DetectorConfig, privileged: bool) -> None:
        self.items: deque[tuple[float, str, int]] = deque()
        self.ips: dict[str, int] = {}
        self.evidence: deque[SshAuthEvent] = deque(maxlen=cfg.evidence_limit)
        self.total = 0
        self.last_ts = float("-inf")
        self.privileged = privileged

    def push(self, ts: float, ip: str, weight: int, maxlen: int) -> None:
        if len(self.items) >= maxlen:
            self._pop()
        self.items.append((ts, ip, weight))
        self.ips[ip] = self.ips.get(ip, 0) + weight
        self.total += weight

    def _pop(self) -> None:
        _, ip, weight = self.items.popleft()
        remaining = self.ips.get(ip, 0) - weight
        if remaining <= 0:
            self.ips.pop(ip, None)
        else:
            self.ips[ip] = remaining
        self.total -= weight

    def evict(self, cutoff: float) -> None:
        while self.items and self.items[0][0] < cutoff:
            self._pop()


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _alert_id(kind: AlertType, subject: str, start: float, severity: Severity) -> str:
    digest = hashlib.sha256(f"{kind.value}|{subject}|{start:.3f}|{severity.value}".encode()).hexdigest()
    return f"ALERT-FANG-{digest[:10].upper()}"


# ---------------------------------------------------------------- detector


class Detector:
    """Stateful detector. Feed events in (roughly) chronological order."""

    def __init__(self, config: DetectorConfig | None = None, stats: AnalysisStats | None = None) -> None:
        self.config = config if config is not None else DetectorConfig()
        self.stats = stats if stats is not None else AnalysisStats()
        cfg = self.config
        self._track_history = bool(cfg.slow_threshold or cfg.compromise_failures)
        self._ips: OrderedDict[str, _IpState] = OrderedDict()
        self._users: OrderedDict[str, _UserState] = OrderedDict()
        self._cooldowns: OrderedDict[tuple[AlertType, str], tuple[float, int]] = OrderedDict()
        self._connections: OrderedDict[tuple[str, str, int | None], float] = OrderedDict()
        self._seen_ips: set[str] = set()
        self._board: dict[str, list[float | int | set[str]]] = {}
        self._latest = float("-inf")
        self._since_prune = 0

    # ------------------------------------------------------------ public

    @property
    def tracked_ips(self) -> int:
        return len(self._ips)

    def process(self, event: SshAuthEvent) -> list[SecurityAlert]:
        """Consume one event and return the alerts it triggered (usually none)."""
        stats = self.stats
        stats.events_parsed += 1
        if event.source_ip in self.config.allowlist:
            stats.allowlisted_events += 1
            return []
        if event.event_type in ACCEPTED_TYPES:
            stats.accepted_logins += 1
            return self._on_accepted(event)
        if not self._counts_as_failure(event):
            return []
        return self._on_failure(event)

    def finalize(self) -> AnalysisStats:
        self.stats.unique_source_ips = len(self._seen_ips)
        self.stats.unique_ips_capped = len(self._seen_ips) >= _MAX_SEEN_IPS
        return self.stats

    def top_offenders(self, limit: int = 10) -> list[dict[str, Any]]:
        """Highest-volume source IPs seen (live state merged with retired state)."""
        merged: dict[str, list[float | int | set[str]]] = {
            ip: [row[0], row[1], row[2], set(row[3])]  # type: ignore[arg-type]
            for ip, row in self._board.items()
        }
        for ip, st in self._ips.items():
            row = merged.get(ip)
            if row is None:
                merged[ip] = [st.total, st.first_ts, st.last_ts, set(st.users)]
            else:
                row[0] = int(row[0]) + st.total  # type: ignore[arg-type]
                row[1] = min(float(row[1]), st.first_ts)  # type: ignore[arg-type]
                row[2] = max(float(row[2]), st.last_ts)  # type: ignore[arg-type]
                row[3] = set(row[3]) | st.users  # type: ignore[arg-type]
        ranked = sorted(merged.items(), key=lambda kv: (-int(kv[1][0]), kv[0]))[:limit]  # type: ignore[arg-type]
        return [
            {
                "ip": ip,
                "failed_attempts": int(row[0]),  # type: ignore[arg-type]
                "first_seen": _utc(float(row[1])).isoformat(),  # type: ignore[arg-type]
                "last_seen": _utc(float(row[2])).isoformat(),  # type: ignore[arg-type]
                "usernames": sorted(row[3])[:10],  # type: ignore[arg-type]
            }
            for ip, row in ranked
        ]

    # ----------------------------------------------------------- failures

    def _counts_as_failure(self, event: SshAuthEvent) -> bool:
        kind = event.event_type
        if kind in STRONG_FAILURES:
            self._mark_connection(event)
            return True
        if kind in WEAK_FAILURES:
            if not self.config.count_preauth_disconnects:
                return False
            key = (event.host, event.source_ip, event.port)
            seen = self._connections.get(key)
            ts = event.timestamp.timestamp()
            if seen is not None and abs(ts - seen) <= _CONNECTION_TTL:
                return False  # this connection already produced a failure
            self._mark_connection(event)
            return True
        return False

    def _mark_connection(self, event: SshAuthEvent) -> None:
        key = (event.host, event.source_ip, event.port)
        self._connections[key] = event.timestamp.timestamp()
        self._connections.move_to_end(key)
        if len(self._connections) > 100_000:
            self._connections.popitem(last=False)

    def _ip_state(self, ip: str) -> _IpState:
        state = self._ips.get(ip)
        if state is not None:
            self._ips.move_to_end(ip)
            return state
        if len(self._ips) >= self.config.max_tracked_ips:
            old_ip, old = self._ips.popitem(last=False)
            self._retire(old_ip, old)
            self.stats.evicted_states += 1
        state = _IpState(self.config, self._track_history)
        self._ips[ip] = state
        return state

    def _user_state(self, user: str) -> _UserState:
        state = self._users.get(user)
        if state is not None:
            self._users.move_to_end(user)
            return state
        if len(self._users) >= self.config.max_tracked_users:
            self._users.popitem(last=False)
            self.stats.evicted_states += 1
        state = _UserState(self.config, user.lower() in self.config.privileged_users)
        self._users[user] = state
        return state

    def _on_failure(self, event: SshAuthEvent) -> list[SecurityAlert]:
        cfg = self.config
        ip = event.source_ip
        ts = event.timestamp.timestamp()
        weight = event.weight
        user = event.username
        priv = user.lower() in cfg.privileged_users

        self.stats.failed_attempts += weight
        if len(self._seen_ips) < _MAX_SEEN_IPS:
            self._seen_ips.add(ip)
        if ts > self._latest:
            self._latest = ts

        state = self._ip_state(ip)
        state.total += weight
        state.first_ts = min(state.first_ts, ts)
        state.last_ts = max(state.last_ts, ts)
        if len(state.users) < 20:
            state.users.add(user)

        fast_cutoff = state.last_ts - cfg.window
        state.fast.evict(fast_cutoff)
        if ts >= fast_cutoff:
            state.fast.push(ts, weight, user, event.port, priv)
        if state.hist is not None:
            hist_cutoff = state.last_ts - cfg.history_window
            state.hist.evict(hist_cutoff)
            if ts >= hist_cutoff:
                state.hist.push(ts, weight, user, event.port, priv)
        state.evidence.append(event)

        alerts: list[SecurityAlert] = []
        fast_total = state.fast.total
        if fast_total >= cfg.threshold:
            alert = self._brute_force(ip, state, ts)
            if alert is not None:
                alerts.append(alert)
        elif cfg.slow_threshold and state.hist is not None and state.hist.total >= cfg.slow_threshold:
            alert = self._slow_brute_force(ip, state, ts)
            if alert is not None:
                alerts.append(alert)

        if cfg.spray_threshold:
            alert = self._spray(event, ts, weight)
            if alert is not None:
                alerts.append(alert)

        self._since_prune += 1
        if self._since_prune >= _PRUNE_EVERY:
            self._prune()
        return alerts

    # ------------------------------------------------------------- rules

    def _should_emit(
        self, key: tuple[AlertType, str], severity: Severity, ts: float, cooldown: int | None = None
    ) -> bool:
        """Decide whether an alert for ``key`` is emitted now.

        An alert repeats only after the cooldown, unless its severity *rose*
        (an escalation, flagged via ``self._escalation``).
        """
        previous = self._cooldowns.get(key)
        self._escalation = False
        wait = self.config.cooldown if cooldown is None else cooldown
        if previous is None or ts - previous[0] >= wait:
            emit = True
        elif severity.rank > previous[1]:
            emit = True
            self._escalation = True
        else:
            self.stats.suppressed_alerts += 1
            return False
        self._cooldowns[key] = (ts, severity.rank)
        self._cooldowns.move_to_end(key)
        if len(self._cooldowns) > self.config.max_tracked_ips * 2:
            self._cooldowns.popitem(last=False)
        return emit

    _escalation = False

    def _brute_force(self, ip: str, state: _IpState, ts: float) -> SecurityAlert | None:
        cfg = self.config
        count = state.fast.total
        privileged = state.fast.priv > 0
        if count >= 4 * cfg.threshold or (privileged and count >= 2 * cfg.threshold):
            severity = Severity.CRITICAL
        elif count >= 2 * cfg.threshold or privileged:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        if not self._should_emit((AlertType.BRUTE_FORCE, ip), severity, ts):
            return None
        items = list(state.fast.items)
        start, end = items[0][0], items[-1][0]
        pattern = (
            f"SSH brute-force: {count} failed attempts in {max(end - start, 0.0):.1f}s "
            f"(threshold {cfg.threshold}/{cfg.window}s)"
        )
        return self._make_alert(
            AlertType.BRUTE_FORCE,
            severity,
            ip,
            [ip],
            pattern,
            count,
            cfg.window,
            items,
            state,
            start,
            end,
            ts,
        )

    def _slow_brute_force(self, ip: str, state: _IpState, ts: float) -> SecurityAlert | None:
        cfg = self.config
        assert state.hist is not None
        count = state.hist.total
        privileged = state.hist.priv > 0
        if count >= 5 * cfg.slow_threshold or (privileged and count >= 2 * cfg.slow_threshold):
            severity = Severity.CRITICAL
        elif count >= 2 * cfg.slow_threshold or privileged:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        # A slow attack lasts hours: re-alert at most once per history window.
        slow_cooldown = max(cfg.cooldown, cfg.history_window)
        if not self._should_emit((AlertType.SLOW_BRUTE_FORCE, ip), severity, ts, slow_cooldown):
            return None
        items = list(state.hist.items)
        start, end = items[0][0], items[-1][0]
        pattern = (
            f"Low-and-slow SSH brute-force: {count} failed attempts over {max(end - start, 0.0) / 60:.1f} min "
            f"(threshold {cfg.slow_threshold}/{cfg.history_window}s)"
        )
        return self._make_alert(
            AlertType.SLOW_BRUTE_FORCE, severity, ip, [ip], pattern, count, cfg.history_window,
            items, state, start, end, ts,
        )  # fmt: skip

    def _spray(self, event: SshAuthEvent, ts: float, weight: int) -> SecurityAlert | None:
        cfg = self.config
        user = event.username
        us = self._user_state(user)
        us.last_ts = max(us.last_ts, ts)
        us.evict(us.last_ts - cfg.spray_window)
        if ts >= us.last_ts - cfg.spray_window:
            us.push(ts, event.source_ip, weight, cfg.max_events_per_window)
        us.evidence.append(event)
        distinct = len(us.ips)
        if distinct < cfg.spray_threshold:
            return None
        if distinct >= 4 * cfg.spray_threshold:
            severity = Severity.CRITICAL
        elif distinct >= 2 * cfg.spray_threshold or us.privileged:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        if not self._should_emit((AlertType.DISTRIBUTED_ATTACK, user), severity, ts):
            return None
        ranked = sorted(us.ips.items(), key=lambda kv: (-kv[1], kv[0]))
        ips = [ip for ip, _ in ranked[:_MAX_LISTED]]
        start, end = us.items[0][0], us.items[-1][0]
        evidence = [e for e in us.evidence if e.timestamp.timestamp() >= us.last_ts - cfg.spray_window]
        ports = sorted({e.port for e in evidence if e.port is not None})[:_MAX_LISTED]
        pattern = (
            f"Distributed attack on account '{user}': {distinct} distinct sources, "
            f"{us.total} failed attempts within {cfg.spray_window}s"
        )
        return SecurityAlert(
            alert_id=_alert_id(AlertType.DISTRIBUTED_ATTACK, user, start, severity),
            alert_type=AlertType.DISTRIBUTED_ATTACK,
            severity=severity,
            source_ip=None,
            source_ips=ips,
            pattern=pattern,
            attempts=us.total,
            window_seconds=cfg.spray_window,
            start_time=_utc(start),
            end_time=_utc(end),
            triggered_at=_utc(ts),
            target_usernames=[user],
            ports=ports,
            evidence=evidence,
            evidence_truncated=sum(e.weight for e in evidence) < us.total,
            escalation=self._escalation,
        )

    def _on_accepted(self, event: SshAuthEvent) -> list[SecurityAlert]:
        cfg = self.config
        if not cfg.compromise_failures:
            return []
        state = self._ips.get(event.source_ip)
        if state is None or state.hist is None:
            return []
        ts = event.timestamp.timestamp()
        state.hist.evict(max(state.last_ts, ts) - cfg.history_window)
        count = state.hist.total
        if count < cfg.compromise_failures:
            return []
        method = event.auth_method.lower()
        severity = Severity.CRITICAL if method in _PASSWORD_LIKE else Severity.HIGH
        key = (AlertType.POSSIBLE_COMPROMISE, f"{event.source_ip}|{event.username}")
        if not self._should_emit(key, severity, ts):
            return []
        items = list(state.hist.items)
        start = items[0][0]
        same_account = any(item[2] == event.username for item in items)
        pattern = (
            f"Possible compromise: successful {event.auth_method or 'login'} for '{event.username}' "
            f"after {count} failed attempts from the same IP"
            + (" (same account was attacked)" if same_account else "")
        )
        alert = self._make_alert(
            AlertType.POSSIBLE_COMPROMISE, severity, event.source_ip, [event.source_ip], pattern,
            count, cfg.history_window, items, state, start, ts, ts, extra_event=event,
        )  # fmt: skip
        alert.login_username = event.username
        alert.login_method = event.auth_method or None
        return [alert]

    # ----------------------------------------------------------- helpers

    def _make_alert(
        self,
        kind: AlertType,
        severity: Severity,
        ip: str,
        ips: list[str],
        pattern: str,
        attempts: int,
        window: int,
        items: list[_Item],
        state: _IpState,
        start: float,
        end: float,
        triggered: float,
        extra_event: SshAuthEvent | None = None,
    ) -> SecurityAlert:
        users = sorted({item[2] for item in items})[:_MAX_LISTED]
        ports = sorted({item[3] for item in items if item[3] is not None})[:_MAX_LISTED]
        evidence = [e for e in state.evidence if start <= e.timestamp.timestamp() <= end + 1e-6]
        truncated = sum(e.weight for e in evidence) < attempts
        if extra_event is not None:
            evidence.append(extra_event)
        return SecurityAlert(
            alert_id=_alert_id(kind, ip, start, severity),
            alert_type=kind,
            severity=severity,
            source_ip=ip,
            source_ips=ips,
            pattern=pattern,
            attempts=attempts,
            window_seconds=window,
            start_time=_utc(start),
            end_time=_utc(end),
            triggered_at=_utc(triggered),
            target_usernames=users,
            ports=ports,
            evidence=evidence,
            evidence_truncated=truncated,
            escalation=self._escalation,
            total_failures_from_ip=state.total,
        )

    def _retire(self, ip: str, state: _IpState) -> None:
        row = self._board.get(ip)
        if row is None:
            self._board[ip] = [state.total, state.first_ts, state.last_ts, set(state.users)]
        else:
            row[0] = int(row[0]) + state.total  # type: ignore[arg-type]
            row[1] = min(float(row[1]), state.first_ts)  # type: ignore[arg-type]
            row[2] = max(float(row[2]), state.last_ts)  # type: ignore[arg-type]
            row[3] = set(row[3]) | state.users  # type: ignore[arg-type]
        if len(self._board) > 4 * _BOARD_SIZE:
            keep = sorted(self._board.items(), key=lambda kv: -int(kv[1][0]))[:_BOARD_SIZE]  # type: ignore[arg-type]
            self._board = dict(keep)

    def _prune(self) -> None:
        """Drop idle state (event-time based) so long-running instances stay small."""
        self._since_prune = 0
        cfg = self.config
        now = self._latest
        horizon = max(cfg.window, cfg.history_window if self._track_history else 0)
        for ip in [ip for ip, st in self._ips.items() if st.last_ts < now - horizon]:
            self._retire(ip, self._ips.pop(ip))
        for user in [u for u, st in self._users.items() if st.last_ts < now - cfg.spray_window]:
            del self._users[user]
        longest = max(cfg.cooldown, cfg.history_window if cfg.slow_threshold else 0)
        for key in [k for k, (t, _) in self._cooldowns.items() if now - t >= longest]:
            del self._cooldowns[key]
        for ckey in [k for k, t in self._connections.items() if now - t > _CONNECTION_TTL]:
            del self._connections[ckey]


class BruteForceDetector(Detector):
    """Fang 1.x compatible facade.

    ``process_event`` returns a single alert (the most severe one) or ``None``.
    New code should use :meth:`Detector.process`, which returns every alert.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
        **options: object,
    ) -> None:
        config = DetectorConfig(
            threshold=threshold,
            window=window_seconds,
            cooldown=cooldown_seconds,
            **options,  # type: ignore[arg-type]
        )
        super().__init__(config)

    def process_event(self, event: SshAuthEvent) -> SecurityAlert | None:
        alerts = self.process(event)
        if not alerts:
            return None
        return max(alerts, key=lambda a: a.severity.rank)


__all__ = [
    "BruteForceDetector",
    "DEFAULT_PRIVILEGED_USERS",
    "Detector",
    "DetectorConfig",
    "EventType",
]

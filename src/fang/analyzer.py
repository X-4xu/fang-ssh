"""Glue between sources, parser, detector and handlers."""

from __future__ import annotations

import heapq
import logging
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timezone, tzinfo

from .detector import Detector
from .handlers import ActionHandler
from .models import AnalysisStats, SecurityAlert, SshAuthEvent
from .parser import SshLogParser
from .sources import LineSource, SourceError

log = logging.getLogger("fang.analyzer")


def iter_events(
    source: LineSource,
    stats: AnalysisStats,
    *,
    tz: tzinfo = timezone.utc,
    year: int | None = None,
) -> Iterator[SshAuthEvent]:
    """Parse one source into events. Read errors are recorded, not raised."""
    parser = SshLogParser(
        reference_time=source.reference_time,
        reference_year=year,
        assume_tz=tz,
        source=source.name,
        stats=stats,
    )
    try:
        for number, line in source.lines():
            event = parser.parse_line(line, number)
            if event is not None:
                yield event
    except SourceError as exc:
        stats.source_errors.append(f"{source.name}: {exc}")
    except OSError as exc:
        stats.source_errors.append(f"{source.name}: {exc.strerror or exc}")
    finally:
        warnings = getattr(source, "warnings", None)
        if warnings:
            stats.warnings.extend(w for w in warnings if w not in stats.warnings)


def merge_events(streams: Sequence[Iterator[SshAuthEvent]]) -> Iterator[SshAuthEvent]:
    """Merge several (nearly) chronological streams into one, oldest first."""
    if len(streams) == 1:
        return streams[0]
    return heapq.merge(*streams, key=lambda e: e.timestamp)


class Analyzer:
    """Runs events through the detector and fans alerts out to handlers."""

    def __init__(
        self,
        detector: Detector,
        handlers: Sequence[ActionHandler] = (),
        *,
        max_report_alerts: int = 10_000,
    ) -> None:
        self.detector = detector
        self.handlers = list(handlers)
        self.stats = detector.stats
        self.alerts: list[SecurityAlert] = []
        self.max_report_alerts = max_report_alerts
        self._failed_handlers: set[int] = set()

    def process_event(self, event: SshAuthEvent) -> list[SecurityAlert]:
        alerts = self.detector.process(event)
        for alert in alerts:
            stats = self.stats
            stats.alerts_triggered += 1
            stats.alerts_by_severity[alert.severity.value] = (
                stats.alerts_by_severity.get(alert.severity.value, 0) + 1
            )
            stats.alerts_by_type[alert.alert_type.value] = (
                stats.alerts_by_type.get(alert.alert_type.value, 0) + 1
            )
            if len(self.alerts) < self.max_report_alerts:
                self.alerts.append(alert)
            else:
                stats.report_alerts_dropped += 1
            self._dispatch(alert)
        return alerts

    def _dispatch(self, alert: SecurityAlert) -> None:
        for index, handler in enumerate(self.handlers):
            try:
                handler.handle(alert)
            except Exception as exc:  # a failing sink must not stop detection
                if index not in self._failed_handlers:
                    self._failed_handlers.add(index)
                    message = f"{type(handler).__name__} failed: {exc}"
                    self.stats.warnings.append(message)
                    log.warning(message)

    def run(self, events: Iterable[SshAuthEvent]) -> None:
        self.stats.scan_start = datetime.now(timezone.utc)
        try:
            for event in events:
                self.process_event(event)
        finally:
            self.stats.scan_end = datetime.now(timezone.utc)
            self.detector.finalize()

    def close(self) -> None:
        for handler in self.handlers:
            try:
                handler.close()
            except Exception as exc:  # pragma: no cover - best effort
                log.warning("closing %s failed: %s", type(handler).__name__, exc)

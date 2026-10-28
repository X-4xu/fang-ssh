"""Fang - defensive SSH brute-force and compromise detector."""

from ._version import __version__
from .detector import BruteForceDetector, Detector, DetectorConfig
from .models import (
    AlertSeverity,
    AlertType,
    EventType,
    SecurityAlert,
    Severity,
    SshAuthEvent,
)
from .parser import SshLogParser

__all__ = [
    "AlertSeverity",
    "AlertType",
    "BruteForceDetector",
    "Detector",
    "DetectorConfig",
    "EventType",
    "SecurityAlert",
    "Severity",
    "SshAuthEvent",
    "SshLogParser",
    "__version__",
]

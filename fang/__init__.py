"""
Fang - Fast, secure, and extensible SSH log analyzer and brute-force detection engine.
"""

__version__ = "1.1.0"
__author__ = "Hassan Ali (X-4xu)"

from fang.detector import BruteForceDetector
from fang.models import (
    AlertSeverity,
    EventType,
    SecurityAlert,
    SshAuthEvent,
)
from fang.parser import SshLogParser

__all__ = [
    "AlertSeverity",
    "BruteForceDetector",
    "EventType",
    "SecurityAlert",
    "SshAuthEvent",
    "SshLogParser",
]

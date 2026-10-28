"""TOML configuration file support with strict validation.

Unknown keys are errors (a typo in a security tool must not silently weaken
detection). Command-line flags override file values, which override defaults.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

MAX_CONFIG_BYTES = 1_000_000

_INT_KEYS = (
    "threshold", "window", "cooldown", "slow_threshold", "history_window", "spray_threshold",
    "spray_window", "compromise_failures", "max_tracked_ips", "max_tracked_users", "evidence_limit",
)  # fmt: skip
_BOOL_KEYS = ("count_preauth_disconnects",)
_LIST_KEYS = ("privileged_users",)

_SCHEMA: dict[str, dict[str, type | tuple[type, ...]]] = {
    "detection": {
        **dict.fromkeys(_INT_KEYS, int),
        **dict.fromkeys(_BOOL_KEYS, bool),
        **dict.fromkeys(_LIST_KEYS, list),
    },
    "allowlist": {"networks": list},
    "parsing": {"assume_timezone": str},
    "output": {"blocklist_min_severity": str},
}


class ConfigError(ValueError):
    """The configuration file is invalid."""


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate ``path``; return a flat ``{option: value}`` dict."""
    target = os.fspath(path)
    try:
        info = os.stat(target)
    except OSError as exc:
        raise ConfigError(f"cannot read config {target}: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"{target}: not a regular file")
    if info.st_size > MAX_CONFIG_BYTES:
        raise ConfigError(f"{target}: file too large")
    try:
        with open(target, "rb") as handle:
            raw = tomllib.load(handle)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{target}: invalid TOML: {exc}") from exc

    flat: dict[str, Any] = {}
    for section, body in raw.items():
        schema = _SCHEMA.get(section)
        if schema is None:
            raise ConfigError(f"{target}: unknown section [{section}]")
        if not isinstance(body, dict):
            raise ConfigError(f"{target}: [{section}] must be a table")
        for key, value in body.items():
            expected = schema.get(key)
            if expected is None:
                raise ConfigError(f"{target}: unknown key '{key}' in [{section}]")
            if expected is int and isinstance(value, bool):
                raise ConfigError(f"{target}: [{section}] {key} must be an integer")
            if not isinstance(value, expected):
                raise ConfigError(f"{target}: [{section}] {key} must be of type {expected.__name__}")  # type: ignore[union-attr]
            if isinstance(value, list) and not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{target}: [{section}] {key} must be a list of strings")
            flat["allow" if (section, key) == ("allowlist", "networks") else key] = value
    return flat

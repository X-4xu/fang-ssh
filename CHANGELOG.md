# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-10-28

### Added
- **Distributed Attack & Password Spray Detection**: Detects multi-IP coordinated attacks targeting a single username across distinct IP addresses (`--distributed-threshold`).
- **Deterministic Alert IDs**: Generates stable SHA-256 derived incident IDs (`ALERT-FANG-<HASH>`) for consistent tracking across audit logs and SIEM correlations.
- **SIEM & ECS Alignment**: Exported JSON reports now include standard Elastic Common Schema (`siem` taxonomy) fields, epoch timestamps, and explicit severity reasoning chains.
- **Bounded Evidence Windows**: Bounded raw evidence lines per incident (`--max-evidence-lines`, default: 50) to prevent memory and JSON report bloat during massive volumetric attacks.
- **Enhanced Untrusted Input Sanitization**: Strips ANSI escape sequences and non-printable control characters from raw log lines and target usernames.
- **Comprehensive Test Suite & Quality Gates**: Expanded test suite to 49 tests (accuracy, integration, and security edge cases) with 85% coverage, automated Ruff linting, and pip-audit vulnerability checks.

## [1.1.0] - 2026-10-28

### Added
- **Standard Input & Journald Ingestion**: Support reading auth logs from stdin (`-l -` or piped) and directly from systemd-journald (`--journalctl` / `--journald` using `journalctl -u ssh -u sshd -o short-iso`).
- **Live Log Tailing (`--follow` / `-f`)**: Real-time auth log monitoring with automatic detection of log rotations and file truncations.
- **Possible Compromise Detection**: Correlates successful authentications (`Accepted password` / `Accepted publickey`) following repeated failures from the same source IP, raising a CRITICAL severity incident.
- **Configurable Privilege Escalation (`--no-root-escalation`)**: Added option to disable automatic severity inflation for attempts targeting privileged accounts like `root` or `admin`.

## [1.0.0] - 2026-09-19

### Added
- Initial release of `Fang` (SSH Log Analyzer & Brute-Force Detection Engine).
- Support for parsing standard Syslog (`Oct 12 14:32:10`) and modern RFC 3339 / ISO 8601 (`2026-09-19T08:12:34+00:00`) auth logs.
- Automatic decompression and reading of rotated `.gz` logs.
- Sliding time-window detection engine for brute-force attacks (e.g. 5+ failed attempts per minute).
- Dynamic severity scoring (LOW, MEDIUM, HIGH, CRITICAL) based on frequency and targeted usernames (`root`, `admin`).
- Alert deduplication and cooldown mechanism to avoid notification flooding.
- Structured JSON report export with full evidence chains, timestamps, and target metadata.
- Beautiful CLI interface using `rich` tables and summary metrics.
- Extensible `ActionHandler` interface and `NetAccessControllerHook` for future IP blocking automation.
- Comprehensive test suite covering unit, integration, and edge-case scenarios.

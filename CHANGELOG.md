# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-28

### Added
- **Possible-compromise detection**: a successful login from an IP that had recent failures
  (`CRITICAL` for password logins, `HIGH` for public-key logins).
- **Low-and-slow brute-force rule** for attackers that stay under the per-minute threshold.
- **Distributed attack / password-spraying rule**: many IPs failing against the same account.
- **Live monitoring** (`--follow`) that survives log rotation and truncation, and
  **systemd-journald input** (`--journald`, `--journal-since`) for hosts without `auth.log`.
- Stdin input (`-l -`), several `--log-file` options merged chronologically, and automatic
  detection of gzip / bzip2 / xz by content rather than file name.
- Parsing of OpenSSH 9.8+ `sshd-session` / `sshd-auth`, `Invalid user`, `Connection closed by ...
  [preauth]`, `maximum authentication attempts exceeded`, rsyslog "message repeated N times",
  journald JSON, and `journalctl -o short-iso` timestamps.
- TOML configuration file (`--config`) with strict validation, `--allow` for trusted IPs/CIDRs,
  `--assume-tz`, `--year`, `--max-bytes`.
- Alert escalation: a higher severity is reported immediately, even inside the cooldown.
- `--jsonl` alert log and `--blocklist-file` (advisory plain-text blocklist; Fang never enforces it).
- Deterministic alert IDs (the same log always yields the same IDs).
- Hardened systemd unit and an nftables example in `contrib/`.
- Test suite (249 tests, 94% coverage) run on Python 3.10-3.13; ruff and strict mypy in CI.

### Changed
- **Distribution name is now `fang-ssh`** (the command and the import name stay `fang`);
  `fang` is already taken on PyPI.
- **No third-party runtime dependencies** (`rich` removed; `tomli` only on Python 3.10).
- **JSON report schema 2.0.0**: `summary.log_file_path` became `summary.log_sources` (a list),
  `detected_at` became `triggered_at` (event time, not wall clock), alerts gained `alert_type`,
  `source_ips`, `escalation`, `evidence_truncated`; evidence is capped per alert.
- Usage errors exit with **64** instead of argparse's 2, so they cannot be confused with
  "alerts found" (2).
- `EventType.ACCEPTED_*` is split by method; `AlertSeverity` remains as an alias of `Severity`.
- PAM `authentication failure` lines are still parsed (`AUTH_FAILURE`) but never counted toward
  thresholds, because every attempt already has its own `Failed ...` line.
- The `LOW` severity was removed (no rule ever produced it).
- Severity thresholds now scale with `--threshold` instead of being fixed numbers.

### Fixed
- Teardown lines (`Connection closed ... [preauth]`, max-attempts) no longer double count a
  connection that already logged `Failed ...` lines.
- Opening a FIFO as an output or blocklist path could hang the process forever.
- `--threshold` above the slow-rule threshold no longer mislabels fast bursts as "low-and-slow"
  (a clear error explains the fix instead).

### Security
- The source address is always taken from the **end** of the line, so an account name like
  `x from 6.6.6.6 port 1` cannot make Fang accuse (or block) someone else.
- All text from logs is stripped of control, escape and bidirectional characters before it is
  printed or stored; console output cannot be spoofed.
- Report, JSONL and blocklist files are created with mode 0600; reports and blocklists are
  written atomically and a symlink at the target is replaced, never followed; JSONL uses
  `O_NOFOLLOW`.
- Memory is bounded: capped LRU state for IPs and accounts, capped windows and evidence,
  per-line size limit, optional decompressed-size limit.
- Loopback, link-local, multicast, reserved and allow-listed addresses can never enter the
  blocklist.

## [1.0.0] - 2026-09-19
- Initial release: SSH log parser, sliding-window brute-force detector, severity scoring,
  cooldown, JSON report export and a dry-run `net-access-controller` hook.

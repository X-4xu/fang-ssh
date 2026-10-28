# Show HN Submission Draft

## Post Details

- **Title**: Show HN: Fang – SSH brute-force analyzer with JSON evidence reports
- **Link**: https://github.com/X-4xu/fang-ssh
- **Submission URL**: https://news.ycombinator.com/submit

---

## First Comment (Post immediately after submission)

Hi HN,

I built **Fang** (https://github.com/X-4xu/fang-ssh) because I needed a lightweight, read-only SSH log analyzer that could reliably detect burst attacks and export forensic-grade evidence without the operational risks of active firewall-modifying daemons.

### Why not Fail2ban or SSHGuard?

Tools like Fail2ban and SSHGuard are standard for active prevention on single servers, but in managed environments and audit pipelines, active blocking introduces risks:
1. **Accidental admin lockout**: Misconfigured regexes or shared egress NATs can lock legitimate operators out.
2. **Lack of structured forensic output**: Most ban daemons record that an IP was banned, but don't export structured JSON evidence chains (with exact line numbers, raw log excerpts, target users, and timing deltas) suitable for audit or SIEM ingestion.
3. **Fixed findtime buckets**: Fixed-window counting can miss burst attacks that span across the boundary of two adjacent minute buckets.

### What Fang Does:

- **Rolling Sliding-Window**: Evaluates failed attempts across a rolling in-memory window with sub-second timestamp eviction, capturing true bursts regardless of wall-clock boundaries.
- **Multi-Source Ingestion**:
  - Traditional BSD syslog (`/var/log/auth.log`, `/var/log/secure`) with automatic year-rollover inference.
  - RFC 3339 / ISO 8601 timestamps.
  - Compressed `.gz` archives (reads rotated logs without manual decompression).
  - Direct systemd-journald streaming (`--journalctl`).
  - Standard input pipelines (`journalctl -u ssh -o short-iso | fang -l -`).
- **Live Monitoring**: `--follow` (`-f`) mode tails logs in real-time, handling file truncations and logrotate inode replacements.
- **Compromise Detection**: Correlates successful logins (`Accepted password` or `Accepted publickey`) following repeated failures from the same source IP, raising a CRITICAL incident.
- **Forensic Evidence Chains**: Exports structured JSON containing the full sequence of raw log lines and metadata for every detected incident.
- **CI/CD Ready**: Supports `--exit-code-on-alert` (returns exit code 2 if an alert triggers) for automated infrastructure test pipelines.

### What Fang Does NOT Do:

- **No Firewall Modification**: Fang is strictly read-only. It never modifies `iptables`, `nftables`, or routing tables. It cannot lock you out.
- **No Network Egress**: Zero external network requests or phone-home telemetry.
- **No PyPI Presence**: Fang is distributed exclusively via GitHub (`pipx install git+https://github.com/X-4xu/fang-ssh.git` or GitHub Release wheels).

The codebase is written in Python (3.10+) with only one external runtime dependency (`rich` for terminal UI), and comes with a 100% passing test suite.

I’d love to hear your thoughts, feedback, and edge-case log formats you’ve encountered!

# Fang: Defensive SSH Brute-Force Log Analyzer

[![CI](https://github.com/X-4xu/fang-ssh/actions/workflows/ci.yml/badge.svg)](https://github.com/X-4xu/fang-ssh/actions)
[![GitHub Release](https://img.shields.io/github/v/release/X-4xu/fang-ssh?color=blue)](https://github.com/X-4xu/fang-ssh/releases)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Fang** is a lightweight, defensive SSH brute-force log analyzer for Linux systems (`/var/log/auth.log` and `/var/log/secure`).  
It uses an in-memory sliding time window to identify burst attacks, scores incident severity, and exports structured JSON reports with full evidence chains for audit and SIEM pipelines.

---

## Comparison: Fang vs. Fail2ban vs. SSHGuard

Fang is designed specifically for **passive analysis, log auditing, and structured forensic reporting**. It operates strictly in user space and does **not** alter your firewall.

| Dimension | Fang (`fang-ssh`) | Fail2ban | SSHGuard |
|---|---|---|---|
| **Primary Role** | Read-only analysis, detection & forensic reporting | Active intrusion prevention & firewall banning | Lightweight host daemon banning |
| **Firewall Modification** | **None** (Read-only; eliminates lockout risks of automated ban rules) | Modifies `iptables` / `nftables` | Modifies `iptables` / `pf` / `ipfw` |
| **Output Formats** | Structured JSON reports & terminal summaries | Plaintext logs / ban commands | Plaintext syslog entries |
| **Forensic Evidence** | Full raw log line chains with line numbers | Timestamp and IP only | Blocked IP and score only |
| **Detection Engine** | Rolling sliding-window with timestamp eviction ($O(1)$) | Fixed `findtime` bucket counters | Attack score accumulation |
| **Dependencies** | Python 3.10+ & `rich` (CLI formatting) | Python & system utilities | Pure C (compiled binary) |
| **Operational Risk** | Non-intrusive (bounded memory; does not alter host networking) | Risk of automated self-lockout or misconfigured ban | Risk of automated self-lockout or misconfigured ban |

### Threat Model & Safety Considerations

Being read-only eliminates host networking disruption, but processing log files requires defensive parsing of untrusted inputs:
- **ReDoS Resistance**: Regular expressions employ strictly bounded matching patterns to mitigate catastrophic backtracking on crafted inputs.
- **Memory Bounds**: Sliding windows evict timestamps outside the active window using `collections.deque`, capping resource consumption during volumetric floods.
- **Input Sanitization**: Malformed IP addresses, null bytes, and non-SSH syslog lines are discarded without terminating analyzer execution.

---

## Terminal Recording

> [!NOTE]
> **Visual Mockup Notice**: The terminal preview below illustrates the CLI interface, alert coloring, and report formatting. It is a visual representation and does not constitute an independently audited performance benchmark. For reproducible benchmarks and synthetic test runs on your specific machine, see the [Reproducible Benchmarking](#reproducible-benchmarking) section below.

```
+----------------------------------------------------------------------------------------------------+
|                                    Fang Terminal Preview                                           |
|                                                                                                    |
|  $ fang -l /var/log/auth.log -t 5 -w 60 -o report.json                                             |
|                                                                                                    |
|  +----------------- FANG ALERT: SSH BRUTE-FORCE DETECTED ------------------+                       |
|  | Alert ID: ALERT-FANG-3B1B67A5                                           |                       |
|  | Source IP: 203.0.113.42                                                 |                       |
|  | Severity: HIGH                                                          |                       |
|  | Failed Attempts: 5 (in 60s window)                                      |                       |
|  | Target Users: admin, root                                               |                       |
|  | Pattern: SSH Brute-Force: 5 failed attempts in 12.0s (Threshold: 5/60s) |                       |
|  +-------------------------------------------------------------------------+                       |
|                                                                                                    |
|  Summary: Scanned 1,420 lines | 124 failed attempts | 2 alerts | Elapsed: 0.045s                   |
+----------------------------------------------------------------------------------------------------+
```

> **To record a live session**: Use [vhs](https://github.com/charmbracelet/vhs) or [asciinema](https://asciinema.org/):
> ```bash
> asciinema rec demo.cast -c "fang -l examples/sample_auth.log -t 5 -w 60"
> ```

---

## Installation

> [!IMPORTANT]
> **Notice**: Fang is **NOT** published on PyPI. Do not run `pip install fang-ssh`: that name is not controlled by this project. Install directly from this GitHub repository using one of the methods below.

### 1. Recommended: Using `pipx` (Isolated CLI application)

```bash
pipx install git+https://github.com/X-4xu/fang-ssh.git
```

### 2. Pinned Release Version

```bash
pipx install git+https://github.com/X-4xu/fang-ssh.git@v1.1.0
```

### 3. One-Off Execution with `uvx` (Fast, zero-install)

```bash
uvx --from git+https://github.com/X-4xu/fang-ssh fang --help
```

### 4. Direct Wheel Installation from GitHub Releases

```bash
pip install https://github.com/X-4xu/fang-ssh/releases/download/v1.1.0/fang_ssh-1.1.0-py3-none-any.whl
```

### 5. Docker Container (Self-Contained)

```bash
docker run --rm -v /var/log:/var/log:ro ghcr.io/x-4xu/fang-ssh:latest -l /var/log/auth.log
```

### 6. From Source (Development)

```bash
git clone https://github.com/X-4xu/fang-ssh.git
cd fang-ssh
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Architecture Overview

```
                      +-----------------------------+
                      |   /var/log/auth.log         |
                      |   /var/log/secure           |
                      |   (*.log or rotated *.gz)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       SshLogParser          |
                      |  - RFC 3339 & BSD Syslog    |
                      |  - ipaddress validation     |
                      |  - Control char stripping   |
                      |  - Memory-safe streaming    |
                      +--------------+--------------+
                                     |
                                     v  (SshAuthEvent stream)
                      +-----------------------------+
                      |     BruteForceDetector      |
                      |  - In-memory sliding window |
                      |  - Eviction by timestamp    |
                      |  - Threshold trigger        |
                      |  - Alert cooldown & dedup   |
                      |  - Dynamic severity rating  |
                      +--------------+--------------+
                                     |
                                     v  (SecurityAlert stream)
                      +-----------------------------+
                      |       Action Handlers       |
                      +--------------+--------------+
                                     |
        +----------------------------+----------------------------+
        |                                                         |
        v                                                         v
+-------------------------------+                         +-------------------------------+
|      ConsoleAlertHandler      |                         |       ReportExporter          |
|  - Real-time colored panels   |                         |  - Structured JSON report     |
|  - Incident summary tables    |                         |  - Evidence event chain       |
+-------------------------------+                         +-------------------------------+
```

---

## Features

- **Multi-Format Parsing**:
  - **Traditional BSD Syslog**: `Sep 19 14:32:10 host sshd[123]: Failed password for root from ...` (with automatic year rollover inference).
  - **RFC 3339 / ISO 8601**: `2026-09-19T08:12:34.567890+00:00 host sshd[123]: ...`
  - **Rotated Compressed Logs**: Reads `.gz` archives seamlessly without manual extraction.
- **Sliding-Window Detection Engine**:
  - Employs a rolling time window (e.g. 5 failed attempts in 60 seconds) rather than static minute-aligned buckets.
  - Automatic time-based eviction prevents false positives on slow typos.
- **Dynamic Severity Scoring**:
  - `CRITICAL`: $\ge 20$ attempts or $\ge 10$ attempts targeting privileged accounts (`root`, `admin`, `wheel`).
  - `HIGH`: $\ge 10$ attempts or any targeting of privileged accounts.
  - `MEDIUM`: Base threshold met ($\ge 5$ attempts within window).
- **Anti-Spam Alert Cooldown**:
  - Suppresses duplicate alert spam for ongoing attacks from the same IP within a configurable cooldown window.
- **Traceable Forensic Evidence**:
  - Every alert contains the full raw log lines, original timestamps, targeted usernames, and port numbers.
- **Defensive Design**:
  - Read-only: never modifies network tables or system configurations.
  - Usernames and log lines are sanitized of non-printable ASCII control characters.
  - IP candidates are validated with Python's standard `ipaddress` library before processing.

---

## CLI Usage

### Basic Scan

```bash
fang -l /var/log/auth.log
```

### Scan RedHat / CentOS / Rocky Linux Log

```bash
fang -l /var/log/secure
```

### Scan Rotated Gzip Archive

```bash
fang -l /var/log/auth.log.1.gz
```

### Custom Threshold and Window

Detect 10 or more failed attempts within a 2-minute (120 seconds) window, exporting to JSON:

```bash
fang -l /var/log/auth.log -t 10 -w 120 -o report.json
```

### Live Log Tailing (`--follow`)

Continuously monitor authentication logs in real-time with automatic rotation handling:

```bash
fang -f -l /var/log/auth.log
```

### Systemd Journald Ingestion

Directly ingest SSH authentication events from `systemd-journald`:

```bash
fang --journalctl
```

### Pipe via Stdin

Stream logs directly into Fang from pipelines:

```bash
journalctl -u ssh -o short-iso | fang -l -
```

### Disable Root Severity Inflation

By default, targeting `root` or `admin` escalates alert severity. To score strictly by attempt volume:

```bash
fang -l /var/log/auth.log --no-root-escalation
```

### CI / Automation Mode

Exit with status code `2` if an alert is detected (useful for automated security audit pipelines):

```bash
fang -l /var/log/auth.log --exit-code-on-alert -q -o report.json
```

---

## Command-Line Options

| Option | Flag | Default | Description |
|---|---|---|---|
| `--log-file` | `-l` | `/var/log/auth.log` | Path to log file, or `-` for stdin (`/var/log/auth.log`, `/var/log/secure`, plaintext or `.gz`). |
| `--follow` | `-f` | `False` | Continuously tail the log file in real-time. |
| `--journalctl` | `--journald` | `False` | Ingest logs directly from `systemd-journald` (`journalctl -u ssh -u sshd -o short-iso`). |
| `--threshold` | `-t` | `5` | Minimum failed attempts to trigger an alert. |
| `--window` | `-w` | `60` | Duration of the sliding time window in seconds. |
| `--cooldown` | `-c` | `300` | Cooldown period in seconds per source IP to prevent alert spam. |
| `--output` | `-o` | `None` | Path to save the structured JSON report. |
| `--no-root-escalation` | | `False` | Disable automatic severity inflation to HIGH for root/admin targets. |
| `--quiet` | `-q` | `False` | Suppress alert panels; show only the summary table. |
| `--verbose` | `-v` | `False` | Enable verbose debug logging. |
| `--exit-code-on-alert` | | `False` | Exit with return code `2` if an alert is detected. |
| `--version` | | | Display version information. |

---

## Structured JSON Report Schema

When running with `-o <path>`, Fang produces structured JSON reports:

```json
{
  "schema_version": "1.0.0",
  "analyzer_version": "1.0.0",
  "generated_at": "2026-09-19T18:57:53.390261+00:00",
  "summary": {
    "log_file_path": "/var/log/auth.log",
    "total_lines_read": 1420,
    "total_events_parsed": 840,
    "failed_attempts_count": 124,
    "unique_source_ips": 12,
    "alerts_triggered": 1,
    "scan_start_time": "2026-09-19T18:57:53.379829+00:00",
    "scan_end_time": "2026-09-19T18:57:53.390230+00:00",
    "scan_duration_seconds": 0.045
  },
  "alerts_count": 1,
  "alerts": [
    {
      "alert_id": "ALERT-FANG-3B1B67A5",
      "source_ip": "192.168.1.100",
      "severity": "high",
      "pattern": "SSH Brute-Force: 5 failed attempts in 12.0s (Threshold: 5/60s)",
      "failed_attempts_count": 5,
      "window_seconds": 60,
      "time_range": {
        "start": "2026-09-19T10:00:10+00:00",
        "end": "2026-09-19T10:00:22+00:00",
        "duration_seconds": 12.0
      },
      "target_usernames": ["admin", "root", "test"],
      "ports": [40001, 40002, 40003, 40004],
      "detected_at": "2026-09-19T18:57:53.384141+00:00",
      "evidence": [
        {
          "timestamp": "2026-09-19T10:00:10+00:00",
          "event_type": "FAILED_PASSWORD",
          "source_ip": "192.168.1.100",
          "port": 40001,
          "username": "admin",
          "is_invalid_user": true,
          "line_number": 2,
          "raw_line": "Sep 19 10:00:10 web-server sshd[2001]: Failed password for invalid user admin from 192.168.1.100 port 40001 ssh2"
        }
      ]
    }
  ]
}
```

---

## Reproducible Benchmarking & Synthetic Logs

Fang includes a standalone synthetic log generator and benchmark tool (`scripts/benchmark_synthetic.py`) to measure ingestion and detection throughput independently on your own hardware without relying on pre-packaged claims.

### Run the Benchmark

```bash
# Generate 25,000 synthetic log lines and measure throughput (lines/second)
python scripts/benchmark_synthetic.py --lines 25000

# Generate and export a synthetic log file for manual inspection
python scripts/benchmark_synthetic.py --lines 10000 --output examples/synthetic_sample.log

# Run Fang directly against the synthetic dataset
fang -l examples/synthetic_sample.log -t 5 -w 60 --json-out report.json
```

### Reference Benchmark Output

On a reference workstation (Windows 11, Intel/AMD x86_64, Python 3.13):
- **Throughput**: ~40,000 – 45,000 lines/second (in-memory streaming).
- **Detection**: Accurately isolates brute-force bursts and identifies targeted users across interleaved benign and malicious streams.
*(Note: Real-world disk I/O, gzip decompression, and Python interpreter versions will affect throughput).*

---

## Testing & CI Verification

Fang maintains an automated test suite covering classic syslog, RFC 3339, and journald log formats, live `--follow` file truncation and rotation handling, compromise detection, and synthetic benchmarking.

Every commit and pull request is automatically verified across a matrix of **Python 3.10, 3.11, 3.12, and 3.13** on Ubuntu runners via GitHub Actions.

```bash
# Run full test suite
pytest -v

# Run test suite with statement coverage report
pytest --cov=fang --cov-report=term-missing
```

---

## License

This project is licensed under the [MIT License](LICENSE).

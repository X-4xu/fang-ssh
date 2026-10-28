# Detecting SSH Brute-Force Attacks from Auth Logs with a Sliding Window

Every Linux server connected to the public internet experiences a relentless hum of background noise: automated bots and credential stuffers cycling through dictionary lists of common passwords against port 22.

While tools like Fail2ban or SSHGuard have long been the default line of defense, they primarily focus on **active prevention**—injecting ephemeral rules into `iptables` or `nftables` to drop attacking packets.

However, in security operations, threat hunting, and compliance auditing, active prevention alone is often insufficient and sometimes operationally risky. A misconfigured regex or an office-wide NAT address can trigger an accidental administrator lockout. More critically, traditional banning tools often discard the detailed forensic evidence chains—the exact timestamps, target usernames, and raw log lines—that incident response teams need to assess the scope of an attack.

In this article, we’ll explore how to build a **safe, passive SSH brute-force detection engine** using an in-memory sliding time window in Python, and walk through the engineering decisions behind [Fang](https://github.com/X-4xu/fang-ssh), an open-source defensive log analyzer.

---

## The Flaw of Fixed-Time Windows

The simplest way to count failed logins is to aggregate events into fixed time buckets—for instance, counting how many failures occur within each calendar minute (e.g., `14:00:00` to `14:01:00`).

While straightforward to implement, fixed-window counters suffer from a well-known vulnerability: **window straddling**.

Imagine a detection policy with a threshold of 5 failures per minute:
- An attacker sends 4 failed attempts at `14:00:58`.
- The attacker sends another 4 failed attempts at `14:01:02`.

In total, the attacker fired **8 attempts in just 4 seconds**. Yet a fixed-window counter registers 4 failures in the first bucket and 4 failures in the second. Neither bucket meets the threshold of 5, and the attack goes entirely undetected.

---

## Designing an In-Memory Sliding Window with $O(1)$ Eviction

To solve window straddling, we need a **rolling sliding window**. For any incoming event at timestamp $t_{\text{current}}$, we look back at a continuous interval of $[t_{\text{current}} - \Delta t, t_{\text{current}}]$.

Using a double-ended queue (`collections.deque`) in Python allows us to maintain timestamps sorted in chronological order with $O(1)$ append and pop operations:

```python
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque

class SlidingWindowDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Map source IP to a queue of authentication events
        self._ip_windows: dict[str, Deque[SshAuthEvent]] = defaultdict(deque)

    def process_event(self, event: SshAuthEvent) -> SecurityAlert | None:
        if not event.event_type.is_failure:
            return None

        ip = event.source_ip
        window = self._ip_windows[ip]

        # Evict all events older than the sliding window horizon
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while window and window[0].timestamp < cutoff:
            window.popleft()

        # Append the new failure event
        window.append(event)

        # Trigger an alert if the threshold is reached
        if len(window) >= self.threshold:
            return self._build_alert(ip, list(window))

        return None
```

With this pattern, the 4-second burst mentioned earlier is immediately detected because both clusters fall well within the 60-second delta of the latest event.

---

## Navigating the Chaos of Linux Authentication Logs

Real-world Linux authentication logs are notoriously heterogeneous. A resilient parser must handle at least three distinct formats:

1. **Traditional BSD Syslog**:
   ```
   Sep 19 14:32:10 web01 sshd[18492]: Failed password for root from 192.168.1.100 port 40001 ssh2
   ```
   *Challenge*: Syslog timestamps lack a year field. If you analyze an archive in January that covers December logs, a naive parser will assign the current year, corrupting time calculations. The parser must detect month-year boundary rollovers.

2. **Modern RFC 3339 / ISO 8601**:
   ```
   2026-09-19T08:12:34.567890+00:00 bastion sshd[3001]: Failed password for invalid user admin from 203.0.113.42 port 51000 ssh2
   ```
   *Benefit*: Explicit year and timezone offsets eliminate ambiguity.

3. **Systemd Journald (`short-iso`)**:
   ```
   2026-10-28T12:00:01+0000 host sshd[1001]: Failed password for root from 198.51.100.22 port 22 ssh2
   ```

### Streaming Compressed Archives

Log files on busy servers are frequently rotated by `logrotate` and compressed with `gzip`. A proper analysis tool shouldn't require manual decompression to disk. We can stream lines transparently:

```python
import gzip
from pathlib import Path

def stream_log(file_path: Path):
    if file_path.suffix == ".gz":
        with gzip.open(file_path, mode="rt", encoding="utf-8", errors="replace") as f:
            yield from f
    else:
        with open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
            yield from f
```

---

## Critical Detection: When the Attacker Actually Succeeds

Most brute-force tools treat failures as the end of the story. But in incident response, the most alarming scenario is a **failure burst followed by an accepted authentication**.

If an IP address fails 15 times within 40 seconds and then suddenly issues an `Accepted password` or `Accepted publickey`, that indicates a high-probability account compromise or successful credential stuffing attempt.

By tracking the failure queue across all event types, we can detect this correlation in real-time:

```python
if event.event_type.is_accepted:
    # If the same IP failed multiple times right before succeeding:
    if len(window) >= min_failures_for_compromise:
        return self._create_compromise_alert(
            source_ip=ip,
            failed_events=list(window),
            accepted_event=event,
            severity=AlertSeverity.CRITICAL,
        )
    window.clear()
    return None
```

---

## Forensic-Grade Evidence Output

When Fang generates a JSON report (`-o report.json`), it doesn't just record a counter. It preserves the complete forensic chain:

```json
{
  "alert_id": "ALERT-FANG-3B1B67A5",
  "source_ip": "192.168.1.100",
  "severity": "high",
  "pattern": "SSH Brute-Force: 5 failed attempts in 12.0s (Threshold: 5/60s)",
  "failed_attempts_count": 5,
  "window_seconds": 60,
  "start_time": "2026-09-19T10:00:10+00:00",
  "end_time": "2026-09-19T10:00:22+00:00",
  "target_usernames": ["admin", "test", "guest", "root"],
  "evidence": [
    {
      "timestamp": "2026-09-19T10:00:10+00:00",
      "event_type": "FAILED_PASSWORD",
      "username": "admin",
      "port": 40001,
      "line_number": 1,
      "raw_line": "Sep 19 10:00:10 srv sshd[100]: Failed password for invalid user admin from 192.168.1.100 port 40001 ssh2"
    }
  ]
}
```

This output can be directly ingested into Elasticsearch, Splunk, or SIEM pipelines without additional formatting.

---

## Honest Limitations: When Is Passive Analysis Not Enough?

No defensive tool is a silver bullet. Understanding what a passive tool does *not* do is just as important as knowing what it can do:

1. **Not an Intrusion Prevention System (IPS)**: Fang is read-only. It will analyze, alert, and report, but it will **not** block IP addresses on your firewall. If you need immediate automatic packet dropping on standalone edge boxes, Fail2ban remains appropriate.
2. **Slow-and-Low Dictionary Attacks**: An attacker distributing attempts over days (e.g. 1 attempt every 6 hours) will not trigger a short-window burst detector. Detecting low-and-slow campaigns requires long-term database correlation across weeks of logs.
3. **NAT and Egress Collisions**: In enterprise environments where thousands of legitimate users egress through a common proxy or NAT IP, burst thresholds must be adjusted or configured with whitelists to avoid noise.

---

## Getting Started with Fang

Fang is open-source (MIT licensed) and distributed directly via GitHub:

```bash
# Run directly without installation via uv:
uvx --from git+https://github.com/X-4xu/fang-ssh fang -l /var/log/auth.log

# Or install as an isolated CLI app using pipx:
pipx install git+https://github.com/X-4xu/fang-ssh.git

# Live real-time tailing:
fang -f -l /var/log/auth.log

# Stream directly from systemd-journald:
fang --journalctl
```

Check out the source code, open starter issues, and contribution guide on GitHub:  
**https://github.com/X-4xu/fang-ssh**

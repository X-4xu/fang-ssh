# Reddit: r/netsec Submission Draft

## Subreddit Information & Rules Assessment

- **Subreddit**: [r/netsec](https://www.reddit.com/r/netsec/) (~600k members)
- **Rules on Self-Promotion**:
  - Extremely strict: Submissions MUST be technical, novel, and provide full source code or detailed technical documentation.
  - "Low-effort" scripts, marketing releases, or basic scanners get removed immediately.
  - Must emphasize defensive engineering, forensic evidence reconstruction, sliding-window threat detection, and threat modeling.

---

## Post Details

- **Title**: Fang: Passive SSH brute-force analysis with sliding-window correlation and JSON evidence chains

---

## Post Body

### Overview

When conducting threat hunting or post-incident analysis on Linux bastion hosts and edge servers, forensic analysts frequently need to distinguish between background internet noise (distributed low-and-slow probing) and targeted credential stuffing or brute-force bursts.

Active prevention tools like Fail2ban typically store ephemeral state and execute firewall drop rules, but rarely preserve the end-to-end evidence chains required for SOC triaging or compliance auditing.

**Fang** ([github.com/X-4xu/fang-ssh](https://github.com/X-4xu/fang-ssh)) is an open-source defensive security tool designed for passive log analysis, burst detection, and forensic evidence packaging.

### Technical Architecture & Detection Heuristics

1. **Sliding-Window Timestamp Eviction ($O(1)$)**:
   Fixed-time window aggregations (e.g. counting events between 12:00:00 and 12:01:00) suffer from window-straddling bypasses. Fang maintains a per-IP double-ended queue where each candidate event $e_i$ is evaluated against cutoff $T_i - \Delta t$:
   $$\forall e \in W_{\text{ip}}, \quad t(e) \ge t(e_{\text{current}}) - \Delta t$$
   Old events are popped immediately prior to threshold evaluation.

2. **Account Compromise Correlation**:
   A common indicator of successful credential stuffing is an authentication burst culminating in a successful session. Fang evaluates incoming `Accepted password` and `Accepted publickey` events against the preceding window of authentication failures for that source IP:
   $$\text{CompromiseAlert} \iff \text{EventType}(e) \in \{\text{ACCEPTED}\} \land |W_{\text{ip}}| \ge \text{MinFailures}$$
   When triggered, Fang immediately elevates the incident to `CRITICAL` severity and captures the complete sequence of failed attempts alongside the successful credential authentication in the incident evidence chain.

3. **Input Sanitization & Attack Surface Hardening**:
   Because log fields (usernames, remote hostnames) are user-controlled data that can contain adversarial payloads:
   - Control characters (`[\x00-\x1f\x7f]`) and ANSI terminal escape sequences are stripped prior to parsing.
   - Max line length is enforced (4,096 bytes) to eliminate potential algorithmic complexity attacks (ReDoS).
   - Source IP candidates are strictly validated through Python's `ipaddress.ip_address` engine before being accepted into tracking state.
   - The analysis engine runs completely in read-only mode, requires no network egress, and performs zero active packet or iptables manipulation.

4. **Forensic Evidence Output**:
   Every alert emitted contains:
   - Unique Incident ID (`ALERT-FANG-<UUID>`)
   - Severity classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
   - Target accounts targeted (with duplicate deduplication)
   - Exact start and end timestamps (to millisecond precision where supported by RFC 3339 / journald)
   - Full, unedited raw log lines with exact file line numbers for audit defensibility.

### Source Code & Installation

Fang is released under the MIT license. Distribution is GitHub-only (no PyPI package):

- Repository: https://github.com/X-4xu/fang-ssh
- Direct install via pipx: `pipx install git+https://github.com/X-4xu/fang-ssh.git`
- One-off run: `uvx --from git+https://github.com/X-4xu/fang-ssh fang -l /var/log/auth.log`

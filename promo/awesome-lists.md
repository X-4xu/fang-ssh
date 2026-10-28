# Curated Awesome Lists PR Proposals

> [!IMPORTANT]
> **Policy**: Do NOT open these Pull Requests until manually reviewed and approved. Each entry has been formatted to comply with the respective list's `CONTRIBUTING.md` guidelines.

---

## 1. `meirwah/awesome-incident-response`

- **Repository**: [https://github.com/meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)
- **Target Section**: `Log Analysis Tools`
- **Maintenance Status**: Actively maintained (regularly merges community tools).
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Lightweight Python SSH brute-force log analyzer with sliding-window detection and structured JSON evidence reporting.
  ```
- **PR Title**: `Add Fang to Log Analysis Tools`
- **PR Description Template**:
  ```markdown
  ### Description
  Adds [Fang](https://github.com/X-4xu/fang-ssh) to the Log Analysis Tools section.

  Fang is an open-source, read-only defensive log analyzer for Linux auth logs (`/var/log/auth.log`, `/var/log/secure`, and `systemd-journald`). It uses an in-memory sliding time window with timestamp eviction to detect brute-force bursts, correlates post-failure successful logins (possible compromise), and exports complete forensic evidence chains as structured JSON.
  ```

---

## 2. `kahun/awesome-sysadmin`

- **Repository**: [https://github.com/kahun/awesome-sysadmin](https://github.com/kahun/awesome-sysadmin)
- **Target Section**: `Security` -> `Log Analysis / Auditing`
- **Maintenance Status**: Active community list.
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Passive SSH brute-force analyzer for Linux auth logs with sliding-window detection and JSON reports.
  ```
- **PR Title**: `Add Fang to Security / Log Analysis`
- **PR Description Template**:
  ```markdown
  ### What does this PR do?
  Adds Fang (https://github.com/X-4xu/fang-ssh) to the Security section.

  ### Why is it useful for sysadmins?
  Unlike active ban daemons (fail2ban/sshguard) that modify iptables, Fang is completely read-only, avoiding risk of accidental admin lockouts while providing forensic JSON reports, `--follow` mode, and native systemd-journald ingestion.
  ```

---

## 3. `sbilly/awesome-security`

- **Repository**: [https://github.com/sbilly/awesome-security](https://github.com/sbilly/awesome-security)
- **Target Section**: `Defensive Security` -> `Log Analysis`
- **Maintenance Status**: Well-maintained security index.
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Safe, read-only SSH brute-force log analyzer providing sliding-window burst detection and forensic JSON reports.
  ```
- **PR Title**: `Add Fang to Defensive Security / Log Analysis`
- **PR Description Template**:
  ```markdown
  Add Fang (https://github.com/X-4xu/fang-ssh) to Defensive Security.

  Fang is a lightweight, defensive CLI tool in Python that analyzes Linux auth logs (Syslog, RFC 3339, `.gz`, and systemd-journald) with rolling sliding-window eviction, compromise correlation, and JSON evidence chains.
  ```

---

## 4. `vinta/awesome-python`

- **Repository**: [https://github.com/vinta/awesome-python](https://github.com/vinta/awesome-python)
- **Target Section**: `DevOps Tools` or `System Administration`
- **Maintenance Status**: Very active, requires strict adherence to alphabetical sorting.
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Defensive SSH brute-force attack detector and forensic log analyzer for Linux.
  ```
- **PR Title**: `Add Fang to DevOps / System Administration`
- **PR Description Template**:
  ```markdown
  Adds Fang (https://github.com/X-4xu/fang-ssh) to the DevOps Tools section in alphabetical order.

  Fang is a Python 3.10+ security tool that uses double-ended queues for in-memory sliding-window log analysis without external network dependencies.
  ```

---

## 5. `onur/awesome-linux-security`

- **Repository**: [https://github.com/onur/awesome-linux-security](https://github.com/onur/awesome-linux-security)
- **Target Section**: `Intrusion Detection & Log Analysis`
- **Maintenance Status**: Curated Linux defensive security tools list.
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Passive SSH brute-force analyzer with sliding-window detection and structured JSON evidence reporting.
  ```
- **PR Title**: `Add Fang to Intrusion Detection & Log Analysis`
- **PR Description Template**:
  ```markdown
  Adds Fang, an open-source defensive SSH authentication log analyzer for Linux systems supporting Syslog, RFC 3339, gzip archives, and systemd-journald.
  ```

---

## 6. `carlospolop/awesome-cybersecurity-blueteam`

- **Repository**: [https://github.com/carlospolop/awesome-cybersecurity-blueteam](https://github.com/carlospolop/awesome-cybersecurity-blueteam)
- **Target Section**: `Host Defense / Log Monitoring`
- **Maintenance Status**: Widely followed Blue Team reference list.
- **Exact Line to Add**:
  ```markdown
  * [Fang](https://github.com/X-4xu/fang-ssh) - Passive SSH brute-force detection and forensic JSON reporting with account compromise correlation.
  ```
- **PR Title**: `Add Fang to Host Defense / Log Monitoring`
- **PR Description Template**:
  ```markdown
  Adds Fang (https://github.com/X-4xu/fang-ssh) under Host Defense / Log Monitoring.
  ```

# Python & Developer Tooling Newsletters Submission Guide

This document contains verified submission forms, contact emails, and ready-to-submit blurbs for the top weekly Python and developer newsletters.

---

## 1. PyCoder’s Weekly

- **Website**: [https://pycoders.com](https://pycoders.com)
- **Submission Link**: [https://pycoders.com/submissions](https://pycoders.com/submissions)
- **Audience**: ~100k Python developers.
- **Title**: `Fang: Defensive SSH Brute-Force Log Analyzer in Python`
- **Link**: `https://github.com/X-4xu/fang-ssh`
- **Short Description (under 300 chars)**:
  > Fang is an open-source Python tool that analyzes Linux SSH auth logs (`/var/log/auth.log`, `.gz`, and `systemd-journald`) using an in-memory sliding-window with timestamp eviction. Outputs structured JSON reports with full raw evidence chains. Read-only with zero firewall risk.

---

## 2. Python Weekly

- **Website**: [https://www.pythonweekly.com](https://www.pythonweekly.com)
- **Submission Email**: `submissions@pythonweekly.com`
- **Audience**: Curated weekly newsletter with ~70k subscribers.
- **Subject**: `Project Submission: Fang - SSH brute-force log analyzer`
- **Body**:
  ```text
  Hi Rahul,

  I'd love to suggest Fang for an upcoming issue of Python Weekly:

  Fang (https://github.com/X-4xu/fang-ssh) is a defensive SSH brute-force log analyzer written in Python 3.10+. It uses a double-ended queue (collections.deque) for rolling sliding-window burst detection, supports BSD syslog, RFC 3339, rotated .gz logs, and live tailing (--follow). It correlates failed login bursts with subsequent accepted logins to detect possible account compromises, and exports full forensic evidence chains to structured JSON.

  Thanks!
  Hassan Ali
  ```

---

## 3. Console.dev (Weekly Tools for Developers)

- **Website**: [https://console.dev](https://console.dev)
- **Submission Form**: [https://console.dev/contact/](https://console.dev/contact/) or suggest via Twitter `@consoledotdev`
- **Focus**: Innovative open-source developer and sysadmin tools.
- **Suggested Pitch**:
  > Fang is a read-only, passive SSH brute-force detection CLI tool in Python. Unlike Fail2ban which actively modifies iptables (creating admin lockout risk), Fang focuses on accurate sliding-window burst detection, real-time log tailing, and forensic JSON evidence reporting for auditing and incident response.
  > Link: https://github.com/X-4xu/fang-ssh

---

## 4. Awesome Python Newsletter (LibHunt)

- **Website**: [https://python.libhunt.com/newsletter](https://python.libhunt.com/newsletter)
- **Submission Method**: Indexed automatically once added to LibHunt or via [https://python.libhunt.com/suggest](https://python.libhunt.com/suggest)
- **Category**: Security / System Administration
- **Description**:
  > Fang (fang-ssh): Defensive SSH brute-force log analyzer and forensic evidence reporter with sliding-window detection and native journald streaming.

---

## 5. Blue Team Weekly / SANS Defensive Security Digests

- **Focus**: Incident response and host-based defense automation.
- **Suggested Blurb**:
  > Fang: Passive SSH brute-force detection for Linux auth logs. Features rolling sliding-window eviction, compromise detection (accepted logins following failure bursts), and structured JSON reports containing exact raw log lines and line numbers.
  > Repository: https://github.com/X-4xu/fang-ssh

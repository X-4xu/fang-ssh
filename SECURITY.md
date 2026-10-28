# Security Policy

## Responsible Testing and Defensive Purpose

`Fang` (`fang-ssh`) is an open-source defensive monitoring tool designed to help system administrators and security engineers detect unauthorized access attempts and brute-force attacks against SSH servers.

- **Defensive Monitoring Only**: This tool only inspects local authentication logs (or piped syslog/journald streams). It does not perform active network scanning, port enumeration, or network interception.
- **Untrusted Input Assumptions**: While Fang operates in read-only mode and does not alter system firewall rules, log lines are treated as untrusted data originating from potential attackers. To protect against malicious inputs, Fang implements:
  - Bounded regular expression matching designed to prevent Regular Expression Denial of Service (ReDoS).
  - Strict IP address validation using standard library parsers (`ipaddress`), dropping invalid or malformed addresses.
  - Bounded in-memory sliding windows with automatic chronological eviction ($O(1)$) to cap memory utilization during flood attempts.
  - Non-execution guarantee: Log data is never evaluated in a shell execution environment.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability or potential parser denial-of-service in `Fang`, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Submit a private advisory via [GitHub Security Advisories](https://github.com/X-4xu/fang-ssh/security/advisories/new).
3. Provide details regarding:
   - Type of issue (e.g., catastrophic backtracking in regex, unhandled exception on malformed log lines, excessive memory allocation during high-volume bursts).
   - Sample log lines that reproduce the issue.
   - Platform, Python version, and potential impact.

Maintainers will acknowledge receipt within 48 hours and coordinate a security fix and release promptly.

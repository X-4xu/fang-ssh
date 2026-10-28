# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
*Security* tab of the repository, then *Report a vulnerability*. Include the Fang version
(`fang --version`), the smallest log line or command that reproduces the problem, and the impact
you expect. You will get an answer within a few days; fixes ship as a patch release.

Supported versions: the latest `2.x` release.

## What Fang is designed to withstand

Fang reads attacker-influenced text (usernames, whole log lines) and often runs with extra
privileges, so it is built to treat logs as hostile:

| Threat | Defense |
|---|---|
| Account name forges a different source IP (`x from 6.6.6.6 port 1`) | Message patterns are anchored to the end of the line; the last `from <ip> port <n>` wins. Covered by tests for every message type. |
| Terminal escape / bidi / control characters in log content | Everything printed or stored is reduced to printable characters. |
| Regular-expression denial of service | Hard length limits before any regex runs; bounded-time tests on pathological lines. |
| Memory exhaustion (many IPs, many usernames, huge lines, decompression bombs) | Capped LRU state, capped windows and evidence, 64 KiB line cap, `--max-bytes`. |
| Symlink / FIFO tricks on output paths when run as root | Atomic replace (never follows a symlink), `O_NOFOLLOW`, regular-file checks, `O_NONBLOCK`. |
| Command or option injection | No shell anywhere. The only subprocess is `journalctl` with a fixed argument list, resolved from a fixed system `PATH`; user text is passed as `--since=<value>`. |
| Data leaking from reports | Output files are created with mode 0600. |
| Network egress | The code imports no networking module. The systemd unit in `contrib/` runs with `PrivateNetwork=yes`. |

## Known limits (please read)

- **Fang detects; it does not enforce.** The blocklist is a text file for *you* to load into your
  firewall. Always add your own administrative addresses with `--allow` first.
- Detection is heuristic. Shared NAT addresses can cause false positives for the
  possible-compromise rule; very busy public servers can make the distributed-attack rule noisy.
- Only OpenSSH message formats in English are understood. Other SSH servers are not supported.
- Log lines can be forged by anyone who can write to the syslog socket on the same host; Fang
  cannot tell. Restrict access to your logs.
- Timestamps in classic syslog have no time zone or year; set `--assume-tz` (and `--year` for old
  files) if the defaults do not match your server.

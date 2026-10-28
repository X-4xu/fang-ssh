# Reddit: r/sysadmin Submission Draft

## Subreddit Information & Rules Assessment

- **Subreddit**: [r/sysadmin](https://www.reddit.com/r/sysadmin/) (~850k members)
- **Rules on Self-Promotion**:
  - Rule 7: Strict anti-spam policy. Pure marketing links or corporate tools get downvoted or removed.
  - Transparent open-source tools that solve real sysadmin pain points (e.g. audit automation, avoiding iptables lockouts) are permitted as text posts if the author actively answers questions and does not sell anything.
  - Focus must be on practical operational value, safety, and why it doesn't break production.

---

## Post Details

- **Title**: Auditing SSH brute-force bursts without risk of iptables lockout (Fang)

---

## Post Body

Hey fellow sysadmins,

Most of us run or have run Fail2ban or SSHGuard on Linux hosts. While they're great at automatically dropping bots, active firewall modification has always had two painful side effects in production:

1. **Accidental Admin Lockout / Self-DoS**: A misbehaving script, a shared VPN egress IP, or a team member fat-fingering credentials can get an entire office or management subnet banned in `iptables`/`nftables`.
2. **Poor Audit Visibility**: When security asks *"which IPs attacked last week, what usernames did they target, and what was the raw log evidence?"*, pulling bans out of syslog or SQLite tables requires custom scripting.

I built **Fang** ([github.com/X-4xu/fang-ssh](https://github.com/X-4xu/fang-ssh)) to solve the passive analysis and forensics side of this problem.

### What it does:

- **100% Read-Only**: Fang never touches `iptables`, `nftables`, or network interfaces. Zero risk of kicking you or your team off the box.
- **Sliding-Window Detection**: Instead of fixed minute-block counters, it uses an in-memory sliding window with timestamp eviction. If an IP sends 10 failed attempts over 15 seconds across a minute boundary, it detects the burst accurately.
- **Handles Real-World Logs**:
  - Plaintext `/var/log/auth.log` or `/var/log/secure`.
  - Rotated compressed `.gz` archives (`/var/log/auth.log.1.gz`) without needing `zcat` first.
  - Direct `systemd-journald` ingestion: `fang --journalctl`
  - Pipelines: `journalctl -u ssh -o short-iso | fang -l -`
- **Real-Time Follow Mode**: `fang -f -l /var/log/auth.log` tails live logs and gracefully handles `logrotate` inode swaps.
- **Possible Compromise Alerting**: If an IP fails several logins and then succeeds (`Accepted password` or `Accepted publickey`), it flags a `CRITICAL` alert for incident response.
- **Structured JSON Evidence Reports**: Running with `-o report.json` dumps complete forensic chains (timestamps, target usernames, ports, and raw unedited log lines).
- **CI / Automation Exit Codes**: `--exit-code-on-alert` exits with code 2 if an attack was detected, making it easy to drop into scheduled audit cron jobs or Ansible playbooks.

### How to run it:

Fang is an open-source Python tool with MIT license. It is distributed directly on GitHub (not on PyPI):

```bash
# Run once without installing:
uvx --from git+https://github.com/X-4xu/fang-ssh fang -l /var/log/auth.log

# Or install as an isolated CLI tool with pipx:
pipx install git+https://github.com/X-4xu/fang-ssh.git
```

GitHub: https://github.com/X-4xu/fang-ssh

I'd love feedback on how it handles your distribution's auth log quirks or journald setups!

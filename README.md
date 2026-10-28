# Fang

**Defensive SSH attack detector for Linux.** Fang reads your `sshd` logs (log files, rotated archives or
systemd-journald), detects brute-force, low-and-slow, distributed (password-spraying) and
**possible-compromise** patterns, and writes clear alerts, a JSON report and an optional blocklist.

[![CI](https://github.com/X-4xu/fang/actions/workflows/ci.yml/badge.svg)](https://github.com/X-4xu/fang/actions)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)

- **No runtime dependencies** (standard library only; `tomli` is pulled in on Python 3.10 only).
- **Passive and defensive**: no network code, no shell, never changes your firewall.
- **Hostile-log safe**: forged source addresses, terminal escapes, giant lines and floods are handled and tested.
- Works on Debian/Ubuntu (`auth.log`), RHEL/Rocky/Alma (`secure`), and any systemd host (`--journald`).

> العربية: انظر القسم [العربي](#-بالعربي) في آخر الصفحة.

## Install

```bash
git clone https://github.com/X-4xu/fang.git && cd fang
pipx install .          # or: python -m venv .venv && . .venv/bin/activate && pip install .
fang --version
```

The PyPI name is **`fang-ssh`** (`fang` is taken): `pipx install fang-ssh` once the release is published.
The command is always `fang`.

## Quick start

```bash
fang                                          # /var/log/auth.log, /var/log/secure, or journald
fang -l /var/log/auth.log -l /var/log/auth.log.1.gz     # several files, merged by time
fang --journald --journal-since "24 hours ago"          # hosts without auth.log
fang --journald --follow --jsonl /var/lib/fang/alerts.jsonl   # live monitoring
journalctl -u ssh -o short-iso | fang -l -              # read from a pipe
fang -l auth.log -o report.json --exit-code-on-alert --quiet  # CI / cron (exit code 2 on alerts)
```

**Your first run: tell Fang who you are.** Add your own admin IPs, VPN and monitoring hosts so they can never
alert or be blocklisted:

```bash
fang --allow 203.0.113.10 --allow 10.0.0.0/8 -l /var/log/auth.log
```

### Running without root

Fang only needs read access to the log, so do not run it as root:

```bash
sudo usermod -aG adm $USER              # Debian/Ubuntu: /var/log/auth.log is readable by group "adm"
sudo usermod -aG systemd-journal $USER  # any systemd host, for --journald (log out and in again)
```

On RHEL-family systems `/var/log/secure` is root-only; use `--journald` with the `systemd-journal` group.
A hardened service that runs Fang as a throw-away user with no network is in `contrib/fang.service`.

## What it detects

| Alert type | Fires when (defaults) | Severity |
|---|---|---|
| `brute_force` | 5+ failed attempts from one IP within 60 s | MEDIUM; HIGH at 10+ or any privileged account; CRITICAL at 20+, or 10+ against a privileged account |
| `slow_brute_force` | 20+ failures from one IP within 1 h (without tripping the fast rule) | MEDIUM; HIGH at 40+ or privileged; CRITICAL at 100+, or 40+ against a privileged account |
| `distributed_attack` | 10+ different IPs failing against the same account within 10 min | MEDIUM; HIGH at 20+ or a privileged account; CRITICAL at 40+ |
| `possible_compromise` | A successful login from an IP that had 3+ failures in the last hour | CRITICAL for password logins, HIGH for public-key logins |

Privileged accounts: `root`, `admin`, `administrator`, `wheel` (configurable). Severities scale with `--threshold`.

**Alerts are de-duplicated**: the same alert repeats only after the cooldown (5 min; 1 h for the slow rule),
but a *higher severity* is always reported immediately and marked `ESCALATED`.

**What counts as one failed attempt** (so thresholds mean what they say):

- each `Failed password / publickey / keyboard-interactive ...` line = 1 (rsyslog's `message repeated N times` = N);
- `Connection closed by ... [preauth]` and `maximum authentication attempts exceeded` count **once per connection**, and
  only if that connection logged no `Failed ...` line (scanners that disconnect before authenticating);
- `Invalid user ...`, `Failed none ...` and PAM `authentication failure` lines are **never counted**: they describe an
  attempt that already has its own `Failed ...` line.

## Example

```text
+---------------- FANG ALERT: POSSIBLE COMPROMISE [CRITICAL] ----------------+
| Alert ID:         ALERT-FANG-9FC25184BD
| Source IP:        203.0.113.42
| Failed attempts:  25 (recent)
| Total from IP:    25
| Time range (UTC): 2026-10-25 02:10:00 -> 2026-10-25 02:10:51
| Target users:     admin, git, oracle, postgres, root, test, ubuntu, user
| Source ports:     40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007 (+17 more)
| Successful login: ubuntu via password
| Pattern:          Possible compromise: successful password for 'ubuntu' after 25 failed attempts from the same IP (same account was attacked)
+----------------------------------------------------------------------------+
```

```text
+------------------ FANG ALERT: DISTRIBUTED ATTACK [HIGH] -------------------+
| Alert ID:         ALERT-FANG-56FB46B820
| Sources:          10 IPs: 192.0.2.100, 192.0.2.101, 192.0.2.102, 192.0.2.103, 192.0.2.104, 192.0.2.105 (+4 more)
| Failed attempts:  19 (in 600s window)
| Time range (UTC): 2026-10-25 02:30:00 -> 2026-10-25 02:32:06
| Target users:     root
| Source ports:     41000, 41001, 41010, 41011, 41020, 41021, 41030, 41031 (+11 more)
| Pattern:          Distributed attack on account 'root': 10 distinct sources, 19 failed attempts within 600s
+----------------------------------------------------------------------------+
```

```text
Fang: SSH Security Analysis Summary
+------------------------+--------------------------+
| Metric                 | Value                    |
+------------------------+--------------------------+
| Log sources            | examples/sample_auth.log |
| Lines scanned          | 133                      |
| SSH events parsed      | 131                      |
| Failed login attempts  | 94                       |
| Successful logins      | 1                        |
| Unique source IPs      | 18                       |
| Allow-listed events    | 1                        |
| Alerts triggered       | 8                        |
| Suppressed duplicates  | 30                       |
| Execution time         | 0.010s                   |
| Log-injection attempts | 1                        |
+------------------------+--------------------------+
```

Try it yourself with the synthetic log in this repository:
`fang -l examples/sample_auth.log --year 2026 --allow 192.0.2.10`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `-l, --log-file PATH` | auto | Log file (plain, `.gz`, `.bz2`, `.xz`, detected by content); `-` = stdin; repeatable |
| `--journald`, `--journal-since WHEN` | | Read sshd from systemd-journald (`--journal-since "1 hour ago"`) |
| `-f, --follow`, `--from-start` | | Keep watching (survives log rotation); `--from-start` also processes existing lines |
| `-t, --threshold` / `-w, --window` | 5 / 60 | Fast rule: attempts per window (seconds) |
| `-c, --cooldown` | 300 | Seconds before the same alert repeats |
| `--slow-threshold`, `--history-window` | 20 / 3600 | Slow rule (0 disables); also the look-back for compromise detection |
| `--spray-threshold`, `--spray-window` | 10 / 600 | Distributed rule: distinct IPs per account (0 disables) |
| `--compromise-failures` | 3 | Failures before a login is suspicious (0 disables) |
| `--ignore-preauth-disconnects` | | Do not count pre-auth disconnects as failures |
| `--privileged-user NAME` | root, admin, administrator, wheel | Accounts that raise severity (repeatable) |
| `--allow IP/CIDR` | | Trusted addresses (repeatable) |
| `--config FILE` | | TOML configuration ([`examples/fang.toml`](examples/fang.toml)); CLI flags override it |
| `--assume-tz TZ`, `--year YYYY` | UTC | Time zone / year for classic syslog timestamps (e.g. `Asia/Baghdad`) |
| `--max-bytes N` | 0 | Abort a source after N decompressed bytes (decompression-bomb guard) |
| `-o, --output FILE` | | JSON report (mode 0600) |
| `--jsonl FILE` | | Append each alert as one JSON line (SIEM / Filebeat friendly) |
| `--blocklist-file FILE`, `--block-min-severity` | high | Maintain a plain-text IP blocklist |
| `--enable-net-access-hook` | | Print dry-run `net-access-controller` payloads |
| `-q`, `--no-summary`, `--no-color`, `-v` | | Output control |
| `--exit-code-on-alert` | | Exit 2 if any alert was raised |

**Exit codes:** `0` ok - `1` error (unreadable source or output) - `2` alerts found (with `--exit-code-on-alert`) -
`64` usage or configuration error.

## Using the blocklist

`--blocklist-file` keeps a plain list (one IP per line). Fang **never** applies it: loopback, link-local, multicast,
reserved and allow-listed addresses are never written, and the file is replaced atomically so a reader never sees half a
list. Review it, then feed your firewall. An example nftables ruleset is in [`contrib/fang.nft`](contrib/fang.nft)
(syntax-checked with `nft -c`):

```bash
sudo nft -f contrib/fang.nft
v4=$(grep -v '^#' /var/lib/fang/blocklist.txt | grep -v ':' | paste -sd,)
[ -n "$v4" ] && sudo nft add element inet fang blocklist4 "{ $v4 }"
```

Fang is a **detector**. If you want automatic enforcement, use it next to fail2ban or CrowdSec, or consume
the blocklist from your own tooling.

## Report format (schema 2.0.0)

`-o report.json` writes `schema_version`, `analyzer_version`, `generated_at`, the effective `config`, a `summary`
(lines, events, failures, unique IPs, alerts by severity/type, skipped lines, warnings), `top_offenders`, and
`alerts[]`, each with `alert_id`, `alert_type`, `severity`, `source_ip`/`source_ips`, `pattern`,
`failed_attempts_count`, `time_range`, `target_usernames`, `ports`, `escalation`, `evidence_truncated` and the
`evidence[]` log lines (capped per alert). Alert IDs are deterministic: the same log always gives the same IDs.

## Security model

Logs are attacker-controlled input. See [`SECURITY.md`](SECURITY.md) for the threats Fang defends against and its
known limits. In short: the source IP is always read from the end of the line; everything printed is sanitized;
memory and line sizes are bounded; output files are 0600 and written without following symlinks; no shell and
no network code.

## Limitations

- OpenSSH message formats in English only. Other SSH servers (Dropbear, ...) are not supported.
- Heuristics can misfire: a shared NAT address, or "root" being sprayed on a busy public server, can be noisy.
  Use `--allow`, raise thresholds, or disable a rule with `0`.
- Classic syslog lines carry no year or time zone; set `--assume-tz` / `--year` when the defaults do not fit.
- Input is expected to be roughly chronological; several files are merged by timestamp.
- Memory is bounded (25 000 tracked IPs and accounts by default). On very large logs the oldest idle entries are evicted;
  `summary.evicted_states` tells you when that happened.

## Development

```bash
pip install -e ".[dev]"
ruff format . && ruff check . && mypy && pytest --cov=fang
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Tests use synthetic data only and run on Python 3.10-3.13.

## License

MIT - see [`LICENSE`](LICENSE).

---

## 🇮🇶 بالعربي

**Fang** أداة دفاعية تحلّل سجلات SSH على لينكس (`auth.log` أو `secure` أو `journald`) وتكتشف:

1. **هجوم القوة الغاشمة السريع**: 5 محاولات فاشلة أو أكثر من نفس الـ IP خلال 60 ثانية.
2. **الهجوم البطيء**: 20 محاولة أو أكثر خلال ساعة (للمهاجم الذي يتجنب الحد السريع).
3. **الهجوم الموزّع (Password Spraying)**: 10 عناوين مختلفة أو أكثر تهاجم نفس الحساب خلال 10 دقائق.
4. **احتمال الاختراق**: تسجيل دخول **ناجح** من عنوان كان قد فشل 3 مرات أو أكثر. وهذا أخطر تنبيه.

**التثبيت والتشغيل:**

```bash
git clone https://github.com/X-4xu/fang.git && cd fang && pipx install .
fang --allow عنوانك_IP -l /var/log/auth.log          # أول تشغيل: أضف عنوانك أولاً
fang --journald --follow                              # مراقبة حيّة على أنظمة systemd
fang -l auth.log -o report.json --exit-code-on-alert  # للأتمتة (رمز الخروج 2 عند وجود تنبيه)
```

**نصائح مهمة:**

- لا تشغّلها كـ root. أضف مستخدمك للمجموعة `adm` (ديبيان/أوبونتو) أو `systemd-journal` لقراءة السجلات فقط.
- استخدم `--allow` لعناوينك وعناوين الـ VPN **قبل** استخدام قائمة الحظر، حتى لا تحظر نفسك.
- الأداة **تكتشف ولا تحظر**: ملف `--blocklist-file` قائمة نصية تراجعها بنفسك ثم تحمّلها في الجدار الناري
  (مثال nftables جاهز في `contrib/fang.nft`).
- إذا كان توقيت السجل بدون منطقة زمنية استخدم `--assume-tz Asia/Baghdad`.
- الأداة لا تستخدم الشبكة إطلاقاً ولا تنفّذ أوامر، وتتعامل مع السجلات على أنها مدخلات عدائية
  (عنوان IP مزوّر داخل اسم المستخدم لا يخدعها).

**القيود:** تدعم صيغ OpenSSH الإنجليزية فقط، والكشف يعتمد على قواعد تقريبية قد تعطي إنذارات كاذبة خلف NAT مشترك
أو على سيرفرات عامة مزدحمة (عدّل الحدود أو عطّل القاعدة بالقيمة 0).

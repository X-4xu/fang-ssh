# Contributing

Thanks for helping! Fang is small on purpose: standard library only, defensive-only.

## Set up

```bash
git clone https://github.com/X-4xu/fang.git && cd fang
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
ruff format . && ruff check .      # style and common bugs
mypy                               # strict typing
pytest --cov=fang                  # tests, coverage must stay >= 90 %
```

## Rules

- **Synthetic data only.** Test logs must use documentation addresses (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Never commit real logs, IPs or usernames.
- Anything read from a log is untrusted. New parsing code needs tests for forged and oversized
  input, and must not add regexes that can backtrack badly (see `tests/test_security.py`).
- No new runtime dependencies, no network access, no shell execution.
- New detection behaviour needs tests for: the trigger, just below the trigger, severity,
  cooldown/escalation, and the allowlist.
- Update `CHANGELOG.md` for user-visible changes.

## Adding a log format

Add the regex to `src/fang/parser.py`, anchor it with `$`, take the username greedily so the
last `from <ip> port <n>` is used, and add a line of the real format to `tests/test_parser.py`.

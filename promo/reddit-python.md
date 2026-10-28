# Reddit: r/Python Submission Draft

## Subreddit Information & Rules Assessment

- **Subreddit**: [r/Python](https://www.reddit.com/r/Python/) (~1.2M members)
- **Rules on Self-Promotion**:
  - Rule 4: "Showcase / Project posts must be informative and demonstrate code or architecture."
  - Best Time: "Showcase Saturday" or regular weekday post with substantial code discussion.
  - Do NOT post purely as a link or marketing pitch; write a technical breakdown of the algorithms and Python standard library features used.

---

## Post Details

- **Flair**: `Showcase` or `Project`
- **Title**: I wrote Fang, a defensive SSH brute-force analyzer in Python using sliding-window deque eviction

---

## Post Body

Hey r/Python,

I recently open-sourced **Fang** ([github.com/X-4xu/fang-ssh](https://github.com/X-4xu/fang-ssh)), a defensive SSH authentication log analyzer built for Linux servers (`/var/log/auth.log` and `/var/log/secure`).

I wanted to share how it's implemented under the hood, particularly around rolling sliding-window detection, safe log streaming, and zero-dependency memory efficiency.

### 1. Rolling Sliding-Window with `collections.deque`

Many traditional log analysis tools use fixed time buckets (e.g. counting events in 1-minute blocks). The classic flaw is that an attacker sending 4 requests at 11:59:58 and 4 requests at 12:00:02 sends 8 requests in 4 seconds, but a naive 1-minute bucket counter only sees 4 in each minute and never triggers a threshold of 5.

Fang tracks events per source IP using a double-ended queue (`collections.deque`):

```python
cutoff = current_event.timestamp - timedelta(seconds=self.window_seconds)
while window and window[0].timestamp < cutoff:
    window.popleft()

window.append(current_event)

if len(window) >= self.threshold:
    # Trigger alert if not within cooldown
```

Because `collections.deque` provides $O(1)$ appends and pops, timestamp eviction is practically instantaneous even during high-volume log replays.

### 2. Streaming Multi-Format Logs Without Memory Blowup

Linux auth logs can grow into multi-gigabyte files or be compressed as `.gz` after rotation. Rather than loading lines into memory:

- A unified generator yields `SshAuthEvent` dataclasses lazily:
  ```python
  if path.suffix == ".gz":
      with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
          yield from self.parse_stream(f)
  ```
- Every line has an upper bound guard (`len(line) <= 4096`) to defend against catastrophic backtracking (ReDoS) or corrupted binary data injected into syslogs.
- Control characters and escape sequences are stripped before field parsing to prevent terminal injection.

### 3. Handling Live Log Tailing (`--follow`) & Rotations

In `--follow` mode, Fang uses file descriptors and `os.stat` to track inodes. If `logrotate` rotates `/var/log/auth.log`, or if a script truncates the file in place, Fang automatically detects the inode change or size regression and re-anchors the file stream seamlessly.

### 4. Detecting "Possible Compromises"

One feature I added in v1.1.0 is correlating failure bursts with successful authentications: if an IP triggers multiple failed password attempts and then achieves an `Accepted password` or `Accepted publickey` within the sliding window, Fang escalates the event to `CRITICAL` as a possible account takeover indicator.

### Packaging & Distribution

Fang is distributed directly via GitHub (not on PyPI):
```bash
pipx install git+https://github.com/X-4xu/fang-ssh.git
# Or try it instantly with uv:
uvx --from git+https://github.com/X-4xu/fang-ssh fang --help
```

GitHub repository: https://github.com/X-4xu/fang-ssh

I'd appreciate feedback on the architecture, detector heuristics, or edge cases in your auth log setups!

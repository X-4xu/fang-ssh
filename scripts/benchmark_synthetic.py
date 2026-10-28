#!/usr/bin/env python3
"""
Synthetic Log Generator and Reproducible Benchmark for Fang (fang-ssh).

Generates realistic SSH authentication logs with configurable volume and
measures parsing and sliding-window detection throughput in lines/second.
"""

from __future__ import annotations

import argparse
import io
import platform
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fang.detector import BruteForceDetector  # noqa: E402
from fang.parser import SshLogParser  # noqa: E402

SAMPLE_USERS = [
    "root",
    "admin",
    "ubuntu",
    "deploy",
    "guest",
    "postgres",
    "test",
    "oracle",
    "git",
]
ATTACKER_IPS = [
    "203.0.113.15",
    "203.0.113.42",
    "203.0.113.88",
    "198.51.100.10",
    "198.51.100.77",
    "192.0.2.100",
]
BENIGN_IPS = [
    "192.0.2.1",
    "192.0.2.2",
    "198.51.100.5",
]


def generate_synthetic_logs(
    num_lines: int, start_time: datetime | None = None
) -> list[str]:
    """Generate synthetic SSH auth log lines with realistic temporal distribution."""
    if start_time is None:
        start_time = datetime(2026, 10, 28, 10, 0, 0, tzinfo=timezone.utc)

    lines: list[str] = []
    current_time = start_time

    for i in range(num_lines):
        # Advance time by 0.1 to 2.5 seconds
        current_time += timedelta(milliseconds=random.randint(100, 2500))
        ts_syslog = current_time.strftime("%b %d %H:%M:%S")
        ts_iso = current_time.isoformat()

        roll = random.random()
        # 40% brute-force failure
        if roll < 0.40:
            ip = random.choice(ATTACKER_IPS)
            user = random.choice(SAMPLE_USERS)
            port = random.randint(30000, 65000)
            if random.random() < 0.3:
                line = f"{ts_syslog} srv01 sshd[{1000 + i % 5000}]: Invalid user {user} from {ip} port {port}"
            else:
                line = f"{ts_syslog} srv01 sshd[{1000 + i % 5000}]: Failed password for {user} from {ip} port {port} ssh2"
        # 10% successful logins
        elif roll < 0.50:
            ip = random.choice(BENIGN_IPS)
            user = random.choice(["deploy", "admin", "ubuntu"])
            port = random.randint(30000, 65000)
            line = f"{ts_syslog} srv01 sshd[{1000 + i % 5000}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abc123demo"
        # 20% RFC 3339 formatted entries
        elif roll < 0.70:
            ip = random.choice(ATTACKER_IPS)
            user = random.choice(SAMPLE_USERS)
            port = random.randint(30000, 65000)
            line = f"{ts_iso} auth-node sshd[{1000 + i % 5000}]: Failed password for invalid user {user} from {ip} port {port} ssh2"
        # 30% background syslog noise (cron, sudo, systemd)
        else:
            noise_types = [
                f"{ts_syslog} srv01 CRON[{2000 + i % 1000}]: (root) CMD (/usr/local/bin/backup.sh > /dev/null 2>&1)",
                f"{ts_syslog} srv01 sudo: pam_unix(sudo:session): session closed for user root",
                f"{ts_syslog} srv01 systemd[1]: Started Daily apt upgrade and clean activities.",
            ]
            line = random.choice(noise_types)

        lines.append(line)

    return lines


def run_benchmark(lines: list[str]) -> dict[str, float | int | str]:
    """Benchmark parsing and detection on in-memory synthetic lines."""
    parser = SshLogParser(reference_year=2026)
    detector = BruteForceDetector(threshold=5, window_seconds=120)

    # Convert lines to text stream
    log_text = "\n".join(lines) + "\n"
    stream = io.StringIO(log_text)

    start_time = time.perf_counter()
    parsed_events = 0
    total_alerts = 0

    for line in stream:
        event = parser.parse_line(line)
        if event:
            parsed_events += 1
            alert = detector.process_event(event)
            if alert:
                total_alerts += 1

    elapsed = time.perf_counter() - start_time
    total_lines = len(lines)
    throughput = total_lines / elapsed if elapsed > 0 else 0

    return {
        "total_lines": total_lines,
        "parsed_events": parsed_events,
        "total_alerts": total_alerts,
        "elapsed_seconds": round(elapsed, 4),
        "lines_per_second": round(throughput, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fang Benchmark & Synthetic Log Generator"
    )
    parser.add_argument(
        "--lines",
        "-n",
        type=int,
        default=25000,
        help="Number of synthetic log lines to generate and benchmark (default: 25000)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Optional file path to save the generated synthetic log",
    )
    args = parser.parse_args()

    print(f"[*] Generating {args.lines:,} synthetic SSH log lines...")
    lines = generate_synthetic_logs(args.lines)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[+] Saved synthetic log to: {args.output}")

    print("\n" + "=" * 60)
    print("                FANG REPRODUCIBLE BENCHMARK")
    print("=" * 60)
    print(
        f"Platform:      {platform.system()} {platform.release()} ({platform.machine()})"
    )
    print(
        f"Python:        {platform.python_version()} ({platform.python_implementation()})"
    )
    print(f"Input Lines:   {args.lines:,}")

    results = run_benchmark(lines)

    print("-" * 60)
    print(f"Total Lines Processed:  {results['total_lines']:,}")
    print(f"SSH Events Extracted:   {results['parsed_events']:,}")
    print(f"Brute-Force Alerts:     {results['total_alerts']:,}")
    print(f"Elapsed Time:           {results['elapsed_seconds']} seconds")
    print(f"Throughput:             {results['lines_per_second']:,} lines/second")
    print("=" * 60)
    print("\nNote: Results depend on CPU speed, I/O, and Python runtime version.")


if __name__ == "__main__":
    main()

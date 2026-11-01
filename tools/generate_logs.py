"""
Generate sample security logs for the six demo scenarios.

  python tools/generate_logs.py --scenario all --reset
  python tools/generate_logs.py --scenario brute

Scenarios: normal, failed, multiple, brute, frequency, critical, all
Timestamps default to today 10:00 (business hours) so results are
repeatable; use --realtime to stamp events with the current time.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402

FMT = "%Y-%m-%d %H:%M:%S"


def ev(t, etype, user, ip, **extra):
    d = {"timestamp": t.strftime(FMT), "event_type": etype, "username": user, "source_ip": ip}
    d.update(extra)
    return d


def scenario_normal(t):
    return [ev(t, "LOGIN_SUCCESS", "alice", "10.0.0.5")]


def scenario_failed(t):
    return [ev(t, "LOGIN_FAILED", "carol", "192.168.1.25")]


def scenario_multiple(t):
    return [ev(t + timedelta(seconds=20 * i), "LOGIN_FAILED", "bob", "192.168.1.30")
            for i in range(4)]


def scenario_brute(t):
    return [ev(t + timedelta(seconds=5 * i), "LOGIN_FAILED", "admin", "198.51.100.23")
            for i in range(12)]


def scenario_frequency(t):
    return [ev(t + timedelta(seconds=i // 3), "WEB_REQUEST", "anonymous", "203.0.113.50",
               description="GET /search") for i in range(90)]


def scenario_critical(t):
    ip, out = "185.44.12.10", []          # ip is on the known-malicious list
    out += [ev(t + timedelta(seconds=i), "LOGIN_FAILED", "admin", ip) for i in range(60)]
    out.append(ev(t + timedelta(seconds=75), "LOGIN_SUCCESS", "admin", ip))
    out.append(ev(t + timedelta(minutes=4), "DATA_EXFILTRATION", "admin", ip,
                  resource="Production Database", affected_users=12,
                  description="Large unexpected outbound data transfer from Production Database"))
    out.append(ev(t + timedelta(minutes=5), "RANSOMWARE_DETECTED", "admin", ip,
                  resource="Production Database", affected_users=15,
                  description="Mass file encryption detected on Production Database"))
    return out


SCENARIOS = {"normal": scenario_normal, "failed": scenario_failed,
             "multiple": scenario_multiple, "brute": scenario_brute,
             "frequency": scenario_frequency, "critical": scenario_critical}


def generate(names, base, log_file):
    os.makedirs(os.path.dirname(str(log_file)), exist_ok=True)
    written = 0
    with open(log_file, "a", encoding="utf-8") as f:
        for i, name in enumerate(names):
            # space scenarios 30 min apart so they never overlap
            for event in SCENARIOS[name](base + timedelta(minutes=30 * i)):
                f.write(json.dumps(event) + "\n")
                written += 1
    return written


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--scenario", default="all", choices=list(SCENARIOS) + ["all"])
    p.add_argument("--reset", action="store_true", help="empty the log file first")
    p.add_argument("--realtime", action="store_true", help="use the current time")
    p.add_argument("--log-file", default=str(settings.LOG_FILE))
    a = p.parse_args()

    if a.reset:
        open(a.log_file, "w").close()
    now = datetime.now()
    base = now if a.realtime else now.replace(hour=10, minute=0, second=0, microsecond=0)
    names = list(SCENARIOS) if a.scenario == "all" else [a.scenario]
    n = generate(names, base, a.log_file)
    print(f"Wrote {n} events ({', '.join(names)}) to {a.log_file}")


if __name__ == "__main__":
    main()

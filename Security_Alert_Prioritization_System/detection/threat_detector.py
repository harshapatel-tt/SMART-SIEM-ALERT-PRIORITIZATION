"""
Turns raw login events into security alerts.

Rule implemented: BRUTE FORCE - too many failed logins for the same
(username, source IP) pair inside a short time window.
"""

import sys
import os
from collections import defaultdict
from datetime import datetime, timedelta

# Allow `python detection/threat_detector.py` as well as `python -m detection.threat_detector`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_collector.log_reader import read_logs  # noqa: E402

FAILED_LOGIN_THRESHOLD = 5      # failures needed to raise an alert
WINDOW_MINUTES = 10             # ...within this many minutes
BUSINESS_HOURS = (8, 18)        # 08:00 - 17:59 on weekdays

# Fixed risk inputs for this rule (feed the scoring engine).
BRUTE_FORCE_SEVERITY = 90
DEMO_APP_CRITICALITY = 80

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def _parse_time(value):
    try:
        return datetime.strptime(str(value), TIMESTAMP_FORMAT)
    except ValueError:
        return None


def _is_after_hours(moment):
    start, end = BUSINESS_HOURS
    return int(moment.weekday() >= 5 or not (start <= moment.hour < end))


def _densest_window(times, window):
    """
    Returns (count, last_time) for the window that contains the most events.
    `times` must be sorted.
    """

    best_count, best_last = 0, None
    left = 0

    for right, current in enumerate(times):
        while current - times[left] > window:
            left += 1

        count = right - left + 1
        if count > best_count:
            best_count, best_last = count, current

    return best_count, best_last


def detect_threats(
    logs=None,
    threshold=FAILED_LOGIN_THRESHOLD,
    window_minutes=WINDOW_MINUTES,
    malicious_ips=(),
):
    """
    Detects brute-force login attempts.

    logs           -- list of event dicts (defaults to the demo app's log file)
    threshold      -- failed logins needed to raise an alert
    window_minutes -- size of the sliding time window
    malicious_ips  -- optional collection of IPs known to be malicious
    """

    if logs is None:
        logs = read_logs()

    window = timedelta(minutes=window_minutes)
    failures = defaultdict(list)

    for event in logs:
        if event.get("event_type") != "LOGIN_FAILED":
            continue

        moment = _parse_time(event.get("timestamp"))
        if moment is None:
            continue

        key = (
            event.get("username") or "unknown",
            event.get("source_ip") or "unknown",
        )
        failures[key].append(moment)

    alerts = []

    for (username, source_ip), times in failures.items():
        times.sort()
        count, last_seen = _densest_window(times, window)

        if count < threshold:
            continue

        alerts.append(
            {
                "alert_id": f"BRUTE-{username}-{source_ip}",
                "timestamp": last_seen.strftime("%Y-%m-%d %H:%M"),
                "alert_type": "Brute Force Attack",
                "severity": BRUTE_FORCE_SEVERITY,
                "asset": "Demo Web Application",
                "asset_criticality": DEMO_APP_CRITICALITY,
                "source_ip": source_ip,
                "username": username,
                "failed_attempts": count,
                "malicious_ip": int(source_ip in malicious_ips),
                "after_hours": _is_after_hours(last_seen),
                "affected_users": 1,
                "description": (
                    f"{count} failed logins for user '{username}' "
                    f"from {source_ip} within {window_minutes} minutes"
                ),
            }
        )

    return alerts


if __name__ == "__main__":

    alerts = detect_threats()

    print("\nThreat Detection Results")
    print("------------------------")

    if not alerts:
        print("No threats detected.")

    for alert in alerts:
        print("\nThreat Detected!")
        print("Alert ID:", alert["alert_id"])
        print("Type:", alert["alert_type"])
        print("Username:", alert["username"])
        print("Source IP:", alert["source_ip"])
        print("Failed Attempts:", alert["failed_attempts"])
        print("Severity:", alert["severity"])

"""
Event analysis stage: enriches each parsed event with context that the
detection rules and the dashboard use.

Added per event:
  attack_type            human readable category of the event
  failed_attempts        running count of failures for this (ip, user)
                         inside the failed-login window
  ip_events_per_minute   events from the same IP in the last minute
"""

from collections import defaultdict, deque

from config import settings

ATTACK_TYPES = {
    "LOGIN_FAILED": "Authentication Failure",
    "LOGIN_SUCCESS": "Authentication Success",
}


def attack_type_for(event_type):
    if event_type in ATTACK_TYPES:
        return ATTACK_TYPES[event_type]
    profile = settings.EVENT_PROFILES.get(event_type)
    return profile["alert_type"] if profile else "General Activity"


def enrich_events(events):
    """Events must be sorted by timestamp. Returns the same list, enriched."""
    fail_windows = defaultdict(deque)   # (ip, user) -> failure datetimes
    rate_windows = defaultdict(deque)   # ip -> event datetimes

    for event in events:
        ts, ip = event["timestamp"], event["source_ip"]

        rate = rate_windows[ip]
        rate.append(ts)
        while (ts - rate[0]).total_seconds() > settings.RATE_WINDOW_SECONDS:
            rate.popleft()
        event["ip_events_per_minute"] = len(rate)

        key = (ip, event["username"])
        fails = fail_windows[key]
        if event["event_type"] == "LOGIN_FAILED":
            fails.append(ts)
        while fails and (ts - fails[0]).total_seconds() > settings.FAILED_LOGIN_WINDOW_SECONDS:
            fails.popleft()
        event["failed_attempts"] = len(fails)
        event["attack_type"] = attack_type_for(event["event_type"])

    return events

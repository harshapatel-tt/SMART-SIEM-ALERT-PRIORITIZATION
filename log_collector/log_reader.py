"""
Log collection + parsing.

The existing log format is preserved: one JSON object per line, e.g.
{"timestamp": "2026-10-04 18:11:07", "event_type": "LOGIN_FAILED",
 "username": "wrong", "source_ip": "127.0.0.1"}

Extra optional keys (resource, destination_ip, description,
affected_users) are understood but never required.
"""

import hashlib
import json
import logging
import os
import sys
from datetime import datetime

# Allow `python log_collector/log_reader.py` as well as `python -m ...`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402

logger = logging.getLogger(__name__)

# Kept for backwards compatibility with the original module.
LOG_FILE = str(settings.LOG_FILE)

TIMESTAMP_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S")


def parse_timestamp(value):
    """Return a datetime, or None when the value cannot be parsed."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "")
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def parse_event(raw_line, raw, occurrence=0):
    """
    Normalise one raw JSON log record into the internal event shape.
    Returns None if mandatory data (timestamp / event_type) is missing.

    `occurrence` is how many identical lines were seen before this one, so
    two genuine events logged in the same second stay distinct while
    re-reading the same file still yields the same hashes.
    """
    ts = parse_timestamp(raw.get("timestamp"))
    event_type = str(raw.get("event_type", "")).strip().upper()
    if ts is None or not event_type:
        return None

    status = raw.get("status")
    if not status:
        status = {"LOGIN_SUCCESS": "SUCCESS", "LOGIN_FAILED": "FAILURE"}.get(event_type, "INFO")

    affected = raw.get("affected_users")
    try:
        affected = int(affected) if affected is not None else None
    except (TypeError, ValueError):
        affected = None

    return {
        # stable id so re-reading the same line never creates a duplicate
        "event_hash": hashlib.sha1(f"{raw_line}#{occurrence}".encode("utf-8")).hexdigest(),
        "timestamp": ts,
        "event_type": event_type,
        "username": raw.get("username") or "unknown",
        "source_ip": raw.get("source_ip") or "unknown",
        "destination_ip": raw.get("destination_ip"),
        "resource": raw.get("resource") or settings.DEFAULT_RESOURCE,
        "status": str(status).upper(),
        "description": raw.get("description") or "",
        "affected_users": affected,
    }


def read_logs_with_stats(log_file=None):
    """Read and parse the log file. Returns (events, stats)."""
    path = str(log_file or settings.LOG_FILE)
    events, stats = [], {"lines": 0, "parsed": 0, "skipped": 0, "file_found": True}
    seen_lines = {}

    if not os.path.exists(path):
        stats["file_found"] = False
        return events, stats

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            stats["lines"] += 1
            try:
                raw = json.loads(line)
                occurrence = seen_lines.get(line, 0)
                event = parse_event(line, raw, occurrence) if isinstance(raw, dict) else None
                seen_lines[line] = occurrence + 1
            except json.JSONDecodeError:
                event = None
            if event is None:
                stats["skipped"] += 1
                logger.warning("Skipping malformed log line: %.120s", line)
                continue
            stats["parsed"] += 1
            events.append(event)

    events.sort(key=lambda e: e["timestamp"])
    return events, stats


def read_logs(log_file=None):
    """Original entry point: returns the list of normalised events."""
    return read_logs_with_stats(log_file)[0]


if __name__ == "__main__":
    logs = read_logs()

    print("\nCollected Security Logs")
    print("-----------------------")

    for event in logs:
        print(event)

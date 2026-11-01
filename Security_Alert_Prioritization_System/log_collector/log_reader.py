"""
Reads JSON-lines security events written by the demo login application.
"""

import json
import os

# Absolute path, so the reader works no matter where the script is started from.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "logs", "security.log")


def read_logs(log_file=None):
    """
    Returns a list of event dictionaries.

    Blank lines, malformed JSON and non-object lines are skipped.
    A missing log file simply returns an empty list.
    """

    log_file = log_file or LOG_FILE
    events = []

    if not os.path.exists(log_file):
        return events

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(event, dict):
                events.append(event)

    return events


if __name__ == "__main__":
    logs = read_logs()

    print("\nCollected Security Logs")
    print("-----------------------")

    for event in logs:
        print(event)

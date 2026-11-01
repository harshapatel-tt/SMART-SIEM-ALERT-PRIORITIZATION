import json
import os
import tempfile
import unittest

from detection.threat_detector import detect_threats
from log_collector import log_reader


def failed(ts, user="admin", ip="10.0.0.5"):
    return {"timestamp": ts, "event_type": "LOGIN_FAILED", "username": user, "source_ip": ip}


class DetectorTests(unittest.TestCase):
    def test_burst_of_failures_raises_one_alert(self):
        logs = [failed(f"2026-10-05 10:0{i}:00") for i in range(6)]
        alerts = detect_threats(logs=logs)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["alert_type"], "Brute Force Attack")
        self.assertEqual(alert["failed_attempts"], 6)
        self.assertEqual(alert["source_ip"], "10.0.0.5")
        self.assertEqual(alert["username"], "admin")
        self.assertEqual(alert["after_hours"], 0)  # Monday 10:xx

    def test_below_threshold_is_ignored(self):
        logs = [failed(f"2026-10-05 10:0{i}:00") for i in range(4)]
        self.assertEqual(detect_threats(logs=logs), [])

    def test_slow_trickle_outside_window_is_ignored(self):
        logs = [failed(f"2026-10-05 0{h}:00:00") for h in range(1, 8)]
        self.assertEqual(detect_threats(logs=logs), [])

    def test_pairs_are_tracked_separately(self):
        logs = [failed(f"2026-10-05 10:0{i}:00", user="a") for i in range(3)]
        logs += [failed(f"2026-10-05 10:0{i}:00", user="b") for i in range(3)]
        self.assertEqual(detect_threats(logs=logs), [])

    def test_after_hours_and_weekend_flags(self):
        night = [failed(f"2026-10-05 23:0{i}:00") for i in range(5)]      # Monday night
        weekend = [failed(f"2026-10-04 11:0{i}:00") for i in range(5)]    # Sunday
        self.assertEqual(detect_threats(logs=night)[0]["after_hours"], 1)
        self.assertEqual(detect_threats(logs=weekend)[0]["after_hours"], 1)

    def test_username_containing_dashes_is_kept_intact(self):
        logs = [failed(f"2026-10-05 10:0{i}:00", user="a-b-c") for i in range(5)]
        self.assertEqual(detect_threats(logs=logs)[0]["username"], "a-b-c")

    def test_bad_events_are_skipped(self):
        logs = [{"event_type": "LOGIN_FAILED", "timestamp": "garbage"}, {"event_type": "LOGIN_SUCCESS"}, {}]
        self.assertEqual(detect_threats(logs=logs), [])

    def test_known_malicious_ip_flag(self):
        logs = [failed(f"2026-10-05 10:0{i}:00", ip="6.6.6.6") for i in range(5)]
        self.assertEqual(detect_threats(logs=logs, malicious_ips={"6.6.6.6"})[0]["malicious_ip"], 1)


class LogReaderTests(unittest.TestCase):
    def test_reads_valid_lines_and_skips_junk(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(json.dumps({"a": 1}) + "\n\nnot json\n[1, 2]\n" + json.dumps({"b": 2}) + "\n")
        try:
            self.assertEqual(log_reader.read_logs(f.name), [{"a": 1}, {"b": 2}])
        finally:
            os.unlink(f.name)

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(log_reader.read_logs("/definitely/not/here.log"), [])


if __name__ == "__main__":
    unittest.main()

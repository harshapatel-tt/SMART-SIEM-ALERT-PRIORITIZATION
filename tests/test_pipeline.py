"""
End-to-end tests: log lines -> detection -> score -> severity -> DB -> API.
Run with:  python -m unittest discover -s tests -v   (no extra packages)
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta

# Point every module at a throw-away log + database BEFORE importing them.
_TMP = tempfile.mkdtemp()
os.environ["SIEM_LOG_FILE"] = os.path.join(_TMP, "security.log")
os.environ["SIEM_DB_PATH"] = os.path.join(_TMP, "siem.db")

from alerts.pipeline import run_pipeline  # noqa: E402
from backend.api import create_app  # noqa: E402
from config import settings  # noqa: E402
from database import db  # noqa: E402
from tools import generate_logs as gen  # noqa: E402

# A weekday inside business hours, so the after-hours factor is 0.
BASE = datetime(2026, 10, 5, 10, 0, 0)


def write_log(lines):
    with open(settings.LOG_FILE, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")


def alerts_by_type():
    with db.get_connection() as conn:
        return {a["alert_type"]: a for a in db.query_alerts(conn)}


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        if os.path.exists(settings.DB_PATH):
            os.remove(settings.DB_PATH)

    def run_scenario(self, name):
        write_log(gen.SCENARIOS[name](BASE))
        run_pipeline()
        return alerts_by_type()

    def test_1_normal_login_creates_no_alert(self):
        self.assertEqual(self.run_scenario("normal"), {})

    def test_2_single_failed_login_is_low(self):
        a = self.run_scenario("failed")["FAILED_LOGIN"]
        self.assertEqual(a["severity"], "LOW")
        self.assertEqual(a["priority"], "P4 - Low")
        self.assertEqual(a["status"], "NEW")

    def test_3_multiple_failed_logins_is_medium(self):
        a = self.run_scenario("multiple")["MULTIPLE_FAILED_LOGINS"]
        self.assertEqual(a["severity"], "MEDIUM")
        self.assertEqual(a["failed_attempts"], 4)

    def test_4_brute_force_is_high(self):
        a = self.run_scenario("brute")["BRUTE_FORCE_LOGIN"]
        self.assertEqual(a["severity"], "HIGH")
        self.assertEqual(a["failed_attempts"], 12)
        self.assertEqual(a["risk_score"], 70.5)

    def test_5_high_frequency_activity(self):
        a = self.run_scenario("frequency")["HIGH_FREQUENCY_ACTIVITY"]
        self.assertEqual(a["severity"], "MEDIUM")
        self.assertGreaterEqual(a["peak_rate_per_min"], 60)

    def test_6_critical_kill_chain(self):
        alerts = self.run_scenario("critical")
        for kind in ("BRUTE_FORCE_LOGIN", "ACCOUNT_COMPROMISE_SUSPECTED",
                     "DATA_EXFILTRATION", "RANSOMWARE_DETECTED"):
            self.assertEqual(alerts[kind]["severity"], "CRITICAL", kind)
            self.assertEqual(alerts[kind]["priority"], "P1 - Immediate")
            self.assertEqual(alerts[kind]["correlated_events"], 3)
        self.assertEqual(alerts["BRUTE_FORCE_LOGIN"]["malicious_ip"], 1)

    def test_scores_stay_within_0_100(self):
        write_log(gen.scenario_critical(BASE))
        run_pipeline()
        with db.get_connection() as conn:
            for a in db.query_alerts(conn):
                self.assertTrue(0 <= a["risk_score"] <= 100)

    def test_priority_ordering(self):
        write_log([e for n in gen.SCENARIOS for e in gen.SCENARIOS[n](BASE)])
        run_pipeline()
        with db.get_connection() as conn:
            alerts = db.query_alerts(conn)
        ranks = [(a["severity_rank"], -a["risk_score"]) for a in alerts]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[-1]["severity"], "LOW")

    def test_reprocessing_is_idempotent_and_keeps_analyst_status(self):
        write_log(gen.scenario_brute(BASE))
        run_pipeline()
        with db.get_connection() as conn:
            alert_id = db.query_alerts(conn)[0]["alert_id"]
            db.update_alert_status(conn, alert_id, "INVESTIGATING", "looking")
        run_pipeline()
        with db.get_connection() as conn:
            alerts = db.query_alerts(conn)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["status"], "INVESTIGATING")
            self.assertEqual(db.count_rows(conn, "security_events"), 12)

    def test_alert_escalates_as_new_log_lines_arrive(self):
        write_log(gen.scenario_failed(BASE))
        run_pipeline()
        self.assertEqual(list(alerts_by_type()), ["FAILED_LOGIN"])
        # same user + IP keep failing -> same alert id, higher type
        extra = [gen.ev(BASE + timedelta(seconds=10 * i), "LOGIN_FAILED", "carol", "192.168.1.25")
                 for i in range(8)]
        write_log(extra)
        run_pipeline()
        with db.get_connection() as conn:
            alerts = db.query_alerts(conn)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "BRUTE_FORCE_LOGIN")

    def test_malformed_lines_are_skipped_not_fatal(self):
        with open(settings.LOG_FILE, "w") as f:
            f.write("not json\n" + json.dumps({"foo": 1}) + "\n")
            f.write(json.dumps(gen.scenario_failed(BASE)[0]) + "\n")
        result = run_pipeline()
        self.assertEqual(result["lines_skipped"], 2)
        self.assertEqual(result["alerts_generated"], 1)

    def test_original_sample_csv_scores_unchanged(self):
        """Adding new optional signals must not change the original CSV scores."""
        with db.get_connection() as conn:
            db.init_db()
            self.assertEqual(db.seed_sample_alerts(conn), 20)
            by_id = {a["alert_id"]: a for a in db.query_alerts(conn)}
        self.assertEqual(by_id["A016"]["risk_score"], 100.0)
        self.assertEqual(by_id["A016"]["severity"], "CRITICAL")
        self.assertEqual(by_id["A010"]["severity"], "LOW")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(settings.DB_PATH):
            os.remove(settings.DB_PATH)
        write_log([e for n in gen.SCENARIOS for e in gen.SCENARIOS[n](BASE)])
        cls.client = create_app().test_client()

    def test_process_then_read_endpoints(self):
        r = self.client.post("/api/process")
        self.assertEqual(r.status_code, 200)
        self.assertGreater(r.get_json()["alerts_generated"], 0)

        alerts = self.client.get("/api/alerts").get_json()["alerts"]
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        for key in ("alert_id", "timestamp", "event_type", "source_ip", "username",
                    "description", "risk_score", "severity", "status", "priority",
                    "recommended_action"):
            self.assertIn(key, alerts[0])

        crit = self.client.get("/api/alerts/critical").get_json()
        self.assertTrue(all(a["severity"] == "CRITICAL" for a in crit["alerts"]))
        hp = self.client.get("/api/alerts/high-priority").get_json()
        self.assertTrue(all(a["severity"] in ("CRITICAL", "HIGH") for a in hp["alerts"]))

        stats = self.client.get("/api/stats").get_json()
        self.assertEqual(stats["total_alerts"], len(alerts))
        summary = self.client.get("/api/dashboard/summary").get_json()
        self.assertEqual(summary["critical"], stats["by_severity"]["CRITICAL"])
        self.assertEqual(sum(self.client.get("/api/distribution").get_json()["risk_score"].values()),
                         len(alerts))
        self.assertTrue(self.client.get("/api/trend").get_json()["trend"])
        self.assertTrue(self.client.get("/api/events").get_json()["events"])

    def test_update_status_and_validation(self):
        self.client.post("/api/process")
        aid = self.client.get("/api/alerts?severity=LOW").get_json()["alerts"][0]["alert_id"]
        r = self.client.patch(f"/api/alerts/{aid}/status", json={"status": "resolved", "note": "ok"})
        self.assertEqual(r.get_json()["status"], "RESOLVED")
        # resolved alerts leave the open queue
        open_ids = [a["alert_id"] for a in
                    self.client.get("/api/alerts?open_only=true").get_json()["alerts"]]
        self.assertNotIn(aid, open_ids)
        self.assertEqual(self.client.patch(f"/api/alerts/{aid}/status",
                                           json={"status": "BOGUS"}).status_code, 400)
        self.assertEqual(self.client.patch(f"/api/alerts/{aid}/status",
                                           data="x").status_code, 400)
        self.assertEqual(self.client.patch("/api/alerts/NOPE/status",
                                           json={"status": "NEW"}).status_code, 404)
        self.assertEqual(self.client.get("/api/alerts?severity=WRONG").status_code, 400)
        self.assertEqual(self.client.get("/api/alerts/NOPE").status_code, 404)

    def test_cors_header(self):
        r = self.client.get("/api/health", headers={"Origin": "http://localhost:8501"})
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "http://localhost:8501")
        r = self.client.get("/api/health", headers={"Origin": "http://evil.example"})
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))


if __name__ == "__main__":
    unittest.main()

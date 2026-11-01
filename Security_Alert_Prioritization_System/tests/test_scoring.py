import math
import unittest

from scoring_engine import (
    calculate_context_score,
    calculate_risk_score,
    calculate_threat_score,
    get_priority,
    get_priority_reason,
    get_score_breakdown,
)


def alert(**overrides):
    base = {
        "severity": 0,
        "asset_criticality": 0,
        "failed_attempts": 0,
        "malicious_ip": 0,
        "after_hours": 0,
        "affected_users": 0,
    }
    base.update(overrides)
    return base


class ScoringTests(unittest.TestCase):
    def test_module_imports_cleanly(self):
        # Regression: scoring_engine used to import from itself and crash.
        import importlib
        import scoring_engine

        importlib.reload(scoring_engine)

    def test_known_scores_from_sample_data(self):
        a001 = alert(severity=98, asset_criticality=100, malicious_ip=1, affected_users=15)
        self.assertEqual(calculate_risk_score(a001), 84.2)

        a016 = alert(
            severity=100, asset_criticality=100, failed_attempts=50,
            malicious_ip=1, after_hours=1, affected_users=20,
        )
        self.assertEqual(calculate_risk_score(a016), 100.0)

    def test_context_score_components(self):
        self.assertEqual(calculate_context_score(alert()), 0)
        self.assertEqual(calculate_context_score(alert(failed_attempts=5)), 15)
        self.assertEqual(calculate_context_score(alert(failed_attempts=10)), 25)
        self.assertEqual(calculate_context_score(alert(failed_attempts=50)), 35)
        self.assertEqual(calculate_context_score(alert(malicious_ip=1)), 30)
        self.assertEqual(calculate_context_score(alert(after_hours=1)), 15)
        self.assertEqual(calculate_context_score(alert(affected_users=5)), 10)
        self.assertEqual(calculate_context_score(alert(affected_users=10)), 20)

    def test_context_score_is_capped_at_100(self):
        worst = alert(failed_attempts=500, malicious_ip=1, after_hours=1, affected_users=99)
        self.assertEqual(calculate_context_score(worst), 100)

    def test_threat_score(self):
        self.assertEqual(calculate_threat_score(alert()), 0)
        self.assertEqual(calculate_threat_score(alert(malicious_ip=1)), 60)
        self.assertEqual(calculate_threat_score(alert(malicious_ip=1, failed_attempts=50)), 100)
        self.assertEqual(calculate_threat_score(alert(failed_attempts=10)), 25)

    def test_priority_boundaries(self):
        cases = {
            100: "CRITICAL", 90: "CRITICAL", 89.99: "HIGH", 70: "HIGH",
            69.99: "MEDIUM", 40: "MEDIUM", 39.99: "LOW", 0: "LOW",
        }
        for score, expected in cases.items():
            self.assertEqual(get_priority(score), expected, score)

    def test_weights_sum_to_final_score(self):
        a = alert(severity=80, asset_criticality=60, failed_attempts=10, after_hours=1)
        b = get_score_breakdown(a)
        total = b["severity_contribution"] + b["asset_contribution"] + b["context_contribution"]
        self.assertAlmostEqual(total, b["final_score"], places=1)
        self.assertEqual(b["final_score"], calculate_risk_score(a))

    def test_score_stays_within_0_100(self):
        self.assertLessEqual(calculate_risk_score(alert(severity=500, asset_criticality=500, failed_attempts=99, malicious_ip=1, after_hours=1, affected_users=99)), 100)
        self.assertGreaterEqual(calculate_risk_score(alert(severity=-50, asset_criticality=-50)), 0)

    def test_missing_and_nan_values_do_not_crash(self):
        self.assertEqual(calculate_risk_score({}), 0.0)
        self.assertEqual(calculate_risk_score(alert(severity=math.nan)), 0.0)
        self.assertEqual(calculate_risk_score(alert(severity="oops")), 0.0)

    def test_reasons(self):
        self.assertEqual(get_priority_reason(alert()), ["No major risk indicators detected"])
        reasons = get_priority_reason(
            alert(severity=90, asset_criticality=90, malicious_ip=1,
                  failed_attempts=7, after_hours=1, affected_users=6)
        )
        self.assertEqual(len(reasons), 6)


if __name__ == "__main__":
    unittest.main()

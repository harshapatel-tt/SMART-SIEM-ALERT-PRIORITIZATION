import unittest

import pandas as pd

import alert_pipeline as pipeline


class PipelineTests(unittest.TestCase):
    def test_sample_data_loads_and_scores(self):
        df, live = pipeline.build_alert_table(include_live=False)
        self.assertEqual(live, 0)
        self.assertEqual(len(df), 20)
        self.assertTrue(df["risk_score"].is_monotonic_decreasing)
        counts = df["priority"].value_counts().to_dict()
        self.assertEqual(counts, {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 6, "LOW": 4})
        self.assertEqual(df.loc[0, "alert_id"], "A016")
        self.assertEqual(df.loc[0, "risk_score"], 100.0)

    def test_missing_columns_raise_clear_error(self):
        with self.assertRaises(pipeline.AlertDataError) as ctx:
            pipeline.normalise_alerts(pd.DataFrame({"alert_id": ["x"]}))
        self.assertIn("severity", str(ctx.exception))

    def test_bad_numbers_become_zero_and_duplicates_dropped(self):
        row = {c: "" for c in pipeline.COLUMNS}
        row.update(alert_id="X1", severity="abc", asset_criticality=50)
        df = pipeline.normalise_alerts(pd.DataFrame([row, row]))
        self.assertEqual(len(df), 1)
        self.assertEqual(df.loc[0, "severity"], 0)

    def test_live_alerts_are_merged_and_scored(self):
        logs = [
            {"timestamp": f"2026-10-05 02:0{i}:00", "event_type": "LOGIN_FAILED",
             "username": "admin", "source_ip": "9.9.9.9"}
            for i in range(6)
        ]
        live = pipeline.load_live_alerts(logs=logs)
        self.assertEqual(len(live), 1)
        scored = pipeline.score_alerts(pipeline.normalise_alerts(pd.concat(
            [pipeline.load_sample_alerts(), live], ignore_index=True)))
        self.assertEqual(len(scored), 21)
        self.assertIn("BRUTE-admin-9.9.9.9", set(scored["alert_id"]))

    def test_empty_inputs(self):
        self.assertTrue(pipeline.load_live_alerts(logs=[]).empty)
        self.assertTrue(pipeline.score_alerts(pd.DataFrame(columns=pipeline.COLUMNS)).empty)

    def test_csv_export_neutralises_formulas(self):
        df = pd.DataFrame({"x": ["=1+1", "@cmd", "-2", "safe"]})
        self.assertEqual(pipeline.csv_safe(df)["x"].tolist(), ["'=1+1", "'@cmd", "'-2", "safe"])


if __name__ == "__main__":
    unittest.main()

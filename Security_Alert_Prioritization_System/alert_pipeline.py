"""
Data pipeline for the dashboard:

    alerts.csv  ----\
                      >--> validate --> score --> sort --> dashboard
    security.log --> threat_detector --/
"""

import os

import pandas as pd

from detection.threat_detector import detect_threats
from scoring_engine import (
    calculate_risk_score,
    calculate_threat_score,
    get_priority,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_ALERTS_FILE = os.path.join(BASE_DIR, "data", "alerts.csv")

COLUMNS = [
    "alert_id",
    "timestamp",
    "alert_type",
    "severity",
    "asset",
    "asset_criticality",
    "source_ip",
    "failed_attempts",
    "malicious_ip",
    "after_hours",
    "affected_users",
    "description",
]

NUMERIC_COLUMNS = [
    "severity",
    "asset_criticality",
    "failed_attempts",
    "malicious_ip",
    "after_hours",
    "affected_users",
]

TEXT_COLUMNS = [c for c in COLUMNS if c not in NUMERIC_COLUMNS]


class AlertDataError(ValueError):
    """Raised when the alert data is missing required columns."""


def normalise_alerts(df):
    """
    Validates an alert DataFrame and returns a clean copy with exactly COLUMNS.
    Numeric columns are coerced (bad values become 0); text columns lose NaN.
    """

    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise AlertDataError(
            "Alert data is missing required column(s): " + ", ".join(missing)
        )

    df = df[COLUMNS].copy()

    for column in NUMERIC_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    for column in TEXT_COLUMNS:
        df[column] = df[column].fillna("").astype(str)

    return df.drop_duplicates(subset="alert_id", keep="first").reset_index(drop=True)


def load_sample_alerts(path=None):
    """Loads and validates the sample alerts CSV."""

    return normalise_alerts(pd.read_csv(path or SAMPLE_ALERTS_FILE))


def load_live_alerts(logs=None):
    """
    Runs the detector over the demo app's log file (or the given events)
    and returns the alerts in the same shape as the CSV data.
    """

    alerts = detect_threats(logs=logs)

    if not alerts:
        return pd.DataFrame(columns=COLUMNS)

    return normalise_alerts(pd.DataFrame(alerts))


def score_alerts(df):
    """
    Adds risk_score, threat_score and priority, then sorts by risk (highest first).
    Ties are broken by severity so the order is stable.
    """

    df = df.copy()

    if df.empty:
        for column in ("risk_score", "threat_score"):
            df[column] = pd.Series(dtype=float)
        df["priority"] = pd.Series(dtype=str)
        return df

    df["risk_score"] = df.apply(calculate_risk_score, axis=1)
    df["threat_score"] = df.apply(calculate_threat_score, axis=1)
    df["priority"] = df["risk_score"].apply(get_priority)

    return df.sort_values(
        by=["risk_score", "severity", "alert_id"],
        ascending=[False, False, True],
    ).reset_index(drop=True)


def build_alert_table(include_live=True):
    """
    Full pipeline used by the dashboard.
    Returns (scored_df, number_of_live_alerts).
    """

    sample = load_sample_alerts()
    live = load_live_alerts() if include_live else pd.DataFrame(columns=COLUMNS)

    combined = pd.concat([sample, live], ignore_index=True)
    combined = normalise_alerts(combined)

    return score_alerts(combined), len(live)


def csv_safe(df):
    """
    Returns a copy that is safe to open in Excel/Sheets.

    Text cells starting with = + - @ (or tab/CR) would be run as formulas, and
    usernames come from untrusted login attempts, so they get a leading quote.
    """

    df = df.copy()

    for column in df.select_dtypes(include=["object", "string"]).columns:
        df[column] = df[column].map(
            lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
        )

    return df

"""
SQLite storage for security events and alerts.

SQLite was chosen because the project had no database yet and it needs
no server or credentials (the file location comes from SIEM_DB_PATH).

Tables
  security_events  every parsed log event (de-duplicated by event_hash)
  alerts           scored + classified alerts (one row per incident)
  alert_history    audit trail of analyst status changes

CLI:  python -m database.db --init [--seed-sample] [--reset]
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    resource TEXT,
    status TEXT,
    attack_type TEXT,
    failed_attempts INTEGER DEFAULT 0,
    frequency_per_min INTEGER DEFAULT 0,
    description TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    last_seen TEXT,
    alert_type TEXT NOT NULL,
    event_type TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    username TEXT,
    asset TEXT,
    description TEXT,
    event_severity REAL,
    asset_criticality REAL,
    failed_attempts INTEGER DEFAULT 0,
    malicious_ip INTEGER DEFAULT 0,
    after_hours INTEGER DEFAULT 0,
    affected_users INTEGER DEFAULT 1,
    correlated_events INTEGER DEFAULT 0,
    event_count INTEGER DEFAULT 1,
    peak_rate_per_min INTEGER DEFAULT 0,
    risk_score REAL NOT NULL,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    priority TEXT NOT NULL,
    recommended_action TEXT,
    reasons TEXT,
    score_breakdown TEXT,
    status TEXT NOT NULL DEFAULT 'NEW',
    analyst_note TEXT,
    source TEXT NOT NULL DEFAULT 'log',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_sort ON alerts(severity_rank, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    note TEXT,
    changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# Triage order required by the SOC: severity, risk score, frequency,
# asset criticality, correlation (then newest first).
PRIORITY_ORDER = (
    "severity_rank ASC, risk_score DESC, event_count DESC, "
    "asset_criticality DESC, correlated_events DESC, last_seen DESC"
)

ALERT_COLUMNS = [
    "alert_id", "timestamp", "last_seen", "alert_type", "event_type", "source_ip",
    "destination_ip", "username", "asset", "description", "event_severity",
    "asset_criticality", "failed_attempts", "malicious_ip", "after_hours",
    "affected_users", "correlated_events", "event_count", "peak_rate_per_min",
    "risk_score", "severity", "severity_rank", "priority", "recommended_action",
    "reasons", "score_breakdown", "source",
]


@contextmanager
def get_connection(db_path=None):
    path = str(db_path or settings.DB_PATH)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=None):
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)


# ------------------------------------------------------------- inserts
def insert_events(conn, events):
    """Insert parsed events; already-stored ones are ignored. Returns #new."""
    before = conn.total_changes
    conn.executemany(
        """INSERT OR IGNORE INTO security_events
           (event_hash, timestamp, event_type, username, source_ip, destination_ip,
            resource, status, attack_type, failed_attempts, frequency_per_min, description)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        [(e["event_hash"], e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"), e["event_type"],
          e["username"], e["source_ip"], e["destination_ip"], e["resource"], e["status"],
          e.get("attack_type"), e.get("failed_attempts", 0),
          e.get("ip_events_per_minute", 0), e["description"]) for e in events])
    return conn.total_changes - before


def upsert_alert(conn, alert):
    """Insert a new alert, or refresh scoring data of an existing one.
    The analyst-controlled fields (status, note, created_at) are preserved."""
    cols = ALERT_COLUMNS
    placeholders = ",".join("?" for _ in cols)
    updates = ",".join(f"{c}=excluded.{c}" for c in cols if c not in ("alert_id", "source"))
    conn.execute(
        f"""INSERT INTO alerts ({",".join(cols)}) VALUES ({placeholders})
            ON CONFLICT(alert_id) DO UPDATE SET {updates}, updated_at=datetime('now')""",
        [alert.get(c) for c in cols])


# ----------------------------------------------------------- retrieval
def _row_to_alert(row):
    alert = dict(row)
    for key in ("reasons", "score_breakdown"):
        try:
            alert[key] = json.loads(alert[key]) if alert.get(key) else None
        except (TypeError, ValueError):
            alert[key] = None
    return alert


def query_alerts(conn, severity=None, status=None, source_ip=None, search=None,
                 open_only=False, severities=None, limit=500):
    where, params = [], []
    if severity:
        where.append("severity = ?"); params.append(severity.upper())
    if severities:
        where.append(f"severity IN ({','.join('?' for _ in severities)})")
        params.extend(severities)
    if status:
        where.append("status = ?"); params.append(status.upper())
    if open_only:
        closed = settings.CLOSED_STATUSES
        where.append(f"status NOT IN ({','.join('?' for _ in closed)})")
        params.extend(closed)
    if source_ip:
        where.append("source_ip = ?"); params.append(source_ip)
    if search:
        like = f"%{search.lower()}%"
        where.append("(LOWER(alert_id) LIKE ? OR LOWER(alert_type) LIKE ? OR LOWER(asset) LIKE ? "
                     "OR LOWER(source_ip) LIKE ? OR LOWER(COALESCE(username,'')) LIKE ?)")
        params.extend([like] * 5)
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {PRIORITY_ORDER} LIMIT ?"
    params.append(limit)
    return [_row_to_alert(r) for r in conn.execute(sql, params).fetchall()]


def get_alert(conn, alert_id):
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return _row_to_alert(row) if row else None


def update_alert_status(conn, alert_id, new_status, note=None):
    """Returns the updated alert, or None if the id does not exist."""
    row = conn.execute("SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        return None
    conn.execute(
        "UPDATE alerts SET status=?, analyst_note=COALESCE(?, analyst_note), "
        "updated_at=datetime('now') WHERE alert_id=?", (new_status, note, alert_id))
    conn.execute(
        "INSERT INTO alert_history (alert_id, old_status, new_status, note) VALUES (?,?,?,?)",
        (alert_id, row["status"], new_status, note))
    return get_alert(conn, alert_id)


def recent_events(conn, limit=50):
    rows = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]


def severity_counts(conn, open_only=False):
    sql = "SELECT severity, COUNT(*) AS n FROM alerts"
    params = []
    if open_only:
        closed = settings.CLOSED_STATUSES
        sql += f" WHERE status NOT IN ({','.join('?' for _ in closed)})"
        params = list(closed)
    sql += " GROUP BY severity"
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in conn.execute(sql, params):
        counts[r["severity"]] = r["n"]
    return counts


def status_counts(conn):
    counts = {s: 0 for s in settings.ALERT_STATUSES}
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"):
        counts[r["status"]] = r["n"]
    return counts


def risk_histogram(conn, bucket=10):
    """Alerts per risk-score bucket (0-9, 10-19, ... 90-100)."""
    buckets = {f"{lo}-{lo + bucket - 1 if lo + bucket < 100 else 100}": 0
               for lo in range(0, 100, bucket)}
    keys = list(buckets)
    for r in conn.execute("SELECT risk_score FROM alerts"):
        idx = min(int(r["risk_score"] // bucket), len(keys) - 1)
        buckets[keys[idx]] += 1
    return buckets


def alert_trend(conn, granularity="hour"):
    """Alerts per hour (or day) split by severity, oldest first."""
    width = 13 if granularity == "hour" else 10
    rows = conn.execute(
        f"SELECT substr(timestamp,1,{width}) AS bucket, severity, COUNT(*) AS n "
        "FROM alerts GROUP BY bucket, severity ORDER BY bucket").fetchall()
    out = {}
    for r in rows:
        label = r["bucket"] + (":00" if granularity == "hour" else "")
        entry = out.setdefault(label, {"bucket": label, "CRITICAL": 0, "HIGH": 0,
                                       "MEDIUM": 0, "LOW": 0, "total": 0})
        entry[r["severity"]] = r["n"]
        entry["total"] += r["n"]
    return list(out.values())


def top_source_ips(conn, limit=5):
    rows = conn.execute(
        "SELECT source_ip, COUNT(*) AS alerts, MAX(risk_score) AS max_risk FROM alerts "
        "GROUP BY source_ip ORDER BY alerts DESC, max_risk DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]


def count_rows(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# --------------------------------------------------------- sample data
def seed_sample_alerts(conn, csv_path=None):
    """Load the project's original data/alerts.csv through the same scoring
    code, tagged source='sample'. Safe to run repeatedly."""
    from alerts.alert_manager import build_alert  # local import avoids a cycle

    path = csv_path or settings.SAMPLE_ALERTS_CSV
    if not os.path.exists(path):
        return 0
    loaded = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ts = row["timestamp"]
            if len(ts) == 16:
                ts += ":00"
            candidate = {
                "alert_id": row["alert_id"],
                "alert_type": row["alert_type"],
                "event_type": row["alert_type"],
                "timestamp": ts, "last_seen": ts,
                "source_ip": row["source_ip"], "destination_ip": None, "username": None,
                "asset": row["asset"], "description": row["description"],
                "severity": int(row["severity"]),
                "asset_criticality": int(row["asset_criticality"]),
                "failed_attempts": int(row["failed_attempts"]),
                "malicious_ip": int(row["malicious_ip"]),
                "after_hours": int(row["after_hours"]),
                "affected_users": int(row["affected_users"]),
                "correlated_events": 0, "event_count": max(int(row["failed_attempts"]), 1),
                "peak_rate_per_min": 0,
            }
            upsert_alert(conn, build_alert(candidate, source="sample"))
            loaded += 1
    return loaded


def main():
    parser = argparse.ArgumentParser(description="Initialise the SIEM database")
    parser.add_argument("--init", action="store_true", help="create tables")
    parser.add_argument("--reset", action="store_true", help="delete the DB file first")
    parser.add_argument("--seed-sample", action="store_true",
                        help="load data/alerts.csv as sample alerts")
    args = parser.parse_args()

    if args.reset and os.path.exists(settings.DB_PATH):
        os.remove(settings.DB_PATH)
        print(f"Deleted {settings.DB_PATH}")
    init_db()
    print(f"Database ready: {settings.DB_PATH}")
    if args.seed_sample:
        with get_connection() as conn:
            print(f"Loaded {seed_sample_alerts(conn)} sample alerts from data/alerts.csv")


if __name__ == "__main__":
    main()

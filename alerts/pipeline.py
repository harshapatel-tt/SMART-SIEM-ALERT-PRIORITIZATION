"""
End-to-end processing pipeline:

 LOG FILE -> collect -> parse -> event analysis -> threat detection
          -> risk score -> severity -> priority/classification -> SQLite
"""

import logging
import threading
from datetime import datetime

from alerts.alert_manager import build_alert
from database import db
from detection.event_analyzer import enrich_events
from detection.threat_detector import detect_threats
from log_collector.log_reader import read_logs_with_stats

logger = logging.getLogger(__name__)

_lock = threading.Lock()
STATUS = {"last_run": None, "last_error": None, "runs": 0, "last_result": None}


def run_pipeline(log_file=None, db_path=None):
    """Process the whole log once. Idempotent: events and alerts are keyed
    by hashes/ids, so running it again only adds what is new."""
    with _lock:
        try:
            db.init_db(db_path)
            events, stats = read_logs_with_stats(log_file)           # collect + parse
            events = enrich_events(events)                           # event analysis
            candidates = detect_threats(events)                      # threat detection
            alerts = [build_alert(c) for c in candidates]            # score + severity

            with db.get_connection(db_path) as conn:                 # storage
                new_events = db.insert_events(conn, events)
                for alert in alerts:
                    db.upsert_alert(conn, alert)

            result = {
                "log_file_found": stats["file_found"],
                "lines_read": stats["lines"],
                "events_parsed": stats["parsed"],
                "lines_skipped": stats["skipped"],
                "new_events_stored": new_events,
                "alerts_generated": len(alerts),
            }
            STATUS.update(last_run=datetime.now().isoformat(timespec="seconds"),
                          last_error=None, last_result=result, runs=STATUS["runs"] + 1)
            return result
        except Exception as exc:                                     # surfaced, not hidden
            STATUS["last_error"] = f"{type(exc).__name__}: {exc}"
            logger.exception("Pipeline run failed")
            raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(run_pipeline())

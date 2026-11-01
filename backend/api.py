"""
Flask REST API for the SOC dashboard.

Run:  python -m backend.api        (from the project root)

All responses are JSON. A background worker re-processes the log file every
SIEM_PROCESS_INTERVAL seconds, so new log lines become alerts automatically.
"""

import logging
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request  # noqa: E402

from alerts import pipeline  # noqa: E402
from config import settings  # noqa: E402
from database import db  # noqa: E402

logger = logging.getLogger("siem.api")


def create_app(start_worker=False):
    app = Flask(__name__)
    db.init_db()

    # --------------------------------------------------------- CORS
    allowed = {o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()}

    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        if origin and ("*" in allowed or origin in allowed):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    @app.route("/api/<path:_any>", methods=["OPTIONS"])
    def preflight(_any):
        return ("", 204)

    # ------------------------------------------------------ errors
    @app.errorhandler(400)
    def bad_request(err):
        return jsonify(error="bad_request", message=str(err.description)), 400

    @app.errorhandler(404)
    def not_found(err):
        return jsonify(error="not_found", message="Resource not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(err):
        return jsonify(error="method_not_allowed", message="Method not allowed"), 405

    @app.errorhandler(Exception)
    def server_error(err):
        logger.exception("Unhandled error")
        return jsonify(error="server_error", message=str(err)), 500

    def _limit(default=500):
        try:
            return max(1, min(int(request.args.get("limit", default)), 2000))
        except ValueError:
            return default

    # -------------------------------------------------------- routes
    @app.get("/api/health")
    def health():
        with db.get_connection() as conn:
            alerts = db.count_rows(conn, "alerts")
        return jsonify(status="ok", database=str(settings.DB_PATH), alerts=alerts,
                       pipeline=pipeline.STATUS)

    @app.get("/api/alerts")
    def list_alerts():
        severity = request.args.get("severity")
        if severity and severity.upper() not in db_severities():
            return jsonify(error="bad_request", message="severity must be one of "
                           f"{db_severities()}"), 400
        status = request.args.get("status")
        if status and status.upper() not in settings.ALERT_STATUSES:
            return jsonify(error="bad_request", message="status must be one of "
                           f"{settings.ALERT_STATUSES}"), 400
        with db.get_connection() as conn:
            alerts = db.query_alerts(
                conn, severity=severity, status=status,
                source_ip=request.args.get("source_ip"), search=request.args.get("search"),
                open_only=request.args.get("open_only", "").lower() == "true",
                limit=_limit())
        return jsonify(count=len(alerts), alerts=alerts)

    @app.get("/api/alerts/critical")
    def critical_alerts():
        with db.get_connection() as conn:
            alerts = db.query_alerts(conn, severity="CRITICAL",
                                     open_only=request.args.get("include_closed") != "true",
                                     limit=_limit())
        return jsonify(count=len(alerts), alerts=alerts)

    @app.get("/api/alerts/high-priority")
    def high_priority_alerts():
        """CRITICAL + HIGH alerts that are still open, most urgent first."""
        with db.get_connection() as conn:
            alerts = db.query_alerts(conn, severities=["CRITICAL", "HIGH"],
                                     open_only=request.args.get("include_closed") != "true",
                                     limit=_limit())
        return jsonify(count=len(alerts), alerts=alerts)

    @app.get("/api/alerts/<alert_id>")
    def one_alert(alert_id):
        with db.get_connection() as conn:
            alert = db.get_alert(conn, alert_id)
        if alert is None:
            return jsonify(error="not_found", message=f"Alert {alert_id} not found"), 404
        return jsonify(alert)

    @app.route("/api/alerts/<alert_id>/status", methods=["PATCH", "PUT", "POST"])
    def set_status(alert_id):
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or "status" not in body:
            return jsonify(error="bad_request",
                           message='JSON body with a "status" field is required'), 400
        new_status = str(body["status"]).upper()
        if new_status not in settings.ALERT_STATUSES:
            return jsonify(error="bad_request",
                           message=f"status must be one of {settings.ALERT_STATUSES}"), 400
        with db.get_connection() as conn:
            alert = db.update_alert_status(conn, alert_id, new_status, body.get("note"))
        if alert is None:
            return jsonify(error="not_found", message=f"Alert {alert_id} not found"), 404
        return jsonify(alert)

    @app.get("/api/stats")
    def stats():
        with db.get_connection() as conn:
            by_sev = db.severity_counts(conn)
            return jsonify(total_alerts=sum(by_sev.values()), by_severity=by_sev,
                           open_by_severity=db.severity_counts(conn, open_only=True),
                           by_status=db.status_counts(conn),
                           total_events=db.count_rows(conn, "security_events"))

    @app.get("/api/distribution")
    def distribution():
        with db.get_connection() as conn:
            return jsonify(severity=db.severity_counts(conn),
                           risk_score=db.risk_histogram(conn))

    @app.get("/api/trend")
    def trend():
        granularity = "day" if request.args.get("granularity") == "day" else "hour"
        with db.get_connection() as conn:
            return jsonify(granularity=granularity, trend=db.alert_trend(conn, granularity))

    @app.get("/api/events")
    def events():
        with db.get_connection() as conn:
            rows = db.recent_events(conn, limit=_limit(50))
        return jsonify(count=len(rows), events=rows)

    @app.get("/api/dashboard/summary")
    def dashboard_summary():
        with db.get_connection() as conn:
            by_sev = db.severity_counts(conn)
            open_sev = db.severity_counts(conn, open_only=True)
            return jsonify(
                total_alerts=sum(by_sev.values()),
                critical=by_sev["CRITICAL"], high=by_sev["HIGH"],
                medium=by_sev["MEDIUM"], low=by_sev["LOW"],
                open_alerts=sum(open_sev.values()),
                open_critical=open_sev["CRITICAL"],
                by_status=db.status_counts(conn),
                total_events=db.count_rows(conn, "security_events"),
                top_source_ips=db.top_source_ips(conn),
                pipeline=pipeline.STATUS)

    @app.post("/api/process")
    def process_now():
        """Run the log -> alert pipeline immediately."""
        return jsonify(pipeline.run_pipeline())

    @app.post("/api/sample/load")
    def load_sample():
        """Load the original data/alerts.csv sample alerts into the DB."""
        with db.get_connection() as conn:
            loaded = db.seed_sample_alerts(conn)
        return jsonify(loaded=loaded)

    # ------------------------------------------------ background worker
    if start_worker and settings.PROCESS_INTERVAL > 0:
        threading.Thread(target=_worker, daemon=True, name="log-processor").start()

    return app


def db_severities():
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _worker():
    while True:
        try:
            pipeline.run_pipeline()
        except Exception:
            pass  # already logged + stored in pipeline.STATUS["last_error"]
        time.sleep(settings.PROCESS_INTERVAL)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    application = create_app(start_worker=True)
    print(f"SIEM API on http://{settings.API_HOST}:{settings.API_PORT}  "
          f"(log: {settings.LOG_FILE}, db: {settings.DB_PATH})")
    # debug/reloader off: the reloader would start the worker thread twice
    application.run(host=settings.API_HOST, port=settings.API_PORT,
                    debug=False, use_reloader=False, threaded=True)

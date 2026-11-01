# Smart SIEM Alert Prioritization

Severity-based threat classification and SOC alert management.
A small, rule-based SIEM pipeline: security logs go in, scored and prioritised
alerts come out on a SOC dashboard. **There is no AI/ML in this project** - detection
and scoring are transparent, deterministic rules that you can explain in a viva.

```
 demo login app / log file
        │  (JSON lines, logs/security.log)
        ▼
 log_collector/log_reader.py     collect + parse
        ▼
 detection/event_analyzer.py     event analysis (running failures, events/min, attack type)
        ▼
 detection/threat_detector.py    threat detection rules + event correlation
        ▼
 scoring_engine.py               risk score 0-100  →  severity (CRITICAL/HIGH/MEDIUM/LOW)
        ▼
 alerts/alert_manager.py         priority (P1-P4), recommended action, explanation
        ▼
 database/db.py  (SQLite)        security_events, alerts, alert_history
        ▼
 backend/api.py  (Flask REST)    /api/...
        ▼
 app.py          (Streamlit)     SOC dashboard  →  security analyst
```

## Project structure

```
Security_Alert_Prioritization_System/
├── app.py                    SOC dashboard (Streamlit, reads the REST API only)
├── scoring_engine.py         risk score, severity thresholds, score breakdown (original, extended)
├── backend/api.py            Flask REST API + background log-processing worker
├── log_collector/            log reading + parsing
├── detection/                event_analyzer.py, threat_detector.py (rules)
├── alerts/                   alert_manager.py (classification), pipeline.py (end-to-end run)
├── database/db.py            SQLite schema + queries (+ `python -m database.db --init`)
├── config/settings.py        all settings, thresholds, asset criticality, threat-intel list
├── demo_app/login_app.py     practice login page that writes real log events
├── tools/generate_logs.py    creates the 6 demo scenarios
├── tests/                    unittest end-to-end + API tests (no extra packages)
├── logs/security.log         log source (JSON lines)
├── data/alerts.csv           original 20 sample alerts (can be loaded as sample data)
├── requirements.txt  .env.example  .gitignore
```

## Run it

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env   (optional - defaults work)
```

Use three terminals, all from the project root:

```bash
# 1) Backend API  (creates the SQLite DB automatically, processes the log every 5 s)
python -m backend.api

# 2) Dashboard
streamlit run app.py        # http://localhost:8501

# 3) Generate security logs
python tools/generate_logs.py --scenario all --reset
```

Within ~5 s the backend turns the new log lines into alerts; the dashboard refreshes itself
every 10 s (sidebar: change the interval, or press **Process logs now**).

Optional extras:

```bash
python -m database.db --init --seed-sample        # load the original data/alerts.csv as sample alerts
python demo_app/login_app.py                      # live login page on http://127.0.0.1:5000
```

Live attack demo against the login page (every request comes from 127.0.0.1, so for a
multi-IP demo set `DEMO_ALLOW_SIMULATED_IP=true` in `.env` and send a header):

```bash
for i in $(seq 1 8); do curl -s -X POST -d "username=admin&password=wrong" \
     -H "X-Simulated-Source-IP: 198.51.100.7" http://127.0.0.1:5000/login > /dev/null; done
```

## How the risk score works

`Risk Score = Severity × 0.40 + Asset Criticality × 0.30 + Event Context × 0.30` (0-100)

* **Severity** - base score of the detected behaviour (failed login 30, multiple failures 55,
  brute force 90, compromise 95, exfiltration 95, ransomware 100, ...).
* **Asset criticality** - from `ASSET_CRITICALITY` in `config/settings.py` (database 100, web app 80, laptop 45 ...).
* **Event context** (capped at 100): failed attempts (≥5 +15, ≥10 +25, ≥50 +35), known-malicious IP +30,
  after-hours +15, affected users (≥5 +10, ≥10 +20), privileged account +10, event frequency
  (≥20/min +10, ≥60/min +20), correlation with other detections from the same IP (1 → +15, ≥2 → +25).

**Severity thresholds** (the project's original ones, unchanged):
CRITICAL 90-100 · HIGH 70-89 · MEDIUM 40-69 · LOW 0-39.
**Priority**: CRITICAL → P1 Immediate, HIGH → P2 Urgent, MEDIUM → P3 Normal, LOW → P4 Low.

**Queue order**: severity, then risk score, event count (frequency), asset criticality, correlation count, newest first.

## Detection rules

| Rule | Trigger | Base severity |
|---|---|---|
| FAILED_LOGIN | 1-2 failures for one user+IP in 10 min | 30 |
| MULTIPLE_FAILED_LOGINS | 3-4 failures | 55 |
| BRUTE_FORCE_LOGIN | ≥5 failures (original threshold) | 90 |
| PASSWORD_SPRAYING | one IP failing against ≥3 users (≥5 failures) | 85 |
| ACCOUNT_COMPROMISE_SUSPECTED | successful login after ≥5 failures | 95 |
| SUSPICIOUS_AUTHENTICATION | successful login from a known-malicious IP | 80 |
| HIGH_FREQUENCY_ACTIVITY | ≥20 events from one IP within 60 s | 70 |
| RANSOMWARE / DATA_EXFILTRATION / PRIVILEGE_ESCALATION / SQL_INJECTION / MALWARE / PORT_SCAN | event types in the log | 100 / 95 / 90 / 85 / 85 / 55 |
| SUSPICIOUS_IP_ACTIVITY | other traffic from a known-malicious IP | 70 |

Alert ids are deterministic (hash of rule + IP + user), so re-processing the log updates an
alert (it can *escalate*, e.g. FAILED_LOGIN → BRUTE_FORCE_LOGIN) instead of duplicating it,
and analyst status/notes are never overwritten.

## Log format

One JSON object per line (unchanged from the original project):

```json
{"timestamp": "2026-10-04 18:11:07", "event_type": "LOGIN_FAILED", "username": "wrong", "source_ip": "127.0.0.1"}
```

Optional keys: `resource`, `destination_ip`, `description`, `affected_users`, `status`.
Malformed lines are skipped and logged, never fatal.

## REST API (default http://127.0.0.1:8000)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness + pipeline status |
| GET | `/api/alerts` | all alerts in priority order. Filters: `severity`, `status`, `source_ip`, `search`, `open_only`, `limit` |
| GET | `/api/alerts/critical` | open critical alerts |
| GET | `/api/alerts/high-priority` | open critical + high alerts |
| GET | `/api/alerts/<id>` | one alert incl. score breakdown + reasons |
| PATCH | `/api/alerts/<id>/status` | body `{"status": "INVESTIGATING", "note": "..."}` (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE) |
| GET | `/api/stats` | counts by severity / status |
| GET | `/api/distribution` | severity + risk-score distribution |
| GET | `/api/trend` | alerts per hour (`?granularity=day`) split by severity |
| GET | `/api/events` | recent security events |
| GET | `/api/dashboard/summary` | everything the KPI cards need |
| POST | `/api/process` | run the log → alert pipeline now |
| POST | `/api/sample/load` | load `data/alerts.csv` as sample alerts |

Errors are JSON: `{"error": "...", "message": "..."}` with 400/404/500 codes. CORS allows the origins in `SIEM_CORS_ORIGINS`.

## Test it

```bash
python -m unittest discover -s tests -t . -v     # 15 tests, no extra packages needed
```

Manual scenarios (`python tools/generate_logs.py --scenario <name> --reset`, timestamps default to today 10:00 = business hours):

| Scenario | Log events | Expected alert | Risk | Severity |
|---|---|---|---|---|
| `normal` | 1 successful login | none (event still stored) | - | - |
| `failed` | 1 failed login | FAILED_LOGIN | 36.0 | LOW |
| `multiple` | 4 failed logins, 1 user | MULTIPLE_FAILED_LOGINS | 46.0 | MEDIUM |
| `brute` | 12 failed logins on `admin` in 1 min | BRUTE_FORCE_LOGIN | 70.5 | HIGH |
| `frequency` | 90 web requests in ~30 s from one IP | HIGH_FREQUENCY_ACTIVITY | 58.0 | MEDIUM |
| `critical` | malicious IP: 60 failed logins → success → exfiltration → ransomware on Production Database | RANSOMWARE 95.5, DATA_EXFILTRATION 93.5, ACCOUNT_COMPROMISE 92.0, BRUTE_FORCE 90.0 (all CRITICAL / P1), plus HIGH_FREQUENCY 83.5 (HIGH) | ≥90 | CRITICAL |

Outside business hours (`--realtime` at night) the after-hours factor adds +4.5 points to the score.

## Notes and limits (be ready for these in a viva)

* Rule-based, not machine learning. Thresholds and weights live in `config/settings.py` and `scoring_engine.py`.
* The malicious-IP list is static demo threat intel; a real SOC would use a feed.
* The log is re-read in full on every run (events are de-duplicated) - fine for a demo, a production system would tail the file.
* SQLite is used because no database existed and it needs no server or credentials.
* The API has no authentication (the original project had none); add an API key/login before exposing it.
* `package-lock.json` in the original upload is empty and unused; it can be deleted.

---
Original project: risk-based alert triage dashboard built as an internship task by Harsha Patel.
#   S M A R T - S I E M - A L E R T - P R I O R I T I Z A T I O N  
 
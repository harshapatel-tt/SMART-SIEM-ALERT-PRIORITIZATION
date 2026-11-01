"""
Central configuration for the Smart SIEM Alert Prioritization project.

Every value can be overridden with an environment variable (or a `.env`
file in the project root - see `.env.example`). No secrets are hard-coded.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path):
    """Tiny .env loader (KEY=VALUE lines) so no extra dependency is needed.
    Real environment variables always win over the file."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _resolve(path_value):
    """Relative paths are resolved against the project root, not the CWD."""
    path = Path(path_value)
    return path if path.is_absolute() else BASE_DIR / path


# ---------------------------------------------------------------- paths
LOG_FILE = _resolve(os.environ.get("SIEM_LOG_FILE", "logs/security.log"))
DB_PATH = _resolve(os.environ.get("SIEM_DB_PATH", "database/siem.db"))
SAMPLE_ALERTS_CSV = BASE_DIR / "data" / "alerts.csv"

# ------------------------------------------------------------- services
API_HOST = os.environ.get("SIEM_API_HOST", "127.0.0.1")
API_PORT = _env_int("SIEM_API_PORT", 8000)
API_URL = os.environ.get("SIEM_API_URL", f"http://127.0.0.1:{API_PORT}")
# Origins allowed to call the API from a browser (comma separated, or "*")
CORS_ORIGINS = os.environ.get("SIEM_CORS_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501")
# Background log processing interval (seconds). 0 disables the worker.
PROCESS_INTERVAL = _env_int("SIEM_PROCESS_INTERVAL", 5)

# ------------------------------------------------------- demo login app
DEMO_APP_HOST = os.environ.get("DEMO_APP_HOST", "127.0.0.1")
DEMO_APP_PORT = _env_int("DEMO_APP_PORT", 5000)
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "admin")
# Demo-only credential for the practice login page. Change it in .env.
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "Admin@123")
DEMO_ALLOW_SIMULATED_IP = os.environ.get("DEMO_ALLOW_SIMULATED_IP", "false").lower() == "true"
DEMO_DEBUG = os.environ.get("DEMO_DEBUG", "false").lower() == "true"

# ------------------------------------------------- detection thresholds
# (BRUTE_FORCE threshold of 5 is the project's original value.)
FAILED_LOGIN_WINDOW_SECONDS = _env_int("SIEM_FAILED_WINDOW_SECONDS", 600)
MULTI_FAILED_THRESHOLD = 3     # 3-4 failures  -> MULTIPLE_FAILED_LOGINS
BRUTE_FORCE_THRESHOLD = 5      # >=5 failures  -> BRUTE_FORCE_LOGIN
SPRAY_USER_THRESHOLD = 3       # one IP failing against >=3 usernames
HIGH_FREQUENCY_THRESHOLD = 20  # events from one IP inside RATE_WINDOW
RATE_WINDOW_SECONDS = 60

# Business hours (24h clock). Activity outside is flagged "after hours".
BUSINESS_HOURS_START = 9
BUSINESS_HOURS_END = 18

# -------------------------------------------------------- threat context
# Static threat-intel list. In a real SOC this would come from a feed.
# 203.0.113.0/24 and 198.51.100.0/24 are documentation ranges (RFC 5737).
KNOWN_MALICIOUS_IPS = {
    ip.strip()
    for ip in os.environ.get(
        "SIEM_MALICIOUS_IPS",
        "185.44.12.10,45.12.88.21,91.22.15.44,203.0.113.66,203.0.113.99",
    ).split(",")
    if ip.strip()
}

# Asset criticality (0-100) by resource name. Unknown resources get default.
ASSET_CRITICALITY = {
    "Demo Web Application": 80,
    "Production Database": 100,
    "Payment Database": 100,
    "Database Server": 100,
    "Payment Server": 100,
    "Customer Database": 90,
    "Domain Controller": 95,
    "Admin Server": 95,
    "Production Server": 90,
    "Web Server": 85,
    "Finance Workstation": 70,
    "Employee Laptop": 45,
    "Test Machine": 20,
}
DEFAULT_ASSET_CRITICALITY = 50
DEFAULT_RESOURCE = "Demo Web Application"

# Accounts whose compromise matters more (user importance).
PRIVILEGED_USERS = {"admin", "administrator", "root", "sysadmin"}

# Non-authentication security events and how they are treated.
# base_severity is the 0-100 "Severity" input of the scoring formula.
EVENT_PROFILES = {
    "RANSOMWARE_DETECTED":  {"alert_type": "Ransomware Detection",  "base_severity": 100},
    "DATA_EXFILTRATION":    {"alert_type": "Data Exfiltration",     "base_severity": 95},
    "PRIVILEGE_ESCALATION": {"alert_type": "Privilege Escalation",  "base_severity": 90},
    "SQL_INJECTION":        {"alert_type": "SQL Injection",         "base_severity": 85},
    "MALWARE_DETECTED":     {"alert_type": "Malware Detection",     "base_severity": 85},
    "PORT_SCAN":            {"alert_type": "Port Scan",             "base_severity": 55},
}

# Alert statuses an analyst can set.
ALERT_STATUSES = ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
CLOSED_STATUSES = ["RESOLVED", "FALSE_POSITIVE"]

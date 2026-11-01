"""
Turns candidate alerts into complete, scored, classified alerts.

  candidate -> risk score (scoring_engine) -> severity label
            -> priority (P1..P4) -> recommended action -> alert record

Everything is rule-based and deterministic.
"""

import json
from datetime import datetime

from scoring_engine import (
    SEVERITY_RANK,
    calculate_risk_score,
    get_priority_label,
    get_priority_reason,
    get_score_breakdown,
    get_severity,
)

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

RECOMMENDED_ACTIONS = {
    "FAILED_LOGIN": "Monitor the account; no action unless attempts repeat.",
    "MULTIPLE_FAILED_LOGINS": "Verify with the user; consider a temporary lockout or MFA prompt.",
    "BRUTE_FORCE_LOGIN": "Block or rate-limit the source IP, force a password reset and review the account's recent activity.",
    "PASSWORD_SPRAYING": "Block the source IP, enforce MFA and check all targeted accounts for successful logins.",
    "ACCOUNT_COMPROMISE_SUSPECTED": "Disable the account and kill active sessions, reset credentials, and start incident response.",
    "SUSPICIOUS_AUTHENTICATION": "Verify the login with the user, revoke the session and block the source IP.",
    "HIGH_FREQUENCY_ACTIVITY": "Apply rate limiting / WAF rule for the source IP and inspect the requests for abuse.",
    "SUSPICIOUS_IP_ACTIVITY": "Block the known-malicious IP at the firewall and search for other activity from it.",
    "RANSOMWARE_DETECTED": "Isolate the affected hosts from the network immediately, preserve evidence and activate the ransomware playbook.",
    "DATA_EXFILTRATION": "Block the outbound channel, isolate the source host and assess what data left the environment.",
    "PRIVILEGE_ESCALATION": "Revoke elevated rights, investigate how access was gained and audit admin actions.",
    "SQL_INJECTION": "Block the source IP, review WAF/application logs and patch the vulnerable input.",
    "MALWARE_DETECTED": "Quarantine the endpoint, run a full scan and collect the sample for analysis.",
    "PORT_SCAN": "Monitor the source and block it if scanning continues.",
}

SEVERITY_PREFIX = {
    "CRITICAL": "IMMEDIATE: ",
    "HIGH": "URGENT: ",
    "MEDIUM": "",
    "LOW": "",
}


def _fmt(ts):
    return ts.strftime(TS_FORMAT) if isinstance(ts, datetime) else str(ts)


def build_alert(candidate, source="log"):
    """Score and classify one candidate alert. Returns a DB-ready dict."""
    risk_score = calculate_risk_score(candidate)
    severity = get_severity(risk_score)
    action = RECOMMENDED_ACTIONS.get(
        candidate["alert_type"], "Investigate the event and escalate if it is confirmed.")

    return {
        "alert_id": candidate["alert_id"],
        "timestamp": _fmt(candidate["timestamp"]),
        "last_seen": _fmt(candidate.get("last_seen", candidate["timestamp"])),
        "alert_type": candidate["alert_type"],
        "event_type": candidate.get("event_type", candidate["alert_type"]),
        "source_ip": candidate["source_ip"],
        "destination_ip": candidate.get("destination_ip"),
        "username": candidate.get("username"),
        "asset": candidate["asset"],
        "description": candidate["description"],
        # scoring inputs, stored so the score can always be explained
        "event_severity": candidate["severity"],
        "asset_criticality": candidate["asset_criticality"],
        "failed_attempts": candidate["failed_attempts"],
        "malicious_ip": candidate["malicious_ip"],
        "after_hours": candidate["after_hours"],
        "affected_users": candidate["affected_users"],
        "correlated_events": candidate.get("correlated_events", 0),
        "event_count": candidate.get("event_count", 1),
        "peak_rate_per_min": candidate.get("peak_rate_per_min", 0),
        # results
        "risk_score": risk_score,
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "priority": get_priority_label(severity),
        "recommended_action": SEVERITY_PREFIX[severity] + action,
        "reasons": json.dumps(get_priority_reason(candidate, risk_score)),
        "score_breakdown": json.dumps(get_score_breakdown(candidate)),
        "source": source,
    }

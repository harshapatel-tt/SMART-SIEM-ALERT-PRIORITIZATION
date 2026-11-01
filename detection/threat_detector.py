"""
Rule-based threat detection (no machine learning).

detect_threats() turns analysed events into *candidate alerts*. Each
candidate carries the inputs the scoring engine needs (severity,
asset_criticality, failed_attempts, malicious_ip, after_hours,
affected_users, ...). Scoring and severity labelling happen later in
alerts/alert_manager.py.

Rules
  1. Failed logins per (source IP, user) inside a time window
       1-2  -> FAILED_LOGIN             (low-signal)
       3-4  -> MULTIPLE_FAILED_LOGINS
       >=5  -> BRUTE_FORCE_LOGIN        (original project threshold)
  2. Password spraying: one IP failing against >=3 different users
  3. Suspicious authentication: success after a brute force, or a
     success coming from a known-malicious IP
  4. Abnormal event frequency: many events from one IP in 60 s
  5. High-risk event types (ransomware, exfiltration, ...)
  6. Suspicious IP activity: any traffic from a known-malicious IP that
     no other rule has already explained
  Finally, event correlation: how many *different* detections share the
  same source IP.
"""

import hashlib
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402
from detection.event_analyzer import enrich_events  # noqa: E402
from log_collector.log_reader import read_logs  # noqa: E402

# Kept for backwards compatibility with the original module name.
FAILED_LOGIN_THRESHOLD = settings.BRUTE_FORCE_THRESHOLD


def _alert_id(prefix, *parts):
    """Deterministic id: the same incident always maps to the same alert,
    so re-processing the log updates the alert instead of duplicating it."""
    digest = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def _peak_in_window(times, seconds):
    """Largest number of timestamps that fall inside any `seconds` window."""
    times = sorted(times)
    best, start = 0, 0
    for end, t in enumerate(times):
        while (t - times[start]).total_seconds() > seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def _is_after_hours(ts):
    return not (settings.BUSINESS_HOURS_START <= ts.hour < settings.BUSINESS_HOURS_END)


def _candidate(alert_id, category, alert_type, events, severity, description,
               failed_attempts=0, affected_users=1, username=None):
    """Build a candidate alert from the events that triggered it."""
    first, last = events[0], events[-1]
    resource = last["resource"]
    ip = first["source_ip"]
    user = username if username is not None else first["username"]
    peak_rate = max(e["ip_events_per_minute"] for e in events)
    return {
        "alert_id": alert_id,
        "category": category,
        "alert_type": alert_type,
        "event_type": last["event_type"],
        "timestamp": first["timestamp"],
        "last_seen": last["timestamp"],
        "source_ip": ip,
        "destination_ip": last.get("destination_ip"),
        "username": user,
        "asset": resource,
        # --- scoring inputs (names match scoring_engine.py) ---
        "severity": severity,
        "asset_criticality": settings.ASSET_CRITICALITY.get(
            resource, settings.DEFAULT_ASSET_CRITICALITY),
        "failed_attempts": failed_attempts,
        "malicious_ip": 1 if ip in settings.KNOWN_MALICIOUS_IPS else 0,
        "after_hours": 1 if _is_after_hours(last["timestamp"]) else 0,
        "affected_users": affected_users,
        "privileged_user": 1 if str(user).lower() in settings.PRIVILEGED_USERS else 0,
        "peak_rate_per_min": peak_rate,
        "correlated_events": 0,          # filled in by _correlate()
        "event_count": len(events),
        "description": description,
    }


def _correlate(candidates):
    """Event correlation: other *distinct* detection categories that share
    the same source IP (capped at 3)."""
    categories_by_ip = defaultdict(set)
    for c in candidates:
        categories_by_ip[c["source_ip"]].add(c["category"])
    for c in candidates:
        c["correlated_events"] = min(len(categories_by_ip[c["source_ip"]]) - 1, 3)


def detect_threats(events=None):
    """Run every rule. If `events` is None the configured log is read."""
    if events is None:
        events = read_logs()
    events = enrich_events(sorted(events, key=lambda e: e["timestamp"]))

    candidates = []

    # Group events once, reuse for the rules below.
    by_pair = defaultdict(list)   # (ip, user) -> auth events
    by_ip = defaultdict(list)     # ip -> all events
    for e in events:
        by_ip[e["source_ip"]].append(e)
        if e["event_type"] in ("LOGIN_FAILED", "LOGIN_SUCCESS"):
            by_pair[(e["source_ip"], e["username"])].append(e)

    # ---- Rule 1: failed logins per (ip, user) ----------------------
    failing_users_by_ip = defaultdict(dict)   # ip -> {user: peak failures}
    for (ip, user), evs in by_pair.items():
        fails = [e for e in evs if e["event_type"] == "LOGIN_FAILED"]
        if not fails:
            continue
        peak = _peak_in_window([e["timestamp"] for e in fails],
                               settings.FAILED_LOGIN_WINDOW_SECONDS)
        failing_users_by_ip[ip][user] = peak

        if peak >= settings.BRUTE_FORCE_THRESHOLD:
            category, alert_type, sev = "auth_failure", "BRUTE_FORCE_LOGIN", 90
            desc = f"{peak} failed logins for user '{user}' from {ip} within " \
                   f"{settings.FAILED_LOGIN_WINDOW_SECONDS // 60} minutes (brute-force behaviour)"
        elif peak >= settings.MULTI_FAILED_THRESHOLD:
            category, alert_type, sev = "auth_failure", "MULTIPLE_FAILED_LOGINS", 55
            desc = f"{peak} failed logins for user '{user}' from {ip}"
        else:
            category, alert_type, sev = "auth_failure", "FAILED_LOGIN", 30
            desc = f"{peak} failed login for user '{user}' from {ip}"

        candidates.append(_candidate(
            _alert_id("AUTH", ip, user), category, alert_type, fails, sev, desc,
            failed_attempts=peak, username=user))

    # ---- Rule 2: password spraying ---------------------------------
    for ip, users in failing_users_by_ip.items():
        total = sum(users.values())
        if len(users) >= settings.SPRAY_USER_THRESHOLD and total >= settings.BRUTE_FORCE_THRESHOLD:
            fails = [e for e in by_ip[ip] if e["event_type"] == "LOGIN_FAILED"]
            candidates.append(_candidate(
                _alert_id("SPRAY", ip), "password_spray", "PASSWORD_SPRAYING", fails, 85,
                f"{total} failed logins from {ip} spread over {len(users)} different accounts",
                failed_attempts=total, affected_users=len(users), username="multiple"))

    # ---- Rule 3: suspicious authentication -------------------------
    for (ip, user), evs in by_pair.items():
        for i, e in enumerate(evs):
            if e["event_type"] != "LOGIN_SUCCESS":
                continue
            prior_fails = [x for x in evs[:i] if x["event_type"] == "LOGIN_FAILED"
                           and (e["timestamp"] - x["timestamp"]).total_seconds()
                           <= settings.FAILED_LOGIN_WINDOW_SECONDS]
            if len(prior_fails) >= settings.BRUTE_FORCE_THRESHOLD:
                candidates.append(_candidate(
                    _alert_id("COMPROMISE", ip, user), "account_compromise",
                    "ACCOUNT_COMPROMISE_SUSPECTED", prior_fails + [e], 95,
                    f"Successful login for '{user}' from {ip} right after "
                    f"{len(prior_fails)} failed attempts - account may be compromised",
                    failed_attempts=len(prior_fails)))
                break
            if ip in settings.KNOWN_MALICIOUS_IPS:
                candidates.append(_candidate(
                    _alert_id("SUSPAUTH", ip, user), "suspicious_auth",
                    "SUSPICIOUS_AUTHENTICATION", [e], 80,
                    f"Successful login for '{user}' from known-malicious IP {ip}"))
                break

    # ---- Rule 4: abnormal event frequency --------------------------
    for ip, evs in by_ip.items():
        peak = _peak_in_window([e["timestamp"] for e in evs], settings.RATE_WINDOW_SECONDS)
        if peak >= settings.HIGH_FREQUENCY_THRESHOLD:
            candidates.append(_candidate(
                _alert_id("FREQ", ip), "high_frequency", "HIGH_FREQUENCY_ACTIVITY", evs, 70,
                f"{peak} events from {ip} within {settings.RATE_WINDOW_SECONDS}s "
                f"(abnormal event frequency)",
                username=evs[0]["username"] if len({e["username"] for e in evs}) == 1
                else "multiple"))

    # ---- Rule 5: high-risk event types -----------------------------
    groups = defaultdict(list)    # (event_type, ip, resource) -> events
    for e in events:
        if e["event_type"] in settings.EVENT_PROFILES:
            groups[(e["event_type"], e["source_ip"], e["resource"])].append(e)
    for (etype, ip, resource), evs in groups.items():
        profile = settings.EVENT_PROFILES[etype]
        affected = max([e["affected_users"] or 1 for e in evs])
        desc = next((e["description"] for e in evs if e["description"]), "") or \
            f"{profile['alert_type']} detected on {resource} from {ip}"
        candidates.append(_candidate(
            _alert_id("EVT", etype, ip, resource), "high_risk_event", etype, evs,
            profile["base_severity"], desc, affected_users=affected))

    # ---- Rule 6: unexplained traffic from a known-malicious IP -----
    explained = {c["source_ip"] for c in candidates}
    for ip, evs in by_ip.items():
        if ip in settings.KNOWN_MALICIOUS_IPS and ip not in explained:
            candidates.append(_candidate(
                _alert_id("MALIP", ip), "suspicious_ip", "SUSPICIOUS_IP_ACTIVITY", evs, 70,
                f"{len(evs)} event(s) from known-malicious IP {ip}"))

    _correlate(candidates)
    return candidates


if __name__ == "__main__":
    alerts = detect_threats()

    print("\nThreat Detection Results")
    print("------------------------")

    if not alerts:
        print("No threats detected.")

    for alert in alerts:
        print("\nThreat Detected!")
        print("Alert ID:", alert["alert_id"])
        print("Type:", alert["alert_type"])
        print("Username:", alert["username"])
        print("Source IP:", alert["source_ip"])
        print("Failed Attempts:", alert["failed_attempts"])
        print("Base severity score:", alert["severity"])

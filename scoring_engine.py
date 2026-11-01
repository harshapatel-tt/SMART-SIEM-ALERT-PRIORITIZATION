def calculate_context_score(alert):
    """
    Builds the event-context score from supporting signals.
    Caps the value at 100.
    """

    score = 0

    
    if alert["failed_attempts"] >= 50:
        score += 35
    elif alert["failed_attempts"] >= 10:
        score += 25
    elif alert["failed_attempts"] >= 5:
        score += 15

    
    if alert["malicious_ip"] == 1:
        score += 30

   
    if alert["after_hours"] == 1:
        score += 15

    if alert["affected_users"] >= 10:
        score += 20
    elif alert["affected_users"] >= 5:
        score += 10

    # ---- Optional signals produced by the log-based detection pipeline.
    # They use .get(..., 0) so alerts without them (e.g. data/alerts.csv)
    # keep exactly the same score as before.

    # Privileged / high-importance account targeted (admin, root, ...)
    if alert.get("privileged_user", 0) == 1:
        score += 10

    # Attack frequency: peak events per minute from the source
    peak_rate = alert.get("peak_rate_per_min", 0)
    if peak_rate >= 60:
        score += 20
    elif peak_rate >= 20:
        score += 10

    # Event correlation: other, different detections from the same source
    correlated = alert.get("correlated_events", 0)
    if correlated >= 2:
        score += 25
    elif correlated == 1:
        score += 15

    return min(score, 100)


def calculate_threat_score(alert):
    """
    Computes a threat-indicator score and caps it at 100.

    Kept as an extra indicator for analysts.
    """

    score = 0

    if alert["malicious_ip"] == 1:
        score += 60

    if alert["failed_attempts"] >= 50:
        score += 40
    elif alert["failed_attempts"] >= 10:
        score += 25

    return min(score, 100)


def calculate_risk_score(alert):
    """
    Calculates the final security risk score.

    Core prioritization factors:
    Severity          = 40%
    Asset Importance  = 30%
    Event Context     = 30%

    Threat indicators are included inside
    the Event Context calculation.
    """

    # How severe the alert itself is
    severity_score = alert["severity"]

    # Business criticality of the impacted asset
    asset_importance_score = alert["asset_criticality"]

    # Supporting context around this event
    event_context_score = calculate_context_score(alert)

    # Weighted final score
    risk_score = (
        severity_score * 0.40
        + asset_importance_score * 0.30
        + event_context_score * 0.30
    )

    return round(risk_score, 2)


def get_priority(score):
    """
    Maps a risk score into a priority label.
    """

    if score >= 90:
        return "CRITICAL"

    elif score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def get_score_breakdown(alert):
    """
    Returns the weighted score breakdown used in the final result.
    """

    severity_score = alert["severity"]
    asset_importance_score = alert["asset_criticality"]
    event_context_score = calculate_context_score(alert)

    severity_contribution = severity_score * 0.40
    asset_contribution = asset_importance_score * 0.30
    context_contribution = event_context_score * 0.30

    final_score = (
        severity_contribution
        + asset_contribution
        + context_contribution
    )

    return {
        "severity_score": severity_score,
        "severity_contribution": round(severity_contribution, 2),
        "asset_score": asset_importance_score,
        "asset_contribution": round(asset_contribution, 2),
        "context_score": event_context_score,
        "context_contribution": round(context_contribution, 2),
        "final_score": round(final_score, 2),
    }


def get_priority_reason(alert, score):
    """
    Builds readable reasons for the alert's assigned priority.
    """

    reasons = []

    if alert["severity"] >= 80:
        reasons.append("High severity event")

    if alert["asset_criticality"] >= 80:
        reasons.append("Critical/high-value asset")

    if alert["malicious_ip"] == 1:
        reasons.append("Known malicious IP")

    if alert["failed_attempts"] >= 10:
        reasons.append("Repeated authentication attempts")

    if alert["after_hours"] == 1:
        reasons.append("Activity outside business hours")

    if alert["affected_users"] >= 5:
        reasons.append("Multiple users affected")

    if alert.get("privileged_user", 0) == 1:
        reasons.append("Privileged account targeted")

    if alert.get("peak_rate_per_min", 0) >= 20:
        reasons.append("High event frequency from source")

    if alert.get("correlated_events", 0) >= 1:
        reasons.append("Correlated with other detections from same source")

    if not reasons:
        reasons.append("No major risk indicators detected")

    return reasons


# Severity label ordering used for sorting (1 = most urgent)
SEVERITY_RANK = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

# SOC triage priority derived from the severity label
PRIORITY_LABEL = {
    "CRITICAL": "P1 - Immediate",
    "HIGH": "P2 - Urgent",
    "MEDIUM": "P3 - Normal",
    "LOW": "P4 - Low",
}


def get_severity(score):
    """
    Severity label for a risk score. Uses the same thresholds as
    get_priority() so there is a single source of truth
    (CRITICAL >= 90, HIGH >= 70, MEDIUM >= 40, LOW < 40).
    """
    return get_priority(score)


def get_priority_label(severity):
    """Maps a severity label to a SOC triage priority (P1..P4)."""
    return PRIORITY_LABEL.get(severity, "P4 - Low")

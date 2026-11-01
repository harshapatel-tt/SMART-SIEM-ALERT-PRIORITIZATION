"""
Risk scoring engine for the Security Alert Prioritization System.

Final score (0-100):

    Risk Score = Severity x 0.40 + Asset Criticality x 0.30 + Event Context x 0.30

Event Context is built from supporting signals (failed attempts, malicious IP,
after-hours activity, number of affected users) and is capped at 100.
"""

# Weights used for the final score. They must add up to 1.0.
SEVERITY_WEIGHT = 0.40
ASSET_WEIGHT = 0.30
CONTEXT_WEIGHT = 0.30

# Priority thresholds (minimum score for each level, checked top-down).
PRIORITY_THRESHOLDS = (
    ("CRITICAL", 90),
    ("HIGH", 70),
    ("MEDIUM", 40),
)
LOWEST_PRIORITY = "LOW"


def _value(alert, key, default=0):
    """
    Reads a numeric field from a dict or pandas row.

    Missing or NaN values fall back to `default` so one bad row
    cannot break the whole dashboard.
    """
    try:
        value = alert.get(key, default)
    except AttributeError:
        value = default

    if value is None or value != value:  # None or NaN
        return default

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value, low=0, high=100):
    return max(low, min(high, value))


def calculate_context_score(alert):
    """
    Builds the event-context score from supporting signals.
    Caps the value at 100.
    """

    score = 0

    failed_attempts = _value(alert, "failed_attempts")
    if failed_attempts >= 50:
        score += 35
    elif failed_attempts >= 10:
        score += 25
    elif failed_attempts >= 5:
        score += 15

    if _value(alert, "malicious_ip") == 1:
        score += 30

    if _value(alert, "after_hours") == 1:
        score += 15

    affected_users = _value(alert, "affected_users")
    if affected_users >= 10:
        score += 20
    elif affected_users >= 5:
        score += 10

    return min(score, 100)


def calculate_threat_score(alert):
    """
    Computes a threat-indicator score and caps it at 100.

    Kept as an extra indicator for analysts. It is shown next to the
    risk score but is not part of the weighted formula.
    """

    score = 0

    if _value(alert, "malicious_ip") == 1:
        score += 60

    failed_attempts = _value(alert, "failed_attempts")
    if failed_attempts >= 50:
        score += 40
    elif failed_attempts >= 10:
        score += 25

    return min(score, 100)


def calculate_risk_score(alert):
    """
    Calculates the final security risk score.

    Core prioritization factors:
        Severity          = 40%
        Asset Importance  = 30%
        Event Context     = 30%

    Threat indicators are included inside the Event Context calculation.
    """

    severity_score = _clamp(_value(alert, "severity"))
    asset_importance_score = _clamp(_value(alert, "asset_criticality"))
    event_context_score = calculate_context_score(alert)

    risk_score = (
        severity_score * SEVERITY_WEIGHT
        + asset_importance_score * ASSET_WEIGHT
        + event_context_score * CONTEXT_WEIGHT
    )

    return round(risk_score, 2)


def get_priority(score):
    """
    Maps a risk score into a priority label.
    """

    for label, minimum in PRIORITY_THRESHOLDS:
        if score >= minimum:
            return label

    return LOWEST_PRIORITY


def get_score_breakdown(alert):
    """
    Returns the weighted score breakdown used in the final result.
    """

    severity_score = _clamp(_value(alert, "severity"))
    asset_importance_score = _clamp(_value(alert, "asset_criticality"))
    event_context_score = calculate_context_score(alert)

    severity_contribution = severity_score * SEVERITY_WEIGHT
    asset_contribution = asset_importance_score * ASSET_WEIGHT
    context_contribution = event_context_score * CONTEXT_WEIGHT

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


def get_priority_reason(alert, score=None):
    """
    Builds readable reasons for the alert's assigned priority.

    `score` is accepted for backwards compatibility and is not needed.
    """

    reasons = []

    if _value(alert, "severity") >= 80:
        reasons.append("High severity event")

    if _value(alert, "asset_criticality") >= 80:
        reasons.append("Critical/high-value asset")

    if _value(alert, "malicious_ip") == 1:
        reasons.append("Known malicious IP")

    if _value(alert, "failed_attempts") >= 5:
        reasons.append("Repeated authentication attempts")

    if _value(alert, "after_hours") == 1:
        reasons.append("Activity outside business hours")

    if _value(alert, "affected_users") >= 5:
        reasons.append("Multiple users affected")

    if not reasons:
        reasons.append("No major risk indicators detected")

    return reasons

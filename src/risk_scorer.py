"""Explainable risk scoring for PhishTrace email investigations."""

from typing import Any


SEVERITY_POINTS = {
    "informational": 0,
    "low": 10,
    "medium": 25,
    "high": 40,
    "critical": 50,
}


def calculate_risk(
    header_results: dict[str, Any],
    ioc_results: dict[str, Any],
    authentication_results: dict[str, Any],
    reputation_results: dict[str, Any],
) -> dict[str, Any]:
    """Calculate a transparent 0-100 risk score from investigation evidence."""

    score = 0
    reasons = []
    indicators = set()

    # 1. Score suspicious email-header findings.
    for finding in header_results.get("findings", []):
        indicator = finding.get("indicator", "Unspecified header finding")
        severity = str(finding.get("severity", "informational")).lower()
        points = SEVERITY_POINTS.get(severity, 0)

        if points > 0 and indicator not in indicators:
            score += points
            indicators.add(indicator)
            reasons.append({
                "indicator": indicator,
                "source": "header_analysis",
                "severity": severity,
                "points": points,
                "explanation": finding.get("detail", indicator),
            })

    # 2. Consider authentication failures only when explicitly reported.
    for mechanism, result in authentication_results.items():
        if not isinstance(result, dict):
            continue

        status = str(result.get("status", "UNKNOWN")).upper()

        if status in {"FAIL", "FAILED"}:
            indicator = f"{mechanism} authentication failed"

            if indicator not in indicators:
                points = 20
                score += points
                indicators.add(indicator)
                reasons.append({
                    "indicator": indicator,
                    "source": "authentication_analysis",
                    "severity": "medium",
                    "points": points,
                    "explanation": (
                        f"{mechanism} was reported as failed in the "
                        "supplied authentication evidence."
                    ),
                })

    # 3. Consider reputation results from VirusTotal.
    reputation_items = (
        reputation_results.get("url_results", [])
        + reputation_results.get("domain_results", [])
    )

    for item in reputation_items:
        if not isinstance(item, dict):
            continue

        status = str(item.get("status", "UNKNOWN")).upper()
        indicator = str(item.get("indicator", "Unknown indicator"))

        if status == "MALICIOUS":
            points = 50

            if indicator not in indicators:
                score += points
                indicators.add(indicator)
                reasons.append({
                    "indicator": indicator,
                    "source": "reputation_analysis",
                    "severity": "critical",
                    "points": points,
                    "explanation": (
                        "The reputation provider classified this indicator "
                        "as malicious."
                    ),
                })

        elif status == "SUSPICIOUS":
            points = 25

            if indicator not in indicators:
                score += points
                indicators.add(indicator)
                reasons.append({
                    "indicator": indicator,
                    "source": "reputation_analysis",
                    "severity": "medium",
                    "points": points,
                    "explanation": (
                        "The reputation provider classified this indicator "
                        "as suspicious."
                    ),
                })

    # Cap the total score at 100.
    score = min(score, 100)

    if score >= 75:
        risk_level = "Critical"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
        "reason_count": len(reasons),
        "reasons": reasons,
        "scoring_note": (
            "This is a transparent heuristic score, not a calibrated "
            "probability of phishing. Missing evidence does not mean safe."
        ),
    }

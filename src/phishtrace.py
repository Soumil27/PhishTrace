import re
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from email_parser import parse_email
from header_analyzer import analyze_headers
from ioc_extractor import extract_iocs
from authentication import analyze_authentication
from reputation import check_reputation
from risk_scorer import calculate_risk


def investigate(email_path):
    email_path = Path(email_path).resolve()

    email_data = parse_email(email_path)
    header_results = analyze_headers(email_data)
    ioc_results = extract_iocs(email_path)
    auth_results = analyze_authentication(email_data)

    # Look up extracted indicators using VirusTotal's existing reports.
    # These calls do not upload the email or visit extracted URLs.
    reputation_results = {
        "url_results": [
            check_reputation(url, "url")
            for url in ioc_results.get("urls", [])
        ],
        "domain_results": [
            check_reputation(domain, "domain")
            for domain in ioc_results.get("domains", [])
        ],
        "note": (
            "Reputation lookups use existing VirusTotal reports only. "
            "UNKNOWN means no usable verdict was obtained; it does not "
            "mean the indicator is safe."
        ),
    }

    indicators = list(header_results.get("findings", []))

    # Add one explainable indicator for high-risk subject wording.
    subject_text = str(email_data.get("subject", "")).casefold()
    subject_patterns = (
        "urgent",
        "verify your account",
        "account will be suspended",
        "immediately",
        "password expires",
        "unusual activity",
    )
    matched_subject_terms = [
        term for term in subject_patterns if term in subject_text
    ]
    if matched_subject_terms:
        indicators.append({
            "indicator": "High-risk subject wording",
            "severity": "low",
            "detail": (
                "Subject contains risk-related wording: "
                + ", ".join(matched_subject_terms)
                + ". This is a heuristic signal, not proof of phishing."
            ),
        })
    concerning = [
        item for item in indicators
        if str(item.get("severity", "")).lower()
        in ("medium", "high", "critical")
    ]

    # Adapt reputation results for the shared explainable risk scorer.
    scoring_reputation = {
        "url_results": [dict(x) for x in reputation_results.get("url_results", [])],
        "domain_results": [dict(x) for x in reputation_results.get("domain_results", [])],
    }

    for item in (
        scoring_reputation["url_results"]
        + scoring_reputation["domain_results"]
    ):
        if str(item.get("status", "")).upper() == "REVIEW":
            malicious = int(item.get("malicious", 0) or 0)
            suspicious = int(item.get("suspicious", 0) or 0)
            if malicious > 0:
                item["status"] = "MALICIOUS"
            elif suspicious > 0:
                item["status"] = "SUSPICIOUS"

    # Combine email body context and links using explainable heuristics.
    raw_email = Path(email_path).read_text(encoding="utf-8", errors="replace")
    normalized_email = raw_email.replace("\r\n", "\n").replace("\r", "\n")
    parts = re.split(r"\n\s*\n", normalized_email, maxsplit=1)
    body_text = parts[1].casefold() if len(parts) > 1 else ""
    has_link = bool(re.search(r"https?://\S+", body_text))

    account_terms = (
        "account", "password", "credential", "sign in", "verify your",
        "review your details", "account information", "account document",
        "profile", "billing", "security notice",
    )
    action_terms = (
        "review", "verify", "confirm", "reply", "provide", "update",
        "complete your request", "details", "document", "information",
    )
    urgency_terms = (
        "urgent", "immediately", "suspended", "expires",
        "act now", "within 24 hours",
    )

    has_account_context = any(term in body_text for term in account_terms)
    has_action_context = any(term in body_text for term in action_terms)
    has_urgency = any(term in body_text for term in urgency_terms)

    if has_link and has_account_context:
        indicators.append({
            "indicator": "Account-related message contains a link",
            "severity": "medium",
            "detail": (
                "The email body combines account-related wording with a URL. "
                "This warrants review but does not prove phishing."
            ),
        })
    elif has_account_context and has_action_context:
        indicators.append({
            "indicator": "Account-related request without a link",
            "severity": "low",
            "detail": (
                "The message discusses an account and requests an action or "
                "response. Legitimate messages can do this too."
            ),
        })

    if has_urgency and (has_link or (has_account_context and has_action_context)):
        indicators.append({
            "indicator": "Urgency combined with account-related content",
            "severity": "low",
            "detail": (
                "Urgent language appears alongside account-related content "
                "or a link. This is a heuristic signal, not proof of phishing."
            ),
        })
    shared_score = calculate_risk(
        {"findings": indicators},
        ioc_results,
        auth_results,
        scoring_reputation,
    )

    risk_score = shared_score["score"]
    risk_level = shared_score["risk_level"]
    risk_reasons = [
        {
            "finding": item["indicator"],
            "severity": item["severity"].capitalize(),
            "points_added": item["points"],
            "explanation": item["explanation"],
            "source": item["source"],
        }
        for item in shared_score["reasons"]
    ]

    # A REVIEW status alone is not evidence of maliciousness.
    # Use actual malicious/suspicious detections alongside email indicators.
    reputation_flags = any(
        int(result.get("malicious", 0) or 0) > 0
        or int(result.get("suspicious", 0) or 0) > 0
        for result in (
            reputation_results["url_results"]
            + reputation_results["domain_results"]
        )
    )

    # Recalculate after body-based indicators have been added.
    concerning = [
        item for item in indicators
        if str(item.get("severity", "")).lower()
        in ("medium", "high", "critical")
    ]

    if concerning or reputation_flags:
        verdict = "Suspicious - further investigation required"
    else:
        verdict = "No configured indicators detected"

    return {
        "project": "PhishTrace",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": email_path.name,
        "email_details": email_data,
        "header_analysis": header_results,
        "ioc_analysis": ioc_results,
        "authentication_analysis": auth_results,
        "reputation_analysis": reputation_results,
        "overall_assessment": {
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
            "concerning_header_indicators": len(concerning),
            "url_count": ioc_results.get("url_count", 0),
            "domain_count": ioc_results.get("domain_count", 0),
            "limitations": [
                "This assessment is a triage aid, not proof of maliciousness.",
                "Authentication results are parsed from supplied headers and are not independently verified.",
                "URL extraction does not establish URL reputation.",
                "Recipient impact cannot be established from an email file alone.",
                "VirusTotal results depend on existing records and API availability.",
            ],
        },
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python src/phishtrace.py <email.eml>")
        sys.exit(1)

    try:
        report = investigate(sys.argv[1])

        reports_dir = Path(__file__).resolve().parents[1] / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_path = reports_dir / "investigation_report.json"

        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print(f"Investigation complete: {report['overall_assessment']['verdict']}")
        print(f"URLs found: {report['overall_assessment']['url_count']}")
        print(f"Domains found: {report['overall_assessment']['domain_count']}")
        print("VirusTotal URL results:", len(report["reputation_analysis"]["url_results"]))
        print("VirusTotal domain results:", len(report["reputation_analysis"]["domain_results"]))
        print(f"Report saved to: {output_path}")

    except (OSError, ValueError, KeyError) as error:
        print(f"Investigation failed: {error}", file=sys.stderr)
        sys.exit(1)

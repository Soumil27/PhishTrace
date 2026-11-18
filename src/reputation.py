import os
import re
import base64
from urllib.parse import urlsplit

import requests

VT_URL_API = "https://www.virustotal.com/api/v3/urls"
VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains"


def unknown(indicator, indicator_type, reason):
    return {
        "indicator": indicator,
        "type": indicator_type,
        "status": "UNKNOWN",
        "reason": reason,
    }


def check_reputation(indicator, indicator_type="url"):
    """Look up existing VirusTotal reports without submitting URLs or files."""
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return unknown(indicator, indicator_type, "VT_API_KEY is not configured.")

    if indicator_type not in ("url", "domain"):
        return unknown(indicator, indicator_type, "Unsupported indicator type.")

    if not isinstance(indicator, str) or not indicator.strip():
        return unknown(indicator, indicator_type, "Indicator is empty or invalid.")

    indicator = indicator.strip()
     # Skip VirusTotal lookups for reserved synthetic test domains.
    if indicator_type == "domain" and indicator.lower().endswith(".test"):
        return unknown(
            indicator,
            indicator_type,
            "Reserved .test domain used for testing; external lookup skipped."
        )

    if indicator_type == "url":
        parsed = urlsplit(indicator)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return unknown(indicator, indicator_type, "Invalid HTTP or HTTPS URL.")

        url_id = base64.urlsafe_b64encode(
            indicator.encode("utf-8")
        ).decode("ascii").rstrip("=")
        endpoint = f"{VT_URL_API}/{url_id}"

    else:
        indicator = indicator.lower()

        if (
            "/" in indicator
            or ":" in indicator
            or "://" in indicator
            or not re.fullmatch(r"[a-z0-9.-]+", indicator)
            or indicator.startswith(".")
            or indicator.endswith(".")
            or ".." in indicator
        ):
            return unknown(
                indicator, indicator_type,
                "Provide a valid domain name, not a URL."
            )

        endpoint = f"{VT_DOMAIN_API}/{indicator}"

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=15,
        )

        if response.status_code == 404:
            return unknown(
                indicator,
                indicator_type,
                "No existing VirusTotal record was found.",
            )

        if response.status_code == 401:
            return unknown(
                indicator,
                indicator_type,
                "VirusTotal rejected the API key (401).",
            )

        if response.status_code == 403:
            return unknown(
                indicator,
                indicator_type,
                "VirusTotal denied access (403); check API permissions.",
            )

        if response.status_code == 429:
            return unknown(
                indicator,
                indicator_type,
                "VirusTotal rate limit reached; retry later.",
            )

        response.raise_for_status()

        payload = response.json()
        attributes = payload["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            interpretation = (
                f"{malicious} security engine(s) flagged this indicator "
                "as malicious. Prioritize investigation and validate "
                "the finding using additional evidence."
            )
        elif suspicious > 0:
            interpretation = (
                f"{suspicious} security engine(s) flagged this indicator "
                "as suspicious. Review the indicator and related evidence."
            )
        elif harmless > 0:
            interpretation = (
                "Some security engines classified this indicator as harmless, "
                "but this does not guarantee that it is safe."
            )
        else:
            interpretation = (
                "No malicious or suspicious detections were reported in "
                "the available statistics. This does not establish that "
                "the indicator is safe."
            )

        return {
            "indicator": indicator,
            "type": indicator_type,
            "status": "REVIEW",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "interpretation": interpretation,
            "reason": (
                "Review detection counts and context; "
                "counts are not a definitive verdict."
            ),
        }

    except requests.Timeout:
        return unknown(
            indicator,
            indicator_type,
            "VirusTotal request timed out.",
        )

    except requests.HTTPError as error:
        code = (
            error.response.status_code
            if error.response is not None
            else "unknown"
        )
        return unknown(
            indicator,
            indicator_type,
            f"VirusTotal HTTP error ({code}).",
        )

    except requests.RequestException as error:
        return unknown(
            indicator,
            indicator_type,
            f"VirusTotal network error ({type(error).__name__}).",
        )

    except (ValueError, KeyError, TypeError):
        return unknown(
            indicator,
            indicator_type,
            "Unexpected or incomplete VirusTotal response.",
        )

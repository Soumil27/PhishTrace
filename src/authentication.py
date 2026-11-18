import re

AUTH_METHODS = ("spf", "dkim", "dmarc")


def analyze_authentication(email_data):
    """Extract SPF, DKIM and DMARC results from available email headers."""
    headers = email_data.get("authentication_results", [])

    if isinstance(headers, str):
        headers = [headers]

    results = {}

    for method in AUTH_METHODS:
        observed = []

        for header in headers:
            # Capture method results such as spf=pass, dkim=fail, dmarc=none.
            pattern = rf"(?i)(?<![\w-]){method}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)"
            observed.extend(re.findall(pattern, str(header)))

        normalized = [value.upper() for value in observed]

        if not normalized:
            status = "UNKNOWN"
            evidence = "No Authentication-Results evidence found."
        elif len(set(normalized)) == 1:
            status = normalized[0]
            evidence = f"Observed result(s): {', '.join(normalized)}"
        else:
            status = "CONFLICTING"
            evidence = f"Observed result(s): {', '.join(normalized)}"

        results[method.upper()] = {
            "status": status,
            "evidence": evidence,
        }

    return {
        "authentication": results,
        "note": (
            "These results are parsed from supplied headers; "
            "header text alone does not establish that the headers are trustworthy."
        ),
    }

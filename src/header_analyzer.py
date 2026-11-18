
def analyze_headers(email_data):
    """Identify email-header indicators for investigation."""
    findings = []

    senders = email_data.get("from", [])
    reply_tos = email_data.get("reply_to", [])
    return_path = email_data.get("return_path", "")
    received = email_data.get("received_headers", [])
    auth_results = email_data.get("authentication_results", [])

    def domains(addresses):
        result = set()
        for item in addresses:
            address = item.get("email", "").strip().lower()
            if "@" in address:
                result.add(address.rsplit("@", 1)[1])
        return result

    sender_domains = domains(senders)
    reply_domains = domains(reply_tos)

    if sender_domains and reply_domains and sender_domains.isdisjoint(reply_domains):
        findings.append({
            "indicator": "Sender and Reply-To domains differ",
            "severity": "medium",
            "detail": f"Sender: {sorted(sender_domains)}; Reply-To: {sorted(reply_domains)}"
        })

    return_address = return_path.strip().strip("<>").lower()
    return_domains = {return_address.rsplit("@", 1)[1]} if "@" in return_address else set()

    if sender_domains and return_domains and sender_domains.isdisjoint(return_domains):
        findings.append({
            "indicator": "Sender and Return-Path domains differ",
            "severity": "low",
            "detail": f"Sender: {sorted(sender_domains)}; Return-Path: {sorted(return_domains)}"
        })

    if not received:
        findings.append({
            "indicator": "No Received headers",
            "severity": "informational",
            "detail": "No mail-server routing history is present in this file."
        })

    if not auth_results:
        findings.append({
            "indicator": "No Authentication-Results header",
            "severity": "informational",
            "detail": "SPF/DKIM/DMARC results cannot be established from this header alone."
        })

    return {
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "Needs investigation" if findings else "No header indicators detected",
        "disclaimer": "Indicators are not proof of maliciousness; investigate with additional evidence."
    }

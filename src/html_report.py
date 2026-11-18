"""HTML export for a PhishTrace investigation report."""
import html
import json
from pathlib import Path
from typing import Any

def generate_html_report(report: dict[str, Any], output_path: str | Path) -> str:
    assessment = report.get("overall_assessment", {})
    headers = report.get("header_analysis", {})
    if not isinstance(headers, dict):
        headers = {}
    findings = headers.get("findings", [])
    ioc = report.get("ioc_analysis", {})
    auth = report.get("authentication_analysis", {})
    reputation = report.get("reputation_analysis", {})

    def esc(value: Any) -> str:
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        return html.escape(str(value if value is not None else "Not available"))

    rows = [
        ("Source file", report.get("file", report.get("source_file", "Uploaded email"))),
        ("Verdict", assessment.get("verdict", "Unknown")),
        ("Risk score", f'{assessment.get("risk_score", 0)}/100'),
        ("Risk level", assessment.get("risk_level", "Unknown")),
        ("URLs extracted", ioc.get("url_count", len(ioc.get("urls", [])))),
        ("Domains extracted", ioc.get("domain_count", len(ioc.get("domains", [])))),
    ]
    summary_rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows
    )
    finding_rows = "".join(
        f"<tr><td>{esc(x.get('indicator', x.get('finding', 'Finding')))}</td>"
        f"<td>{esc(x.get('severity', 'Unknown'))}</td>"
        f"<td>{esc(x.get('detail', x.get('explanation', '')))}</td></tr>"
        for x in findings if isinstance(x, dict)
    ) or '<tr><td colspan="3">No header findings recorded.</td></tr>'

    reasons = assessment.get("risk_reasons", [])
    reason_rows = "".join(
        f"<tr><td>{esc(x.get('finding', 'Indicator'))}</td>"
        f"<td>{esc(x.get('severity', 'Unknown'))} / {esc(x.get('points_added', 0))}</td>"
        f"<td>{esc(x.get('explanation', ''))}</td></tr>"
        for x in reasons if isinstance(x, dict)
    ) or '<tr><td colspan="3">No scored risk reasons.</td></tr>'

    indicator_rows = ""
    for kind, key in (("URL", "urls"), ("Domain", "domains")):
        values = ioc.get(key, [])
        if isinstance(values, list):
            indicator_rows += "".join(
                f"<tr><td>{kind}</td><td>{esc(v)}</td></tr>" for v in values
            )
    indicator_rows = indicator_rows or '<tr><td colspan="2">No indicators extracted.</td></tr>'

    auth_rows = ""
    if isinstance(auth, dict):
        for key, value in auth.items():
            if isinstance(value, dict):
                status = value.get("status", "UNKNOWN")
                evidence = value.get("evidence", value.get("detail", ""))
            else:
                status, evidence = value, ""
            auth_rows += f"<tr><td>{esc(key)}</td><td>{esc(status)}</td><td>{esc(evidence)}</td></tr>"
    auth_rows = auth_rows or '<tr><td colspan="3">No authentication evidence.</td></tr>'

    rep_rows = ""
    if isinstance(reputation, dict):
        for kind in ("url_results", "domain_results"):
            results = reputation.get(kind, [])
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        indicator = item.get("indicator", item.get("url", item.get("domain", "Unknown")))
                        rep_rows += (
                            f"<tr><td>{esc(kind.removesuffix('_results'))}</td>"
                            f"<td>{esc(indicator)}</td><td>{esc(item.get('status', 'UNKNOWN'))}</td>"
                            f"<td>{esc(item.get('reason', ''))}</td></tr>"
                        )
    rep_rows = rep_rows or '<tr><td colspan="4">No reputation results.</td></tr>'

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishTrace Investigation Report</title>
<style>
body{{font-family:Arial,sans-serif;max-width:1000px;margin:32px auto;padding:0 20px;color:#172033}}
h1{{color:#123763}}h2{{margin-top:28px;color:#174b7a}}
table{{border-collapse:collapse;width:100%;margin:12px 0 24px;table-layout:fixed}}
th,td{{border:1px solid #ccd5df;padding:9px;text-align:left;overflow-wrap:anywhere}}
th{{background:#173b64;color:white}}tr:nth-child(even){{background:#f1f5f9}}
.note{{background:#fff7df;padding:12px;border-left:4px solid #d69b20}}
@media print{{body{{margin:0;max-width:none}}}}
</style></head><body>
<h1>PhishTrace</h1><p>Email Phishing Investigation Report</p>
<p>Generated in PhishTrace. This report supports initial triage.</p>
<h2>1. Executive Summary</h2><table>{summary_rows}</table>
<h2>2. Explainable Risk Reasons</h2>
<table><tr><th>Finding</th><th>Severity / Points</th><th>Explanation</th></tr>{reason_rows}</table>
<h2>3. Email Header Findings</h2>
<table><tr><th>Indicator</th><th>Severity</th><th>Details</th></tr>{finding_rows}</table>
<h2>4. Extracted Indicators</h2>
<table><tr><th>Type</th><th>Value</th></tr>{indicator_rows}</table>
<h2>5. Authentication Evidence</h2>
<table><tr><th>Mechanism</th><th>Status</th><th>Evidence</th></tr>{auth_rows}</table>
<h2>6. Reputation Results</h2>
<table><tr><th>Type</th><th>Indicator</th><th>Status</th><th>Reason</th></tr>{rep_rows}</table>
<p class="note">Risk scoring is heuristic, not a calibrated probability. UNKNOWN or missing evidence does not mean safe. Authentication headers are interpreted as supplied and are not independently verified by this report. PhishTrace does not visit extracted URLs to generate this report.</p>
</body></html>"""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return str(path)

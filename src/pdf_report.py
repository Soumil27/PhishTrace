"""Generate a readable PDF report for a PhishTrace investigation."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def generate_pdf_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> str:
    """Create a PDF report from a PhishTrace investigation dictionary."""

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=1.7 * cm,
        leftMargin=1.7 * cm,
        topMargin=1.7 * cm,
        bottomMargin=1.7 * cm,
        title="PhishTrace Investigation Report",
        author="PhishTrace",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        wordWrap="CJK",
    ))

    def safe(value: Any) -> str:
        """Escape values before inserting them into ReportLab paragraphs."""
        from xml.sax.saxutils import escape

        if value is None:
            return "Not available"
        return escape(str(value))

    def make_table(rows: list[list[Any]]) -> Table:
        table = Table(rows, colWidths=[4.5 * cm, 11 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2E0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#F2F6FA"),
            ]),
        ]))
        return table

    assessment = report.get("overall_assessment", {})
    header = report.get("header_analysis", {})
    ioc = report.get("ioc_analysis", {})
    auth = report.get("authentication_analysis", {})
    reputation = report.get("reputation_analysis", {})

    story = [
        Paragraph("PhishTrace", styles["ReportTitle"]),
        Paragraph(
            "Email Phishing Investigation Report",
            styles["Heading2"],
        ),
        Spacer(1, 8),
        Paragraph(
            "Generated: "
            + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph("1. Executive Summary", styles["SectionHeading"]),
        make_table([
            ["Field", "Result"],
            ["Source file", safe(report.get("source_file", "Not available"))],
            ["Verdict", safe(assessment.get("verdict", "Inconclusive"))],
            ["Risk score", f"{safe(assessment.get('risk_score', 0))}/100"],
            ["Risk level", safe(assessment.get("risk_level", "Unknown"))],
            ["URLs extracted", safe(assessment.get("url_count", 0))],
            ["Domains extracted", safe(assessment.get("domain_count", 0))],
        ]),
        Spacer(1, 8),
        Paragraph(
            "This report supports initial triage. Findings and reputation "
            "results are evidence for investigation, not definitive proof "
            "that an email is malicious or safe.",
            styles["SmallText"],
        ),
        Paragraph("2. Explainable Risk Reasons", styles["SectionHeading"]),
    ]

    reasons = assessment.get("risk_reasons", [])
    if reasons:
        reason_rows = [["Finding", "Severity / Points", "Explanation"]]
        for item in reasons:
            reason_rows.append([
                Paragraph(safe(item.get("finding", "Finding")), styles["SmallText"]),
                Paragraph(
                    safe(item.get("severity", "Unknown"))
                    + " / "
                    + safe(item.get("points_added", 0)),
                    styles["SmallText"],
                ),
                Paragraph(
                    safe(item.get("explanation", "No explanation provided")),
                    styles["SmallText"],
                ),
            ]) # type: ignore

        reason_table = Table(
            reason_rows,
            colWidths=[4.5 * cm, 3.2 * cm, 7.8 * cm],
            repeatRows=1,
        )
        reason_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2E0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(reason_table)
    else:
        story.append(Paragraph(
            "No scored risk reasons were recorded.",
            styles["BodyText"],
        ))

    story.append(Paragraph("3. Email Header Findings", styles["SectionHeading"]))
    findings = header.get("findings", [])
    if findings:
        finding_rows = [["Indicator", "Severity", "Details"]]
        for finding in findings:
            finding_rows.append([
                Paragraph(safe(finding.get("indicator", "Unknown")), styles["SmallText"]),
                Paragraph(safe(finding.get("severity", "Unknown")), styles["SmallText"]),
                Paragraph(safe(finding.get("detail", "")), styles["SmallText"]),
            ]) # type: ignore

        finding_table = Table(
            finding_rows,
            colWidths=[4.5 * cm, 2.5 * cm, 8.5 * cm],
            repeatRows=1,
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2E0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(finding_table)
    else:
        story.append(Paragraph("No header findings recorded.", styles["BodyText"]))

    story.append(Paragraph("4. Extracted Indicators", styles["SectionHeading"]))
    urls = ioc.get("urls", [])
    domains = ioc.get("domains", [])
    indicator_rows = [["Type", "Value"]]

    for url in urls:
        indicator_rows.append([
            "URL",
            Paragraph(safe(url), styles["SmallText"]), # type: ignore
        ])
    for domain in domains:
        indicator_rows.append([
            "Domain",
            Paragraph(safe(domain), styles["SmallText"]), # type: ignore
        ])

    if len(indicator_rows) == 1:
        indicator_rows.append(["Indicators", "None extracted"])

    story.append(make_table(indicator_rows))

    story.append(Paragraph("5. Authentication Evidence", styles["SectionHeading"]))
    auth_data = auth.get("authentication", auth)
    auth_rows = [["Mechanism", "Status / Evidence"]]

    if isinstance(auth_data, dict):
        for mechanism, result in auth_data.items():
            if mechanism == "note":
                continue
            if isinstance(result, dict):
                details = (
                    f"Status: {result.get('status', 'UNKNOWN')}; "
                    f"Evidence: {result.get('evidence', 'Not available')}"
                )
                auth_rows.append([
                    safe(mechanism),
                    Paragraph(safe(details), styles["SmallText"]), # type: ignore
                ])

    if len(auth_rows) == 1:
        auth_rows.append(["Authentication", "No results available"])

    story.append(make_table(auth_rows))

    story.append(Paragraph("6. Reputation Results", styles["SectionHeading"]))
    rep_rows = [["Type", "Indicator", "Status", "Reason"]]

    for result_type, label in (
        ("url_results", "URL"),
        ("domain_results", "Domain"),
    ):
        for item in reputation.get(result_type, []):
            rep_rows.append([
                label,
                Paragraph(safe(item.get("indicator", "Unknown")), styles["SmallText"]),
                safe(item.get("status", "UNKNOWN")),
                Paragraph(safe(item.get("reason", "No reason provided")), styles["SmallText"]),
            ]) # type: ignore

    if len(rep_rows) == 1:
        rep_rows.append(["Reputation", "None", "UNKNOWN", "No results available"])

    rep_table = Table(
        rep_rows,
        colWidths=[1.7 * cm, 5.2 * cm, 2.1 * cm, 6.5 * cm],
        repeatRows=1,
    )
    rep_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C7D2E0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(rep_table)

    story.append(Spacer(1, 12))
    story.append(Paragraph("Limitations", styles["SectionHeading"]))
    story.append(Paragraph(
        "Risk scoring is heuristic and is not a calibrated probability of "
        "phishing. Missing evidence does not mean an email is safe. "
        "Authentication data is interpreted from supplied headers and is "
        "not independently verified by this report. Reputation lookups "
        "depend on existing provider records and service availability. "
        "PhishTrace does not need to visit extracted URLs to generate this report.",
        styles["SmallText"],
    ))

    doc.build(story)
    return str(output)

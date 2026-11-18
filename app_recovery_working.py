import json
import sys
import tempfile
from pathlib import Path

import streamlit as st # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from phishtrace import investigate
from pdf_report import generate_pdf_report # type: ignore


st.set_page_config(
    page_title="PhishTrace",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PhishTrace")
st.subheader("Email Phishing Investigation Platform")

st.write(
    "Analyze email headers, extract indicators of compromise, "
    "review authentication evidence, and query threat intelligence."
)

st.info(
    "Use synthetic or non-sensitive email samples. VirusTotal lookups "
    "query an external service, so avoid submitting confidential indicators."
)

uploaded_file = st.file_uploader(
    "Upload an email file (.eml)",
    type=["eml"],
)

if uploaded_file is not None:

    if uploaded_file.size > 2 * 1024 * 1024:
        st.error("File is too large. Please upload an email under 2 MB.")
        st.stop()

    if st.button("Analyze Email", type="primary"):

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".eml",
                delete=False,
            ) as temporary_file:
                temporary_file.write(uploaded_file.getvalue())
                temporary_path = Path(temporary_file.name)

            with st.spinner("Analyzing email..."):
                report = investigate(temporary_path)

            st.success("Analysis completed.")

            assessment = report.get("overall_assessment", {})
             # Export the complete investigation report.
            report_json = json.dumps(report, indent=4, ensure_ascii=False)
            pdf_path = Path(tempfile.gettempdir()) / "phishtrace_investigation_report.pdf"
            generate_pdf_report(report, pdf_path)
            with open(pdf_path, "rb") as pdf_file:
                st.download_button(
                    label="Download Investigation Report (PDF)",
                    data=pdf_file.read(),
                    file_name="phishtrace_investigation_report.pdf",
                    mime="application/pdf",
                    key="download_investigation_report_pdf",
                )

            st.download_button(
                label="Download Investigation Report (JSON)",
                data=report_json,
                file_name="phishtrace_investigation_report.json",
                mime="application/json",
                key="download_investigation_report",
            )

            st.header("Investigation Overview")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "URLs Extracted",
                assessment.get("url_count", 0),
            )

            col2.metric(
                "Domains Extracted",
                assessment.get("domain_count", 0),
            )

            col3.metric(
                "Header Findings",
                report.get("header_analysis", {}).get(
                    "finding_count", 0
                ),
            )

            st.subheader("Preliminary Assessment")
            st.write(assessment.get("verdict", "Inconclusive"))

            st.caption(
                "This is a triage result, not proof that an email "
                "is malicious."
            )

            # Explainable risk assessment
            st.subheader("Explainable Risk Assessment")

            risk_score = assessment.get("risk_score", 0)
            risk_level = assessment.get("risk_level", "Informational")
            risk_reasons = assessment.get("risk_reasons", [])

            col1, col2 = st.columns(2)

            col1.metric("Risk Score", f"{risk_score}/100")
            col2.metric("Risk Level", risk_level)

            st.progress(
                min(max(float(risk_score) / 100, 0.0), 1.0)
            )

            if risk_reasons:
                st.markdown("**Why this score was assigned:**")

                for reason in risk_reasons:
                    st.write(
                        f"- **{reason.get('finding', 'Finding')}** "
                        f"(Severity: {reason.get('severity', 'Unknown')}; "
                        f"Points added: {reason.get('points_added', 0)})"
                    )

                    st.caption(
                        reason.get(
                            "explanation",
                            "No additional explanation available.",
                        )
                    )
            else:
                st.info("No scored risk indicators were identified.")

            with st.expander("Email Details", expanded=True):
                details = report.get("email_details", {})

                st.write(
                    "**Subject:**",
                    details.get("subject", "(not available)"),
                )
                st.write(
                    "**From:**",
                    details.get("from", "(not available)"),
                )
                st.write(
                    "**To:**",
                    details.get("to", "(not available)"),
                )
                st.write(
                    "**Reply-To:**",
                    details.get("reply_to", "(not available)"),
                )

            with st.expander("Header Analysis"):
                st.json(report.get("header_analysis", {}))

            with st.expander("Extracted URLs and Domains"):
                st.json(report.get("ioc_analysis", {}))

            with st.expander("Authentication Evidence", expanded=True):
                auth = report.get("authentication_analysis", {})

                auth_columns = st.columns(3)

                for column, method in zip(
                    auth_columns,
                    ["SPF", "DKIM", "DMARC"],
                ):
                    result = auth.get(method, {})
                    status = result.get("status", "UNKNOWN")

                    column.metric(method, status)

                    if result.get("evidence"):
                        column.caption(result["evidence"])

                st.caption(
                    "Authentication results are parsed from the supplied "
                    "email headers and are not independently verified."
                )

            with st.expander(
                "VirusTotal Reputation Results",
                expanded=True,
            ):
                reputation = report.get("reputation_analysis", {})

                st.write(
                    "These results use existing VirusTotal reports. "
                    "PhishTrace does not upload the email or visit extracted URLs."
                )

                url_results = reputation.get("url_results", [])
                domain_results = reputation.get("domain_results", [])

                st.subheader("URL Reputation")

                if url_results:
                    st.dataframe(url_results, use_container_width=True)
                else:
                    st.info("No URLs were extracted from this email.")

                st.subheader("Domain Reputation")

                if domain_results:
                    st.dataframe(domain_results, use_container_width=True)
                else:
                    st.info("No domains were extracted from this email.")

                st.caption(
                    "UNKNOWN means no usable reputation result was obtained; "
                    "it does not mean the indicator is safe."
                )

            report_json = json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            )

            st.download_button(
                label="Download JSON Investigation Report",
                data=report_json,
                file_name="phishtrace_investigation_report.json",
                mime="application/json",
            )

        except Exception as error:
            st.error(
                "Analysis failed. Check the terminal for diagnostic details."
            )
            print(
                f"PhishTrace application error: "
                f"{type(error).__name__}: {error}"
            )

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

else:
    st.caption("Choose a synthetic or non-sensitive .eml file to begin.")
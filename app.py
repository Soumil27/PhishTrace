import json
import sys
import tempfile
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from phishtrace import investigate
from pdf_report import generate_pdf_report
from history import save_investigation, get_recent_investigations, get_investigation_by_id


def _pdf_bytes(report):
    pdf_path = Path(tempfile.gettempdir()) / "phishtrace_investigation_report.pdf"
    generate_pdf_report(report, pdf_path)
    with open(pdf_path, "rb") as pdf_file:
        return pdf_file.read()

st.set_page_config(
    page_title="PhishTrace | Email Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Visual-only styling: analysis, scoring, storage and exports remain unchanged.
st.markdown("""
<style>
:root { --pt-bg:#0b1220; --pt-panel:#111c2e; --pt-border:#26364d; --pt-blue:#38bdf8; }
.stApp { background: radial-gradient(ellipse at 15% 0%, #142743 0%, #0b1220 48%, #080e19 100%); }
.block-container { max-width: 1450px; padding-top: 1.6rem; padding-bottom: 3rem; }
[data-testid="stSidebar"] { background: #0d1727; border-right: 1px solid #26364d; }
.hero { padding: 1.5rem 1.7rem; border:1px solid #29415d; border-radius:18px;
        background:linear-gradient(115deg,rgba(20,45,73,.96),rgba(15,27,45,.94));
        margin-bottom:1.25rem; box-shadow:0 14px 40px rgba(0,0,0,.18); }
.eyebrow { color:#7dd3fc; text-transform:uppercase; letter-spacing:.16em; font-size:.72rem; font-weight:700; }
.hero h1 { margin:.25rem 0 .25rem; font-size:2.25rem; color:#f8fafc; }
.hero p { color:#c4d2e3; margin:0; font-size:1rem; }
.section-label { color:#7dd3fc; text-transform:uppercase; letter-spacing:.12em; font-size:.72rem; font-weight:700; margin:.8rem 0 .25rem; }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#14243a,#101b2c); border:1px solid #2a3e58;
    border-radius:14px; padding:15px 17px; }
div[data-testid="stMetric"] label { color:#a9bfd5 !important; }
div[data-testid="stMetricValue"] { color:#f8fafc !important; }
.stButton>button, .stDownloadButton>button { border-radius:10px; border:1px solid #36516f; font-weight:650; }
.stButton>button[kind="primary"] { background:linear-gradient(90deg,#0284c7,#2563eb); border:0; }
div[data-testid="stExpander"] { border:1px solid #293d56; border-radius:12px; background:rgba(17,28,46,.72); }
div[data-testid="stAlert"] { border-radius:12px; }
hr { border-color:#26364d; }
.small-muted { color:#9fb1c5; font-size:.86rem; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ PhishTrace")
    st.caption("EMAIL SECURITY WORKSPACE")
    st.markdown("---")
    st.markdown("**Investigation workflow**")
    st.markdown("1. Upload an `.eml` file")
    st.markdown("2. Run the analysis")
    st.markdown("3. Review evidence and risk")
    st.markdown("4. Export the investigation")
    st.markdown("---")
    st.caption("Use synthetic or non-sensitive email samples. VirusTotal queries existing external reports; avoid confidential indicators.")

st.markdown("""
<div class="hero">
  <div class="eyebrow">Email threat analysis • SOC triage</div>
  <h1>🛡️ PhishTrace</h1>
  <p>Investigate suspicious emails with header analysis, IOC extraction, authentication evidence and threat-intelligence context.</p>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="section-label">01 / New investigation</div>', unsafe_allow_html=True)
with st.container(border=True):
    uploaded_file = st.file_uploader("Upload an email file (.eml)", type=["eml"], help="Maximum file size: 2 MB.")
    if uploaded_file is not None:
        st.caption(f"Selected file: **{uploaded_file.name}** · {uploaded_file.size / 1024:.1f} KB")
        if uploaded_file.size > 2 * 1024 * 1024:
            st.error("File is too large. Please upload an email under 2 MB.")
            st.stop()

    if uploaded_file is not None and st.button("🔍  Analyze email", type="primary", use_container_width=True):
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".eml", delete=False) as temporary_file:
                temporary_file.write(uploaded_file.getvalue())
                temporary_path = Path(temporary_file.name)

            with st.spinner("Analyzing email headers, indicators and reputation..."):
                report = investigate(temporary_path)
            report["source_file"] = Path(uploaded_file.name).name
            save_investigation(report)
            st.session_state["phishtrace_latest_report"] = report
            st.success("Analysis completed and saved to investigation history.")
        except Exception as error:
            st.error("Analysis failed. Check the terminal for diagnostic details.")
            print(f"PhishTrace application error: {type(error).__name__}: {error}")
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

report = st.session_state.get("phishtrace_latest_report")

if report:
    assessment = report.get("overall_assessment", {})
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    st.markdown('<div class="section-label">02 / Investigation results</div>', unsafe_allow_html=True)
    with st.container(border=True):
        st.markdown(f"### {report.get('source_file', 'Email investigation')}")
        verdict = assessment.get("verdict", "Inconclusive")
        score = assessment.get("risk_score", 0)
        level = assessment.get("risk_level", "Informational")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk score", f"{score}/100")
        c2.metric("Risk level", level)
        c3.metric("URLs extracted", assessment.get("url_count", 0))
        c4.metric("Domains extracted", assessment.get("domain_count", 0))
        st.markdown("**Preliminary assessment**")
        st.warning(verdict)
        st.caption("This is a triage result, not proof that an email is malicious.")
        st.progress(min(max(float(score) / 100, 0.0), 1.0))
        left, right = st.columns(2)
        with left:
            st.download_button("⬇️ Download PDF report", data=_pdf_bytes(report), file_name="phishtrace_investigation_report.pdf", mime="application/pdf", use_container_width=True)
        with right:
            st.download_button("⬇️ Download JSON report", data=report_json, file_name="phishtrace_investigation_report.json", mime="application/json", use_container_width=True)

    st.markdown('<div class="section-label">03 / Evidence and analysis</div>', unsafe_allow_html=True)
    reasons = assessment.get("risk_reasons", [])
    with st.expander("Risk assessment — why this score was assigned", expanded=True):
        if reasons:
            for reason in reasons:
                st.markdown(f"**{reason.get('finding', 'Finding')}**  ·  {reason.get('severity', 'Unknown')} severity  ·  +{reason.get('points_added', 0)} points")
                st.caption(reason.get("explanation", "No additional explanation available."))
        else:
            st.info("No scored risk indicators were identified.")

    details = report.get("email_details", {})
    with st.expander("Email details"):
        a, b = st.columns(2)
        a.write("**Subject**")
        a.write(details.get("subject", "(not available)"))
        a.write("**From**")
        a.write(details.get("from", "(not available)"))
        b.write("**To**")
        b.write(details.get("to", "(not available)"))
        b.write("**Reply-To**")
        b.write(details.get("reply_to", "(not available)"))

    with st.expander("Header analysis"):
        st.json(report.get("header_analysis", {}), expanded=False)
    with st.expander("Extracted URLs and domains"):
        st.json(report.get("ioc_analysis", {}), expanded=False)

    with st.expander("Authentication evidence", expanded=True):
        auth_data = report.get("authentication_analysis", {})
        auth = auth_data.get("authentication", auth_data)
        auth_columns = st.columns(3)
        for column, method in zip(auth_columns, ["SPF", "DKIM", "DMARC"]):
            result = auth.get(method, {})
            column.metric(method, result.get("status", "UNKNOWN"))
            if result.get("evidence"):
                column.caption(result["evidence"])
        st.caption("Authentication results are parsed from supplied email headers and are not independently verified.")

    with st.expander("VirusTotal reputation results", expanded=True):
        reputation = report.get("reputation_analysis", {})
        st.caption("Uses existing VirusTotal reports only. PhishTrace does not upload the email or visit extracted URLs.")
        url_results = reputation.get("url_results", [])
        domain_results = reputation.get("domain_results", [])
        st.markdown("**URL reputation**")
        if url_results:
            st.dataframe(url_results, use_container_width=True, hide_index=True)
        else:
            st.info("No URLs were extracted from this email.")
        st.markdown("**Domain reputation**")
        if domain_results:
            st.dataframe(domain_results, use_container_width=True, hide_index=True)
        else:
            st.info("No domains were extracted from this email.")
        st.caption("UNKNOWN means no usable reputation result was obtained; it does not mean the indicator is safe.")

st.markdown("---")
st.markdown('<div class="section-label">04 / Case history</div>', unsafe_allow_html=True)
st.subheader("Previous investigations")
history_rows = get_recent_investigations(50)
if history_rows:
    st.dataframe(history_rows, use_container_width=True, hide_index=True)
    selected_history_id = st.selectbox(
        "Open a saved investigation",
        options=[int(row["id"]) for row in history_rows],
        format_func=lambda item_id: next(
            (f"#{row['id']} · {row.get('source_file', 'Unknown file')} · {row.get('risk_level', 'Unknown')} ({row.get('risk_score', 0)}/100)"
             for row in history_rows if int(row["id"]) == int(item_id)),
            f"Investigation #{item_id}",
        ),
        key="historical_investigation_selector",
    )
    saved = get_investigation_by_id(selected_history_id)
    if saved:
        historical_report = saved["report"]
        with st.expander("View selected investigation details"):
            st.caption(f"Saved file: {saved.get('source_file', 'Unknown')} · Investigated at: {saved.get('investigated_at', 'Unknown')}")
            st.json(historical_report, expanded=False)
            historical_json = json.dumps(historical_report, indent=2, ensure_ascii=False).encode("utf-8")
            h1, h2 = st.columns(2)
            h1.download_button("Download selected JSON", data=historical_json, file_name=f"phishtrace_investigation_{selected_history_id}.json", mime="application/json", key=f"history_json_{selected_history_id}", use_container_width=True)
            try:
                historical_pdf_path = Path(tempfile.gettempdir()) / f"phishtrace_history_{selected_history_id}.pdf"
                generate_pdf_report(historical_report, historical_pdf_path)
                with open(historical_pdf_path, "rb") as historical_pdf:
                    historical_pdf_bytes = historical_pdf.read()
                h2.download_button("Download selected PDF", data=historical_pdf_bytes, file_name=f"phishtrace_investigation_{selected_history_id}.pdf", mime="application/pdf", key=f"history_pdf_{selected_history_id}", use_container_width=True)
            except Exception as pdf_error:
                st.error(f"Could not generate this historical PDF: {pdf_error}")
else:
    st.info("No saved investigations yet. Analyze an email to create your first history entry.")

st.caption("PhishTrace · Email phishing investigation and triage platform")


def _pdf_bytes(report):
    pdf_path = Path(tempfile.gettempdir()) / "phishtrace_investigation_report.pdf"
    generate_pdf_report(report, pdf_path)
    with open(pdf_path, "rb") as pdf_file:
        return pdf_file.read()

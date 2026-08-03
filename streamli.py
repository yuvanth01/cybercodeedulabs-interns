import json
import os
import sys
import pandas as pd
import streamlit as st

# ---------------- IMPORT SRC ---------------- #

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from parser import validate_incident
from ai_generator import generate_ai_report
from report_writer import save_report
from pdf_generator import create_pdf
from utils import calculate_threat_score

# ---------------- PAGE CONFIG ---------------- #

st.set_page_config(
    page_title="AI Incident Report Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---------------- CSS ---------------- #

st.markdown("""
<style>

/* ---------- BACKGROUND ---------- */

.stApp{
    background:#000000;
}

/* ---------- CONTAINER ---------- */

.block-container{
    padding-top:1rem;
}

/* ---------- TITLE ---------- */

.title{
    text-align:center;
    font-size:42px;
    font-weight:bold;
    color:#00BFFF;
}

.subtitle{
    text-align:center;
    font-size:18px;
    color:white;
}

/* ---------- HEADINGS ---------- */

h1,h2,h3,h4{
    color:#00BFFF !important;
}

/* ---------- CARDS ---------- */

.card{

    background:white;

    color:black;

    border-radius:15px;

    padding:20px;

    border:2px solid #00BFFF;

    text-align:center;

    box-shadow:0px 0px 12px rgba(0,191,255,.3);

}

.metric{

    color:#007BFF;

    font-size:28px;

    font-weight:bold;

}

/* ---------- REPORT ---------- */

.report-box{

    background:white;

    color:black;

    padding:20px;

    border-radius:12px;

    border:2px solid #00BFFF;

}

/* ---------- BUTTON ---------- */

.stButton>button{

    width:100%;

    background:#007BFF;

    color:white;

    border:none;

    border-radius:8px;

    font-weight:bold;

}

.stDownloadButton>button{

    width:100%;

    background:#007BFF;

    color:white;

    border:none;

    border-radius:8px;

}

/* ---------- METRICS ---------- */

[data-testid="stMetric"]{

    background:white;

    border-radius:10px;

    padding:10px;

}

[data-testid="stMetricLabel"]{

    color:black;

}

[data-testid="stMetricValue"]{

    color:#007BFF;

}

/* ---------- TABLE ---------- */

[data-testid="stDataFrame"]{

    background:white;

}

/* ---------- FILE ---------- */

[data-testid="stFileUploader"]{

    background:white;

    padding:12px;

    border-radius:10px;

}

</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ---------------- #

st.markdown(
    "<div class='title'>🛡️ AI Incident Report Generator</div>",
    unsafe_allow_html=True
)

st.markdown(
    "<div class='subtitle'>Professional SOC Incident Report Generator using Gemini AI</div>",
    unsafe_allow_html=True
)

st.divider()

# ---------------- FILE UPLOAD ---------------- #

uploaded_file = st.file_uploader(
    "Upload Incident JSON",
    type=["json"]
)

if uploaded_file:

    incident = json.load(uploaded_file)

    validate_incident(incident)

    st.success("Incident JSON Uploaded Successfully")

    st.divider()

    c1,c2,c3,c4 = st.columns(4)

    with c1:

        st.markdown(f"""
        <div class="card">
        Incident ID
        <div class="metric">{incident['incident_id']}</div>
        </div>
        """,unsafe_allow_html=True)

    with c2:

        st.markdown(f"""
        <div class="card">
        Severity
        <div class="metric">{incident['severity']}</div>
        </div>
        """,unsafe_allow_html=True)

    with c3:

        st.markdown(f"""
        <div class="card">
        Attack Type
        <div class="metric">{incident['attack_type']}</div>
        </div>
        """,unsafe_allow_html=True)

    with c4:

        st.markdown(f"""
        <div class="card">
        Status
        <div class="metric">{incident['status']}</div>
        </div>
        """,unsafe_allow_html=True)

    st.divider()

    left,right = st.columns([1,2])
        # ================= LEFT PANEL ================= #

    with left:

        # ---------------- INCIDENT SUMMARY ---------------- #

        st.subheader("📋 Incident Summary")

        st.markdown(f"""
### Incident Report — {incident["source_ip"]}

**Status:** {incident["status"]}

**Current Stage:** Post-Incident

**First Seen:** {incident["timestamp"]}

**Last Seen:** {incident["timestamp"]}

**Total Events:** {len(incident["evidence"])}
""")

        st.divider()

        # ---------------- SEVERITY BREAKDOWN ---------------- #

        st.subheader("🚨 Severity Breakdown")

        critical = 1 if incident["severity"] == "Critical" else 0
        high = 1 if incident["severity"] == "High" else 0
        medium = 1 if incident["severity"] == "Medium" else 0
        low = 1 if incident["severity"] == "Low" else 0

        c1,c2,c3,c4 = st.columns(4)

        c1.metric("Critical", critical)
        c2.metric("High", high)
        c3.metric("Medium", medium)
        c4.metric("Low", low)

        st.divider()

        # ---------------- THREAT SCORE ---------------- #

        st.subheader("🎯 Threat Score")

        threat_score = calculate_threat_score(incident)

        st.progress(threat_score)

        st.metric(
            "Threat Score",
            f"{threat_score}/100"
        )

        st.divider()

        # ---------------- MITRE ---------------- #

        st.subheader("🛡 MITRE ATT&CK Techniques Observed")

        mitre_mapping = {

            "SSH Brute Force": {
                "Technique ID":"T1110.001",
                "Tactic":"Credential Access",
                "Technique":"Brute Force: Password Guessing"
            },

            "SQL Injection":{
                "Technique ID":"T1190",
                "Tactic":"Initial Access",
                "Technique":"Exploit Public-Facing Application"
            },

            "Port Scan":{
                "Technique ID":"T1046",
                "Tactic":"Discovery",
                "Technique":"Network Service Discovery"
            },

            "HTTP Probe":{
                "Technique ID":"T1595",
                "Tactic":"Reconnaissance",
                "Technique":"Active Scanning"
            },

            "DNS Tunnel":{
                "Technique ID":"T1071.004",
                "Tactic":"Command and Control",
                "Technique":"DNS"
            },

            "Ransomware":{
                "Technique ID":"T1486",
                "Tactic":"Impact",
                "Technique":"Data Encrypted for Impact"
            }

        }

        attack = mitre_mapping.get(

            incident["attack_type"],

            {

                "Technique ID":"-",
                "Tactic":"-",
                "Technique":"Unknown"

            }

        )

        mitre_df = pd.DataFrame([attack])

        st.dataframe(

            mitre_df,

            hide_index=True,

            use_container_width=True

        )

        st.divider()

        # ---------------- RECOMMENDATIONS ---------------- #

        st.subheader("🛠 Recommended Remediation")

        st.info(f"""

• Check if **{incident['source_ip']}** made multiple login attempts.

• Block the attacker IP

`ufw deny from {incident['source_ip']}`

• Disable SSH password authentication.

• Use SSH Keys instead of passwords.

• Install **Fail2Ban**.

• Monitor SIEM alerts.

• Review firewall logs.

• Rotate privileged credentials if necessary.

""")
        st.divider()

        # ---------------- EVIDENCE ---------------- #

        st.subheader("🔍 Evidence Collected")

        for evidence in incident["evidence"]:
            st.success(evidence)

        st.divider()

        # ---------------- GENERATE REPORT ---------------- #

        if st.button(
            "🚀 Generate AI Report",
            use_container_width=True
        ):

            progress = st.progress(0)

            status = st.empty()

            steps = [

                "📂 Reading Incident JSON...",

                "✅ Validating Data...",

                "🛡 Mapping MITRE ATT&CK...",

                "🤖 Connecting to Gemini AI...",

                "📝 Generating Report...",

                "💾 Saving Report..."

            ]

            for i in range(100):

                progress.progress(i + 1)

                if i < 15:
                    status.info(steps[0])

                elif i < 30:
                    status.info(steps[1])

                elif i < 50:
                    status.info(steps[2])

                elif i < 70:
                    status.info(steps[3])

                elif i < 90:
                    status.info(steps[4])

                else:
                    status.info(steps[5])

            with st.spinner("Generating AI Report..."):

                report = generate_ai_report(incident)

            txt_path = save_report(report)

            pdf_path = create_pdf(report)

            st.session_state["report"] = report
            st.session_state["txt"] = txt_path
            st.session_state["pdf"] = pdf_path

            progress.empty()

            status.success("✅ AI Report Generated Successfully!")
                # ================= RIGHT PANEL ================= #

    with right:

        # ---------------- EVENT TIMELINE ---------------- #

        st.subheader("📜 Full Event Timeline")

        timeline = []

        for event in incident["evidence"]:

            timeline.append({

                "Time (UTC)": incident["timestamp"],

                "Event": incident["attack_type"],

                "Severity": incident["severity"],

                "Raw Log": event

            })

        timeline_df = pd.DataFrame(timeline)

        st.dataframe(

            timeline_df,

            use_container_width=True,

            hide_index=True

        )

        st.divider()

        # ---------------- AI REPORT ---------------- #

        st.subheader("🤖 AI Generated Incident Report")

        if "report" in st.session_state:

            st.markdown(

                f"""

<div class="report-box">

<pre style="white-space:pre-wrap;
font-size:15px;
color:black;">

{st.session_state["report"]}

</pre>

</div>

""",

                unsafe_allow_html=True

            )

        else:

            st.info("Generate the report to preview it here.")

        st.divider()

        # ---------------- DOWNLOADS ---------------- #

        if "report" in st.session_state:

            st.subheader("📥 Download Reports")

            d1,d2 = st.columns(2)

            with d1:

                with open(
                    st.session_state["txt"],
                    "rb"
                ) as file:

                    st.download_button(

                        "📄 Download TXT",

                        data=file,

                        file_name="incident_report.txt",

                        mime="text/plain",

                        use_container_width=True

                    )

            with d2:

                with open(
                    st.session_state["pdf"],
                    "rb"
                ) as file:

                    st.download_button(

                        "📕 Download PDF",

                        data=file,

                        file_name="incident_report.pdf",

                        mime="application/pdf",

                        use_container_width=True

                    )

            st.divider()

            # ---------------- REPORT STATS ---------------- #

            st.subheader("📊 Report Statistics")

            s1,s2,s3 = st.columns(3)

            with s1:

                st.metric(

                    "Evidence",

                    len(incident["evidence"])

                )

            with s2:

                st.metric(

                    "Threat Score",

                    f"{calculate_threat_score(incident)}/100"

                )

            with s3:

                st.metric(

                    "Attack",

                    incident["attack_type"]

                )

            st.divider()

            # ---------------- JSON ---------------- #

            with st.expander("📂 Uploaded JSON"):

                st.json(incident)
            st.divider()

            # ---------------- THREAT LEVEL ---------------- #

            st.subheader("🚨 Threat Assessment")

            threat = calculate_threat_score(incident)

            if threat >= 80:

                st.error("🔴 Threat Level : CRITICAL")

            elif threat >= 60:

                st.warning("🟠 Threat Level : HIGH")

            elif threat >= 40:

                st.info("🟡 Threat Level : MEDIUM")

            else:

                st.success("🟢 Threat Level : LOW")

            st.divider()

            # ---------------- INCIDENT OVERVIEW ---------------- #

            st.subheader("📌 Incident Overview")

            overview = {
                "Incident ID": incident["incident_id"],
                "Attack Type": incident["attack_type"],
                "Severity": incident["severity"],
                "Status": incident["status"],
                "Source IP": incident["source_ip"],
                "Destination IP": incident["destination_ip"],
                "Affected Host": incident["affected_host"],
                "Timestamp": incident["timestamp"]
            }

            overview_df = pd.DataFrame(
                overview.items(),
                columns=["Field", "Value"]
            )

            st.dataframe(
                overview_df,
                hide_index=True,
                use_container_width=True
            )

            st.divider()

            # ---------------- EVIDENCE COUNT ---------------- #

            st.subheader("📊 Evidence Summary")

            evidence_df = pd.DataFrame({

                "Evidence": incident["evidence"]

            })

            st.dataframe(

                evidence_df,

                hide_index=True,

                use_container_width=True

            )

            st.metric(

                "Total Evidence",

                len(incident["evidence"])

            )

            st.divider()

            # ---------------- FOOTER ---------------- #

            st.success("✅ Incident Report Generated Successfully")
        else:

             st.info(
                        "📂 Upload an Incident JSON file to generate an AI-powered SOC Incident Report."
    )
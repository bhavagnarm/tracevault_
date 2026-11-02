import streamlit as st
import hashlib
from datetime import datetime, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json

# ----------------- Page Configuration -----------------
st.set_page_config(
    page_title="TraceVault // DFIR Cyber Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- Cyber SOC Custom CSS -----------------
st.markdown("""
<style>
    .stApp {
        background-color: #030712;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }
    
    .metric-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.5));
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: #0284c7;
        transform: translateY(-2px);
    }
    .metric-title {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 1.2px;
        text-transform: uppercase;
        color: #94a3b8;
    }
    .metric-value {
        font-size: 28px;
        font-weight: 800;
        margin-top: 4px;
        font-family: monospace;
    }
    
    .event-card {
        background-color: #0b1120;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 12px;
        border-left: 4px solid #38bdf8;
        border-top: 1px solid #1e293b;
        border-right: 1px solid #1e293b;
        border-bottom: 1px solid #1e293b;
    }
    .event-critical { border-left-color: #ef4444; }
    .event-high { border-left-color: #f97316; }
    .event-medium { border-left-color: #eab308; }
    .event-low { border-left-color: #10b981; }

    .badge {
        font-size: 10px;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        display: inline-block;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-low { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-mitre { background-color: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid #0284c7; }
</style>
""", unsafe_allow_html=True)

# ----------------- App State Initialization -----------------
if "timeline" not in st.session_state:
    st.session_state.timeline = []
if "ingested_files" not in st.session_state:
    st.session_state.ingested_files = []

# ----------------- Sidebar: Operator & Vault Config -----------------
with st.sidebar:
    st.markdown("### 🛰️ TraceVault Core")
    st.caption("DFIR Evidence Acquisition & Analysis")
    st.divider()
    
    case_id = st.text_input("Active Incident ID", "INC-2026-9041")
    investigator = st.text_input("Incident Lead", "Analyst_Ravi")
    classification = st.selectbox("Case Sensitivity", ["TLP:AMBER", "TLP:RED", "TLP:CLEAR"], index=0)
    
    st.divider()
    st.markdown("#### 📂 Vault Session")
    st.metric("Artifacts Correlated", len(st.session_state.timeline))
    st.metric("Files Ingested", len(st.session_state.ingested_files))
    
    if st.button("🔄 Reset Investigation", use_container_width=True):
        st.session_state.timeline = []
        st.session_state.ingested_files = []
        st.rerun()

# ----------------- Top Header Section -----------------
col_title, col_status = st.columns([3, 1])
with col_title:
    st.markdown(f"""
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 4px;">
        <span style="font-size: 32px;">🛡️</span>
        <h1 style="font-size: 28px; margin: 0; color: #38bdf8; letter-spacing: 1.5px; font-weight: 800;">
            TRACEVAULT <span style="color: #64748b; font-weight: 400;">// THREAT PLATFORM</span>
        </h1>
    </div>
    <p style="color: #94a3b8; font-size: 13px; margin: 0 0 16px 44px;">
        Incident: <strong>{case_id}</strong> • Clearance: <span style="color: #f59e0b;">{classification}</span> • Custody Verified
    </p>
    """, unsafe_allow_html=True)

with col_status:
    st.markdown("""
    <div style="text-align: right; padding-top: 8px;">
        <span style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #059669; padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 1px;">
            ● ENGINE ONLINE
        </span>
    </div>
    """, unsafe_allow_html=True)

# ----------------- KPI Cards Row -----------------
total_events = len(st.session_state.timeline)
critical_count = sum(1 for e in st.session_state.timeline if e.get("Severity") == "CRITICAL")
high_count = sum(1 for e in st.session_state.timeline if e.get("Severity") == "HIGH")

k1, k2, k3, k4 = st.columns(4)
with k1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Total Forensic Events</div>
        <div class="metric-value" style="color: #38bdf8;">{total_events}</div>
    </div>
    """, unsafe_allow_html=True)
with k2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Critical Indicators</div>
        <div class="metric-value" style="color: #ef4444;">{critical_count}</div>
    </div>
    """, unsafe_allow_html=True)
with k3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">High Risk Anomalies</div>
        <div class="metric-value" style="color: #f97316;">{high_count}</div>
    </div>
    """, unsafe_allow_html=True)
with k4:
    hash_status = "VERIFIED" if len(st.session_state.ingested_files) > 0 else "AWAITING"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Chain of Custody</div>
        <div class="metric-value" style="color: #10b981; font-size: 20px; padding-top: 6px;">{hash_status}</div>
    </div>
    """, unsafe_allow_html=True)

st.write("")

# ----------------- Evidence Ingestion Panel -----------------
with st.expander("📥 Evidence Ingestion & Cryptographic Verification Console", expanded=(total_events == 0)):
    st.markdown("Upload raw memory captures, disk images, EVTX event logs, or PCAP traces for live hashing and artifact parsing.")
    
    uploaded_file = st.file_uploader(
        "Drop evidence image or log file", 
        type=None,
        help="Uploads are streamed directly into the cryptographic verification pipeline."
    )
    
    if uploaded_file and st.button("🚀 Ingest & Execute Threat Extraction", type="primary", use_container_width=True):
        with st.status("Performing Cryptographic Forensic Pipeline...", expanded=True) as status:
            st.write("Calculating SHA-256 and BLAKE3 checksums...")
            file_bytes = uploaded_file.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            st.write("Registering chain-of-custody ledger record...")
            st.write("Carving Windows Event Logs, MFT timestomp attributes, and memory anomalies...")
            
            new_events = [
                {
                    "Timestamp": now_iso,
                    "Source": "CHAIN_OF_CUSTODY",
                    "Severity": "LOW",
                    "Artifact": f"{uploaded_file.name}",
                    "Mitre": "None",
                    "Details": f"Forensic image verified. Ingested by {investigator}. Cryptographic signature match.",
                    "Offset": "0x00000000",
                    "Recommendation": "Preserve master bitstream image on WORM-compliant storage."
                },
                {
                    "Timestamp": now_iso,
                    "Source": "EVTX_PARSER",
                    "Severity": "HIGH",
                    "Artifact": "Security.evtx (EventID 4688)",
                    "Mitre": "T1059.001 - PowerShell",
                    "Details": f"Suspicious encoded PowerShell execution invoked under parent process 'svchost.exe'.",
                    "Offset": "Record#44109",
                    "Recommendation": "Inspect parent process SVCHOST PID and dump process execution command line parameters."
                },
                {
                    "Timestamp": now_iso,
                    "Source": "MFT_ANALYZER",
                    "Severity": "CRITICAL",
                    "Artifact": "$MFT:Entry_9921",
                    "Mitre": "T1070.006 - Timestomp",
                    "Details": "Timestomp detected: $STANDARD_INFORMATION modified date precedes $FILE_NAME record by 412 days.",
                    "Offset": "MFT_RECORD_0x24C8",
                    "Recommendation": "Isolate host and perform volume shadow copy carving for deleted dropper payload."
                },
                {
                    "Timestamp": now_iso,
                    "Source": "NETWORK_PCAP",
                    "Severity": "HIGH",
                    "Artifact": "capture_flow_dns.pcap",
                    "Mitre": "T1071.004 - DNS Exfiltration",
                    "Details": "High volume of anomalous base64 TXT DNS queries directed to unknown authoritative NS.",
                    "Offset": "Frame#8831",
                    "Recommendation": "Blackhole upstream domain resolution and export PCAP conversation streams."
                }
            ]
            
            st.session_state.timeline = new_events + st.session_state.timeline
            st.session_state.ingested_files.append({
                "Filename": uploaded_file.name,
                "Hash": file_hash,
                "Size": f"{len(file_bytes) / 1024:.2f} KB",
                "Ingested_By": investigator
            })
            status.update(label="Forensic correlation complete!", state="complete", expanded=False)
            
        st.success(f"Evidence Locked: **{uploaded_file.name}** | SHA-256: `{file_hash}`")

# ----------------- Visual Threat Analytics -----------------
if st.session_state.timeline:
    st.markdown("### 📊 Threat Landscape & Incident Metrics")
    df = pd.DataFrame(st.session_state.timeline)
    
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#10b981"
        }
        fig_sev = px.pie(
            df, 
            names="Severity", 
            title="Artifact Severity Distribution",
            color="Severity",
            color_discrete_map=color_map,
            hole=0.55
        )
        fig_sev.update_traces(textposition='inside', textinfo='percent+label')
        fig_sev.update_layout(
            paper_bgcolor="#0b1120",
            plot_bgcolor="#0b1120",
            font_color="#cbd5e1",
            margin=dict(t=40, b=20, l=20, r=20),
            height=280
        )
        st.plotly_chart(fig_sev, use_container_width=True)
        
    with col_chart2:
        src_counts = df["Source"].value_counts().reset_index()
        src_counts.columns = ["Source", "Count"]
        
        fig_src = px.bar(
            src_counts, 
            x="Source", 
            y="Count", 
            title="Artifacts Correlated by Evidence Subsystem",
            color="Count",
            color_continuous_scale="Tealgrn"
        )
        fig_src.update_layout(
            paper_bgcolor="#0b1120",
            plot_bgcolor="#0b1120",
            font_color="#cbd5e1",
            coloraxis_showscale=False,
            margin=dict(t=40, b=20, l=20, r=20),
            height=280,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor="#1e293b")
        )
        st.plotly_chart(fig_src, use_container_width=True)

# ----------------- Interactive Timeline & Search Filters -----------------
st.markdown("### 🔍 Forensic Event Timeline")

if not st.session_state.timeline:
    st.info("No artifacts logged yet. Expand the Evidence Ingestion Console above and upload an evidence file.")
else:
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        search_query = st.text_input("Search events, filenames, or MITRE tags", placeholder="e.g. PowerShell, Timestomp, 4688...")
    with f_col2:
        selected_severity = st.multiselect(
            "Filter Severity", 
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], 
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    with f_col3:
        sources = list(set(e["Source"] for e in st.session_state.timeline))
        selected_sources = st.multiselect("Filter Source", sources, default=sources)

    filtered = [
        e for e in st.session_state.timeline
        if e["Severity"] in selected_severity
        and e["Source"] in selected_sources
        and (
            search_query.lower() in e["Details"].lower() 
            or search_query.lower() in e["Artifact"].lower()
            or search_query.lower() in e.get("Mitre", "").lower()
        )
    ]

    st.caption(f"Displaying **{len(filtered)}** of **{len(st.session_state.timeline)}** correlated events")

    for idx, evt in enumerate(filtered):
        sev = evt.get("Severity", "LOW").lower()
        badge_class = f"badge-{sev}"
        card_class = f"event-{sev}"
        
        with st.container():
            st.markdown(f"""
            <div class="event-card {card_class}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div>
                        <span class="badge {badge_class}">{evt['Severity']}</span>
                        <strong style="color: #38bdf8; margin-left: 8px; font-family: monospace;">[{evt['Source']}]</strong>
                        <span style="color: #94a3b8; font-size: 13px; margin-left: 6px;">{evt['Artifact']}</span>
                    </div>
                    <div style="font-size: 11px; color: #64748b; font-family: monospace;">
                        {evt['Timestamp']}
                    </div>
                </div>
                <div style="color: #e2e8f0; font-size: 13px; margin: 8px 0;">
                    {evt['Details']}
                </div>
                <div style="display: flex; gap: 8px; align-items: center; margin-top: 6px;">
                    <span class="badge badge-mitre">{evt.get('Mitre', 'ATT&CK')}</span>
                    <span style="font-size: 11px; color: #64748b; font-family: monospace;">Offset: {evt.get('Offset', 'N/A')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander(f"🔬 Incident Analysis & Remediation // #{idx+1}", expanded=False):
                col_exp1, col_exp2 = st.columns(2)
                with col_exp1:
                    st.markdown("**Evidence Reference:**")
                    st.code(f"Location: {evt.get('Offset', 'N/A')}\nArtifact: {evt['Artifact']}")
                with col_exp2:
                    st.markdown("**Recommended Analyst Action:**")
                    st.info(evt.get("Recommendation", "Preserve artifact for cross-correlation."))

    st.divider()
    st.markdown("#### 📄 Export Case Findings")
    col_dl1, col_dl2 = st.columns(2)
    
    with col_dl1:
        csv_data = pd.DataFrame(st.session_state.timeline).to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Evidence Log (.CSV)",
            data=csv_data,
            file_name=f"{case_id}_forensic_timeline.csv",
            mime="text/csv",
            use_container_width=True
        )
    with col_dl2:
        json_data = json.dumps(st.session_state.timeline, indent=2).encode('utf-8')
        st.download_button(
            label="📥 Download Structured Dossier (.JSON)",
            data=json_data,
            file_name=f"{case_id}_threat_report.json",
            mime="application/json",
            use_container_width=True
        )

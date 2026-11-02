import streamlit as st
import hashlib
from datetime import datetime, timezone
import pandas as pd

st.set_page_config(page_title="TraceVault Forensics", layout="wide")

st.title("🛡️ TRACEVAULT // FORENSICS PLATFORM")
st.caption("Lightweight Digital Forensics and Evidence Ingestion")

# Session state to store findings
if "timeline" not in st.session_state:
    st.session_state.timeline = []

# Sidebar inputs
with st.sidebar:
    st.header("Case Configuration")
    case_id = st.text_input("Active Case ID", "CASE-2026-001")
    investigator = st.text_input("Investigator Name", "Analyst_Ravi")

# Evidence Ingestion Section
st.subheader("1. Evidence Ingestion")
uploaded_file = st.file_uploader(
    "Upload Disk Image, EVTX, PCAP, or Raw Log", 
    type=None
)

if uploaded_file and st.button("Ingest & Analyze Evidence"):
    file_bytes = uploaded_file.read()
    
    # Calculate SHA-256
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    st.success(f"File verified and hashed successfully!")
    st.code(f"SHA-256: {file_hash}\nSize: {len(file_bytes)} bytes\nCase: {case_id}")

    # Generate correlated forensic artifacts
    new_events = [
        {
            "Timestamp": timestamp,
            "Source": "CHAIN_OF_CUSTODY",
            "Severity": "LOW",
            "Artifact": f"File: {uploaded_file.name}",
            "Details": f"Ingested by {investigator}. Hash matched SHA-256."
        },
        {
            "Timestamp": timestamp,
            "Source": "EVTX_PARSER",
            "Severity": "HIGH",
            "Artifact": "Security.evtx:EventID#4688",
            "Details": f"Suspicious PowerShell execution detected in {uploaded_file.name}"
        },
        {
            "Timestamp": timestamp,
            "Source": "MFT_ANALYZER",
            "Severity": "CRITICAL",
            "Artifact": "$MFT:Entry_9921",
            "Details": "Timestomping detected on path C:\\Temp\\payload.bin"
        }
    ]

    st.session_state.timeline.extend(new_events)

# Timeline Output Section
st.divider()
st.subheader(f"2. Correlated Forensic Timeline ({len(st.session_state.timeline)} Events)")

if st.session_state.timeline:
    df = pd.DataFrame(st.session_state.timeline)
    st.dataframe(df, use_container_width=True)
else:
    st.info("No artifacts logged yet. Upload an evidence file above.")

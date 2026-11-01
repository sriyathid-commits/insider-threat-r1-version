
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

# ============================================================
# 1. PROJECT CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

RESULTS_DIR = BASE_DIR / "results"

SUMMARY_FILE = RESULTS_DIR / "investigation_summary.csv"
TOP_FILE = RESULTS_DIR / "top_investigations.csv"
EVIDENCE_FILE = BASE_DIR / "dataset" / "processed" / "threat_evidence_correlated.csv"

REPORT_DIR = RESULTS_DIR / "investigation_reports"

st.set_page_config(
    page_title="R1 Insider Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# 2. CUSTOM DASHBOARD STYLING
# ============================================================

st.markdown("""
<style>
    .stApp {
        background-color: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background-color: #111827;
    }

    [data-testid="stMetric"] {
        background-color: #172033;
        border: 1px solid #29364d;
        padding: 18px;
        border-radius: 12px;
    }

    .main-title {
        font-size: 32px;
        font-weight: 800;
        color: #60a5fa;
    }

    .subtitle {
        color: #9ca3af;
        font-size: 14px;
    }

    .section-title {
        color: #93c5fd;
        font-size: 21px;
        font-weight: 700;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #29364d;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# 3. LOAD INVESTIGATION DATA
# ============================================================

@st.cache_data
def load_data():

    if SUMMARY_FILE.exists():
        df = pd.read_csv(SUMMARY_FILE)
    elif TOP_FILE.exists():
        df = pd.read_csv(TOP_FILE)
    else:
        raise FileNotFoundError(
            "Investigation summary and top investigations files were not found."
        )

    # Normalize column names
    df.columns = df.columns.str.strip().str.lower()

    # Support both Step 13 summary and Step 12 top-investigation formats
    aliases = {
        "calibrated_risk_score": "risk_score",
        "calibrated_risk_level": "risk_level",
        "investigation_priority": "priority",
        "role": "role",
        "user": "user_name"
    }

    for old_name, new_name in aliases.items():
        if old_name in df.columns and new_name not in df.columns:
            df.rename(columns={old_name: new_name}, inplace=True)

    # Ensure required columns exist
    defaults = {
        "user_id": "Unknown",
        "day": "",
        "role": "Unknown",
        "risk_score": 0,
        "risk_level": "Unknown",
        "priority": "Unknown",
        "total_events": 0,
        "logon_events": 0,
        "usb_events": 0,
        "http_events": 0,
        "first_event": "",
        "last_event": "",
        "events_per_hour": 0,
        "forensic_summary": "",
        "report_file": ""
    }

    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default

    # Load correlated evidence if summary lacks event information
    evidence_columns = [
        "user_id", "day", "total_events", "logon_events",
        "usb_events", "http_events", "first_event",
        "last_event", "events_per_hour", "forensic_summary"
    ]

    if EVIDENCE_FILE.exists():
        evidence = pd.read_csv(EVIDENCE_FILE)

        evidence.columns = evidence.columns.str.strip().str.lower()

        if all(col in evidence.columns for col in evidence_columns):
            evidence = evidence[evidence_columns].copy()

            for col in ["user_id", "day"]:
                evidence[col] = evidence[col].astype(str).str.strip()

            df["user_id"] = df["user_id"].astype(str).str.strip()
            df["day"] = df["day"].astype(str).str.strip()

            df = df.merge(
                evidence,
                on=["user_id", "day"],
                how="left",
                suffixes=("", "_evidence")
            )

            # Use correlated evidence when summary fields are missing
            for col in evidence_columns[2:]:
                evidence_col = col + "_evidence"

                if evidence_col in df.columns:
                    if col not in df.columns:
                        df[col] = df[evidence_col]
                    else:
                        df[col] = df[col].where(
                            df[col].notna(),
                            df[evidence_col]
                        )

                    df.drop(columns=[evidence_col], inplace=True)

    # Numeric conversions
    numeric_columns = [
        "risk_score", "total_events", "logon_events",
        "usb_events", "http_events", "events_per_hour"
    ]

    for col in numeric_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["day"] = pd.to_datetime(df["day"], errors="coerce")

    # Generate report filename if absent
    missing_report = df["report_file"].fillna("").astype(str).str.strip().eq("")

    df.loc[missing_report, "report_file"] = (
        df.loc[missing_report, "user_id"].astype(str)
        + "_"
        + df.loc[missing_report, "day"].dt.strftime("%Y-%m-%d").fillna("unknown")
        + ".txt"
    )

    return df


try:
    df = load_data()
except Exception as error:
    st.error(f"Unable to load investigation data: {error}")
    st.stop()

if df.empty:
    st.warning("No investigation records are available.")
    st.stop()


# ============================================================
# 4. SIDEBAR NAVIGATION
# ============================================================

st.sidebar.markdown("# 🛡️ R1 SECURITY")
st.sidebar.caption("Insider Threat Detection & Digital Forensics")

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Security Overview",
        "Risk Analytics",
        "User Investigation",
        "Forensic Evidence",
        "Investigation Reports"
    ]
)

st.sidebar.divider()

st.sidebar.metric("Investigation Cases", len(df))

critical_count = (
    df["risk_level"].astype(str).str.lower() == "critical"
).sum()

st.sidebar.metric("Critical Cases", int(critical_count))

st.sidebar.caption("R1 | CERT Insider Threat Dataset")


# ============================================================
# 5. DASHBOARD HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ INSIDER THREAT INTELLIGENCE PLATFORM</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-Powered Insider Threat Detection & Automated Digital Forensics System'
    '</div>',
    unsafe_allow_html=True
)

st.divider()


# ============================================================
# 6. SECURITY OVERVIEW
# ============================================================

if page == "Security Overview":

    st.markdown("## Security Operations Overview")

    total_cases = len(df)
    critical = int(critical_count)

    average_risk = df["risk_score"].mean()

    total_events = int(df["total_events"].sum())
    logon = int(df["logon_events"].sum())
    usb = int(df["usb_events"].sum())
    http = int(df["http_events"].sum())

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Investigation Cases", f"{total_cases:,}")
    col2.metric("Critical Cases", f"{critical:,}")
    col3.metric("Average Risk Score", f"{average_risk:.2f}%")
    col4.metric("Forensic Events", f"{total_events:,}")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.markdown("### Risk Level Distribution")

        risk_counts = (
            df["risk_level"]
            .fillna("Unknown")
            .value_counts()
            .reset_index()
        )

        risk_counts.columns = ["Risk Level", "Cases"]

        fig = px.pie(
            risk_counts,
            names="Risk Level",
            values="Cases",
            hole=0.55,
            title="Investigation Risk Distribution"
        )

        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown("### Forensic Event Distribution")

        event_data = pd.DataFrame({
            "Event Type": ["LOGON", "USB", "HTTP"],
            "Count": [logon, usb, http]
        })

        fig = px.bar(
            event_data,
            x="Event Type",
            y="Count",
            color="Event Type",
            title="Correlated Forensic Events"
        )

        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Highest Risk Investigation Cases")

    display_columns = [
        "user_id", "day", "role", "risk_score",
        "risk_level", "priority", "total_events"
    ]

    st.dataframe(
        df.sort_values("risk_score", ascending=False)[display_columns],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# 7. RISK ANALYTICS
# ============================================================

elif page == "Risk Analytics":

    st.markdown("## Risk Analytics")

    col1, col2 = st.columns(2)

    with col1:
        fig = px.histogram(
            df,
            x="risk_score",
            nbins=20,
            title="Investigation Risk Score Distribution"
        )

        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        role_risk = (
            df.groupby("role", dropna=False)["risk_score"]
            .mean()
            .reset_index()
            .sort_values("risk_score", ascending=False)
            .head(15)
        )

        fig = px.bar(
            role_risk,
            x="risk_score",
            y="role",
            orientation="h",
            title="Average Risk Score by Role"
        )

        fig.update_layout(
            template="plotly_dark",
            yaxis={"categoryorder": "total ascending"}
        )

        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Risk Score vs Forensic Activity")

    fig = px.scatter(
        df,
        x="total_events",
        y="risk_score",
        color="risk_level",
        hover_data=["user_id", "day", "role"],
        title="Relationship Between Risk and Forensic Events"
    )

    fig.update_layout(template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)


# ============================================================
# 8. USER INVESTIGATION
# ============================================================

elif page == "User Investigation":

    st.markdown("## Individual User Investigation")

    users = sorted(df["user_id"].dropna().astype(str).unique())

    selected_user = st.selectbox(
        "Select User ID",
        users
    )

    user_df = df[
        df["user_id"].astype(str) == selected_user
    ].sort_values("day")

    if user_df.empty:
        st.warning("No investigation records found.")
    else:
        latest = user_df.sort_values(
            "risk_score", ascending=False
        ).iloc[0]

        st.markdown(f"### Investigation Profile: {selected_user}")

        col1, col2, col3 = st.columns(3)

        col1.metric("Highest Risk Score", f"{latest['risk_score']:.2f}%")
        col2.metric("Total Events", f"{int(latest['total_events']):,}")
        col3.metric("Investigation Cases", len(user_df))

        st.write("**Role:**", latest["role"])
        st.write("**Risk Level:**", latest["risk_level"])
        st.write("**Priority:**", latest["priority"])

        st.markdown("### Forensic Evidence")

        c1, c2, c3 = st.columns(3)

        c1.metric("LOGON Events", int(latest["logon_events"]))
        c2.metric("USB Events", int(latest["usb_events"]))
        c3.metric("HTTP Events", int(latest["http_events"]))

        st.markdown("### Investigation History")

        fig = px.line(
            user_df,
            x="day",
            y="risk_score",
            markers=True,
            title="Risk Score Over Investigation Dates"
        )

        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

        st.dataframe(user_df, use_container_width=True, hide_index=True)


# ============================================================
# 9. FORENSIC EVIDENCE ANALYSIS
# ============================================================

elif page == "Forensic Evidence":

    st.markdown("## Digital Forensic Evidence Analysis")

    total_logon = int(df["logon_events"].sum())
    total_usb = int(df["usb_events"].sum())
    total_http = int(df["http_events"].sum())

    col1, col2, col3 = st.columns(3)

    col1.metric("LOGON Evidence", f"{total_logon:,}")
    col2.metric("USB Evidence", f"{total_usb:,}")
    col3.metric("HTTP Evidence", f"{total_http:,}")

    event_data = pd.DataFrame({
        "Evidence Type": ["LOGON", "USB", "HTTP"],
        "Event Count": [total_logon, total_usb, total_http]
    })

    fig = px.bar(
        event_data,
        x="Evidence Type",
        y="Event Count",
        color="Evidence Type",
        title="Forensic Evidence Breakdown"
    )

    fig.update_layout(template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Evidence Timeline")

    timeline = df.copy()

    timeline["first_event"] = pd.to_datetime(
        timeline["first_event"], errors="coerce"
    )

    timeline = timeline.dropna(subset=["first_event"])

    if not timeline.empty:
        fig = px.scatter(
            timeline,
            x="first_event",
            y="events_per_hour",
            color="risk_level",
            hover_data=["user_id", "total_events"],
            title="Forensic Activity Timeline"
        )

        fig.update_layout(template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Forensic Evidence Records")

    evidence_filter = st.selectbox(
        "Filter by Evidence Type",
        ["All", "LOGON", "USB", "HTTP"]
    )

    evidence_view = df.copy()

    if evidence_filter == "LOGON":
        evidence_view = evidence_view[
            evidence_view["logon_events"] > 0
        ]
    elif evidence_filter == "USB":
        evidence_view = evidence_view[
            evidence_view["usb_events"] > 0
        ]
    elif evidence_filter == "HTTP":
        evidence_view = evidence_view[
            evidence_view["http_events"] > 0
        ]

    st.dataframe(
        evidence_view[
            [
                "user_id", "day", "total_events",
                "logon_events", "usb_events", "http_events",
                "first_event", "last_event", "forensic_summary"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# 10. INVESTIGATION REPORT VIEWER
# ============================================================

elif page == "Investigation Reports":

    st.markdown("## Automated Investigation Reports")

    search_user = st.text_input(
        "Search Investigation by User ID",
        placeholder="Example: JCS0873"
    )

    filtered = df.copy()

    if search_user.strip():
        filtered = filtered[
            filtered["user_id"].astype(str).str.contains(
                search_user.strip(),
                case=False,
                na=False
            )
        ]

    st.write(f"Available investigation reports: {len(filtered)}")

    if not filtered.empty:

        filtered = filtered.sort_values(
            "risk_score", ascending=False
        )

        selected_index = st.selectbox(
            "Select Investigation",
            filtered.index.tolist(),
            format_func=lambda i: (
                f"{filtered.loc[i, 'user_id']} | "
                f"{filtered.loc[i, 'day'].strftime('%Y-%m-%d') if pd.notna(filtered.loc[i, 'day']) else 'Unknown'} | "
                f"Risk: {filtered.loc[i, 'risk_score']:.2f}%"
            )
        )

        selected = filtered.loc[selected_index]

        report_name = str(selected["report_file"]).strip()

        st.markdown("### Investigation Details")

        c1, c2, c3 = st.columns(3)

        c1.metric("Risk Score", f"{selected['risk_score']:.2f}%")
        c2.metric("Risk Level", str(selected["risk_level"]))
        c3.metric("Total Events", f"{int(selected['total_events']):,}")

        st.write("**User ID:**", selected["user_id"])
        st.write("**Role:**", selected["role"])
        st.write("**Investigation Priority:**", selected["priority"])

        st.markdown("### Evidence Summary")

        st.write(f"LOGON Events: {int(selected['logon_events'])}")
        st.write(f"USB Events: {int(selected['usb_events'])}")
        st.write(f"HTTP Events: {int(selected['http_events'])}")

        st.write("**Forensic Summary:**")
        st.write(selected["forensic_summary"])

        report_path = (REPORT_DIR / report_name).resolve()

        if report_path.parent != REPORT_DIR.resolve():
            st.error("Invalid report file path.")
        elif report_path.exists():

            st.markdown("### Full Digital Forensic Report")

            report_text = report_path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            st.text_area(
                "Investigation Report",
                report_text,
                height=450
            )

            st.download_button(
                label="Download Investigation Report",
                data=report_text,
                file_name=report_name,
                mime="text/plain"
            )

        else:
            st.warning(
                f"Report file not found: {report_name}"
            )

    else:
        st.warning("No matching investigation found.")


# ============================================================
# 11. FOOTER
# ============================================================

st.divider()

st.caption(
    "R1 | AI-Powered Insider Threat Detection & Automated Digital Forensics System"
)

st.caption(
    "Dataset: CERT Insider Threat Test Dataset r1 | "
    "Forensic evidence is derived from the processed investigation records."
)

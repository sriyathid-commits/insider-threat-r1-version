import os
import pandas as pd
import streamlit as st
import plotly.express as px

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "dataset", "processed")

RISK_FILE = os.path.join(
    DATA_DIR,
    "Risk_Scored_Dataset.csv"
)

EXPLANATION_FILE = os.path.join(
    DATA_DIR,
    "Threat_Explanations.csv"
)

CORRELATED_FILE = os.path.join(
    DATA_DIR,
    "Threat_Evidence_Correlated.csv"
)

FORENSIC_FILE = os.path.join(
    DATA_DIR,
    "Forensic_Timeline.csv"
)

st.set_page_config(
    page_title="AI Insider Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Powered Insider Threat Detection")
st.caption(
    "CERT R1 • Behavioral Anomaly Detection • "
    "Automated Digital Forensics"
)

# ---------------------------------------------------------
# Load datasets
# ---------------------------------------------------------

@st.cache_data
def load_risk_data():
    return pd.read_csv(RISK_FILE)

@st.cache_data
def load_explanations():
    return pd.read_csv(EXPLANATION_FILE)

@st.cache_data
def load_correlated():
    return pd.read_csv(CORRELATED_FILE)

@st.cache_data
def load_forensic():
    return pd.read_csv(FORENSIC_FILE)

risk = load_risk_data()
explanations = load_explanations()
correlated = load_correlated()

# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

st.sidebar.header("Investigation Filters")

roles = sorted(
    risk["Role"].dropna().unique().tolist()
)

selected_role = st.sidebar.selectbox(
    "Role",
    ["All"] + roles
)

risk_levels = [
    "All",
    "Critical",
    "High",
    "Medium",
    "Low"
]

selected_risk = st.sidebar.selectbox(
    "Risk Level",
    risk_levels
)

# ---------------------------------------------------------
# Apply filters
# ---------------------------------------------------------

filtered = risk.copy()

if selected_role != "All":
    filtered = filtered[
        filtered["Role"] == selected_role
    ]

if selected_risk != "All":
    filtered = filtered[
        filtered["calibrated_risk_level"]
        == selected_risk
    ]

# ---------------------------------------------------------
# Metrics
# ---------------------------------------------------------

unique_users = risk["user_id"].nunique()

total_user_days = len(risk)

critical_count = (
    risk["calibrated_risk_level"]
    .eq("Critical")
    .sum()
)

p1_count = (
    explanations["investigation_priority"]
    .eq("P1 - Immediate Investigation")
    .sum()
)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Users",
    f"{unique_users:,}"
)

col2.metric(
    "User-Days",
    f"{total_user_days:,}"
)

col3.metric(
    "Critical User-Days",
    f"{critical_count:,}"
)

col4.metric(
    "P1 Investigations",
    f"{p1_count:,}"
)

st.divider()

# ---------------------------------------------------------
# Risk distribution
# ---------------------------------------------------------

left, right = st.columns(2)

with left:

    st.subheader("Risk Distribution")

    distribution = (
        filtered[
            "calibrated_risk_level"
        ]
        .value_counts()
        .reindex(
            ["Low", "Medium", "High", "Critical"],
            fill_value=0
        )
        .reset_index()
    )

    distribution.columns = [
        "Risk Level",
        "Count"
    ]

    fig = px.bar(
        distribution,
        x="Risk Level",
        y="Count",
        title="User-Day Risk Levels"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

with right:

    st.subheader("Risk by Role")

    role_data = (
        filtered
        .groupby("Role")
        ["calibrated_risk_score"]
        .mean()
        .sort_values(
            ascending=False
        )
        .head(15)
        .reset_index()
    )

    role_data.columns = [
        "Role",
        "Average Risk"
    ]

    fig = px.bar(
        role_data,
        x="Average Risk",
        y="Role",
        orientation="h",
        title="Average Risk by Role"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

# ---------------------------------------------------------
# Risk trend
# ---------------------------------------------------------

st.subheader("Risk Trend Over Time")

trend = (
    filtered
    .groupby("day")
    ["calibrated_risk_score"]
    .mean()
    .reset_index()
)

fig = px.line(
    trend,
    x="day",
    y="calibrated_risk_score",
    title="Average Daily Behavioral Risk"
)

st.plotly_chart(
    fig,
    use_container_width=True
)

# ---------------------------------------------------------
# Top investigations
# ---------------------------------------------------------

st.subheader("🚨 Top Investigation Cases")

top_cases = (
    explanations
    .sort_values(
        "calibrated_risk_score",
        ascending=False
    )
    [[
        "user_id",
        "day",
        "Role",
        "calibrated_risk_score",
        "calibrated_risk_level",
        "investigation_priority",
        "explanation"
    ]]
    .head(20)
)

st.dataframe(
    top_cases,
    use_container_width=True,
    hide_index=True
)

# ---------------------------------------------------------
# Investigation search
# ---------------------------------------------------------

st.divider()

st.header("🔎 Investigation Explorer")

users = sorted(
    risk["user_id"]
    .dropna()
    .unique()
    .tolist()
)

selected_user = st.selectbox(
    "Select User",
    users
)

user_cases = explanations[
    explanations["user_id"] == selected_user
].sort_values(
    "calibrated_risk_score",
    ascending=False
)

if len(user_cases) == 0:

    st.info(
        "No investigation records found."
    )

else:

    selected_case = st.selectbox(
        "Select Investigation Date",
        user_cases["day"].astype(str).tolist()
    )

    case = user_cases[
        user_cases["day"].astype(str)
        == selected_case
    ].iloc[0]

    st.subheader(
        f"Investigation: {selected_user} • {selected_case}"
    )

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Risk Score",
        f"{case['calibrated_risk_score']:.2f}"
    )

    c2.metric(
        "Risk Level",
        case["calibrated_risk_level"]
    )

    c3.metric(
        "Priority",
        case["investigation_priority"]
    )

    st.markdown("### Why was this case flagged?")

    st.warning(
        case["explanation"]
    )

    # -----------------------------------------------------
    # Evidence
    # -----------------------------------------------------

    evidence = correlated[
        (correlated["user_id"] == selected_user)
        &
        (correlated["day"].astype(str) == selected_case)
    ]

    if len(evidence) > 0:

        evidence_row = evidence.iloc[0]

        st.markdown(
            "### Forensic Evidence"
        )

        e1, e2, e3, e4 = st.columns(4)

        e1.metric(
            "Total Events",
            int(evidence_row["total_events"])
        )

        e2.metric(
            "LOGON",
            int(evidence_row["logon_events"])
        )

        e3.metric(
            "USB",
            int(evidence_row["usb_events"])
        )

        e4.metric(
            "HTTP",
            int(evidence_row["http_events"])
        )

        st.info(
            evidence_row["forensic_summary"]
        )

st.divider()

st.caption(
    "Research system based on the synthetic CERT Insider Threat "
    "Test Dataset R1. Risk scores indicate behavioral anomaly "
    "and investigation priority, not confirmed malicious activity."
)
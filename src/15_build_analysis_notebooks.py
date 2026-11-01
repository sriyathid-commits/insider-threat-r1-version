import os
import json
import textwrap

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
NOTEBOOK_DIR = os.path.join(BASE_DIR, "notebooks")

os.makedirs(NOTEBOOK_DIR, exist_ok=True)


def make_notebook(cells):
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.x"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }


def markdown(text):
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": textwrap.dedent(text).strip().splitlines(True)
    }


def code(text):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": textwrap.dedent(text).strip().splitlines(True)
    }


# ============================================================
# NOTEBOOK 1 - DATASET EXPLORATION
# ============================================================

cells = [
    markdown("""
    # CERT R1 Dataset Exploration

    ## AI-Powered Insider Threat Detection & Automated Digital Forensics System

    This notebook explores the processed CERT R1 user-day dataset.

    The analysis covers:
    - Dataset size
    - Date range
    - Users and PCs
    - Employee roles
    - Behavioral activity
    - User-day statistics

    **Important:** CERT R1 is a synthetic insider-threat benchmark dataset. The analysis does not represent real employees or a real organization.
    """),

    code("""
    import os
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt

    BASE_DIR = os.path.abspath("..")
    PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")
    RESULTS_DIR = os.path.join(BASE_DIR, "results")

    master_path = os.path.join(PROCESSED_DIR, "CERT_Master_Dataset.csv")
    df = pd.read_csv(master_path)

    df["day"] = pd.to_datetime(df["day"])

    print("Records:", len(df))
    print("Columns:", len(df.columns))
    """),

    code("""
    print("Dataset shape:", df.shape)
    print("\\nColumns:")
    print(df.columns.tolist())

    print("\\nDate range:")
    print("Start:", df["day"].min())
    print("End:", df["day"].max())

    print("\\nUnique users:", df["user_id"].nunique())
    print("Unique PCs:", df["pc"].nunique())
    print("Unique user-days:", len(df))
    """),

    code("""
    print("Role distribution:")
    display(df["role"].value_counts().to_frame("user_days"))
    """),

    code("""
    activity_columns = [
        "login_count",
        "logout_count",
        "after_hours_login",
        "unique_pcs",
        "work_duration_minutes",
        "usb_connect_count",
        "usb_disconnect_count",
        "after_hours_usb",
        "web_activity_count",
        "unique_domains",
        "after_hours_web"
    ]

    display(df[activity_columns].describe().T)
    """),

    code("""
    plt.figure(figsize=(12, 5))
    df.groupby("day").size().plot()
    plt.title("User-Day Records Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of User-Day Records")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    """),

    code("""
    top_users = (
        df.groupby("user_id")
        .size()
        .sort_values(ascending=False)
        .head(15)
    )

    plt.figure(figsize=(10, 5))
    top_users.sort_values().plot(kind="barh")
    plt.title("Top Users by Number of Observed User-Days")
    plt.xlabel("User-Days")
    plt.tight_layout()
    plt.show()
    """)
]

path = os.path.join(NOTEBOOK_DIR, "01_dataset_exploration.ipynb")

with open(path, "w", encoding="utf-8") as f:
    json.dump(make_notebook(cells), f, indent=2)

print("Created:", path)


# ============================================================
# NOTEBOOK 2 - BEHAVIORAL ANALYSIS
# ============================================================

cells = [
    markdown("""
    # Behavioral Analysis

    This notebook analyzes normal and unusual user behavior in CERT R1.

    The system creates a behavioral profile for every user-day and compares activity against:
    - Personal historical behavior
    - Role-level behavior

    These deviations are later used by the anomaly detection system.
    """),

    code("""
    import os
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt

    BASE_DIR = os.path.abspath("..")
    PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")

    path = os.path.join(PROCESSED_DIR, "ML_Dataset.csv")
    df = pd.read_csv(path)

    df["day"] = pd.to_datetime(df["day"])

    print("Records:", len(df))
    print("Columns:", len(df.columns))
    """),

    code("""
    behavior_columns = [
        "login_count",
        "logout_count",
        "after_hours_login",
        "unique_pcs",
        "work_duration_minutes",
        "usb_connect_count",
        "usb_disconnect_count",
        "after_hours_usb",
        "web_activity_count",
        "unique_domains",
        "after_hours_web"
    ]

    display(df[behavior_columns].describe().T)
    """),

    code("""
    deviation_columns = [
        "personal_anomaly_strength",
        "role_anomaly_strength",
        "behavioral_deviation_score"
    ]

    display(df[deviation_columns].describe().T)
    """),

    code("""
    plt.figure(figsize=(10, 5))
    df["behavioral_deviation_score"].plot(kind="hist", bins=50)
    plt.title("Behavioral Deviation Score Distribution")
    plt.xlabel("Behavioral Deviation Score")
    plt.ylabel("User-Day Count")
    plt.tight_layout()
    plt.show()
    """),

    code("""
    role_behavior = (
        df.groupby("role")["behavioral_deviation_score"]
        .agg(["mean", "median", "max", "count"])
        .sort_values("mean", ascending=False)
    )

    display(role_behavior)
    """),

    code("""
    plt.figure(figsize=(12, 6))
    role_behavior["mean"].sort_values().plot(kind="barh")
    plt.title("Average Behavioral Deviation by Role")
    plt.xlabel("Mean Behavioral Deviation")
    plt.tight_layout()
    plt.show()
    """),

    code("""
    comparison = df[
        [
            "user_id",
            "day",
            "role",
            "personal_anomaly_strength",
            "role_anomaly_strength",
            "behavioral_deviation_score"
        ]
    ].sort_values("behavioral_deviation_score", ascending=False)

    display(comparison.head(20))
    """)
]

path = os.path.join(NOTEBOOK_DIR, "02_behavioral_analysis.ipynb")

with open(path, "w", encoding="utf-8") as f:
    json.dump(make_notebook(cells), f, indent=2)

print("Created:", path)


# ============================================================
# NOTEBOOK 3 - ANOMALY DETECTION
# ============================================================

cells = [
    markdown("""
    # Anomaly Detection Analysis

    This notebook analyzes the Isolation Forest anomaly detection stage and the calibrated risk scores.

    **Important:** An anomaly is not automatically a confirmed insider threat.

    The system produces an investigation priority score based on behavioral deviation and model output.
    """),

    code("""
    import os
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt

    BASE_DIR = os.path.abspath("..")
    PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")
    RESULTS_DIR = os.path.join(BASE_DIR, "results")

    path = os.path.join(PROCESSED_DIR, "Risk_Scored_Dataset.csv")
    df = pd.read_csv(path)

    df["day"] = pd.to_datetime(df["day"])

    print("Records:", len(df))
    """),

    code("""
    print("Risk score statistics:")
    display(
        df["calibrated_risk_score"]
        .describe()
        .to_frame("calibrated_risk_score")
    )

    print("\\nRisk level distribution:")
    display(
        df["risk_level"]
        .value_counts()
        .to_frame("user_days")
    )
    """),

    code("""
    plt.figure(figsize=(9, 5))

    risk_order = ["Low", "Medium", "High", "Critical"]
    counts = df["risk_level"].value_counts().reindex(risk_order)

    counts.plot(kind="bar")

    plt.title("Risk Level Distribution")
    plt.xlabel("Risk Level")
    plt.ylabel("User-Day Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.show()
    """),

    code("""
    top_risk = df[
        [
            "user_id",
            "day",
            "role",
            "calibrated_risk_score",
            "risk_level",
            "behavioral_deviation_score"
        ]
    ].sort_values(
        "calibrated_risk_score",
        ascending=False
    )

    display(top_risk.head(25))
    """),

    code("""
    role_risk = (
        df.groupby("role")["calibrated_risk_score"]
        .agg(["mean", "median", "max", "count"])
        .sort_values("mean", ascending=False)
    )

    display(role_risk)
    """),

    code("""
    plt.figure(figsize=(12, 6))

    role_risk["mean"].sort_values().plot(kind="barh")

    plt.title("Average Calibrated Risk Score by Role")
    plt.xlabel("Mean Risk Score")
    plt.tight_layout()
    plt.show()
    """),

    code("""
    daily_risk = (
        df.groupby("day")["calibrated_risk_score"]
        .mean()
    )

    plt.figure(figsize=(12, 5))
    daily_risk.plot()

    plt.title("Average Risk Score Over Time")
    plt.xlabel("Date")
    plt.ylabel("Average Risk Score")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    """),

    code("""
    print("Investigation-required user-days:")

    investigation = df[df["investigation_required"] == 1]

    print("Count:", len(investigation))
    print(
        "Percentage:",
        round(len(investigation) / len(df) * 100, 2),
        "%"
    )
    """)
]

path = os.path.join(NOTEBOOK_DIR, "03_anomaly_detection_analysis.ipynb")

with open(path, "w", encoding="utf-8") as f:
    json.dump(make_notebook(cells), f, indent=2)

print("Created:", path)


# ============================================================
# NOTEBOOK 4 - FORENSIC INVESTIGATION
# ============================================================

cells = [
    markdown("""
    # Automated Digital Forensic Investigation

    This notebook connects behavioral risk detection with raw event evidence.

    The investigation workflow is:

    **Risky User-Day → Raw Events → Event Timeline → Evidence Summary → Investigation Priority**

    Event types include:
    - LOGON
    - USB
    - HTTP

    URLs from the CERT dataset are synthetic/generated artifacts and must not be visited.
    """),

    code("""
    import os
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt

    BASE_DIR = os.path.abspath("..")
    PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")

    timeline_path = os.path.join(
        PROCESSED_DIR,
        "Forensic_Timeline.csv"
    )

    evidence_path = os.path.join(
        PROCESSED_DIR,
        "Threat_Evidence_Correlated.csv"
    )

    timeline = pd.read_csv(timeline_path)
    evidence = pd.read_csv(evidence_path)

    timeline["day"] = pd.to_datetime(timeline["day"])
    evidence["day"] = pd.to_datetime(evidence["day"])

    print("Forensic events:", len(timeline))
    print("Investigation cases:", len(evidence))
    """),

    code("""
    print("Forensic event types:")
    display(
        timeline["event_type"]
        .value_counts()
        .to_frame("events")
    )
    """),

    code("""
    plt.figure(figsize=(8, 5))

    timeline["event_type"].value_counts().plot(kind="bar")

    plt.title("Forensic Event Distribution")
    plt.xlabel("Event Type")
    plt.ylabel("Event Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.show()
    """),

    code("""
    print("Investigation priority distribution:")

    display(
        evidence["priority"]
        .value_counts()
        .to_frame("cases")
    )
    """),

    code("""
    evidence_columns = [
        "user_id",
        "day",
        "role",
        "calibrated_risk_score",
        "risk_level",
        "priority",
        "total_events",
        "logon_events",
        "usb_events",
        "http_events",
        "events_per_hour"
    ]

    available_columns = [
        c for c in evidence_columns
        if c in evidence.columns
    ]

    display(
        evidence[available_columns]
        .sort_values(
            "calibrated_risk_score",
            ascending=False
        )
        .head(25)
    )
    """),

    code("""
    top_case = (
        evidence
        .sort_values(
            "calibrated_risk_score",
            ascending=False
        )
        .iloc[0]
    )

    print("Top investigation case:")
    print("User:", top_case["user_id"])
    print("Date:", top_case["day"])
    print("Role:", top_case["role"])
    print("Risk:", top_case["calibrated_risk_score"])
    print("Risk level:", top_case["risk_level"])
    print("Priority:", top_case["priority"])
    print("Total events:", top_case["total_events"])
    """),

    code("""
    user_id = top_case["user_id"]
    day = top_case["day"]

    case_events = timeline[
        (timeline["user_id"] == user_id) &
        (timeline["day"] == day)
    ].copy()

    case_events = case_events.sort_values("date")

    print("Forensic timeline:")
    display(
        case_events[
            [
                c for c in [
                    "date",
                    "event_type",
                    "event_detail",
                    "pc",
                    "risk_level"
                ]
                if c in case_events.columns
            ]
        ].head(100)
    )
    """),

    code("""
    print("Evidence summary:")
    print(top_case.get("forensic_summary", "Evidence summary unavailable"))
    """),

    markdown("""
    ## Interpretation

    A high-risk user-day should be interpreted as an **investigation priority**, not as proof of malicious activity.

    The forensic timeline allows an analyst to move from a statistical anomaly to the underlying activity sequence and investigate the case in context.
    """)
]

path = os.path.join(NOTEBOOK_DIR, "04_forensic_investigation.ipynb")

with open(path, "w", encoding="utf-8") as f:
    json.dump(make_notebook(cells), f, indent=2)

print("Created:", path)

print()
print("=" * 60)
print("ALL ANALYSIS NOTEBOOKS CREATED SUCCESSFULLY")
print("=" * 60)
print("01_dataset_exploration.ipynb")
print("02_behavioral_analysis.ipynb")
print("03_anomaly_detection_analysis.ipynb")
print("04_forensic_investigation.ipynb")
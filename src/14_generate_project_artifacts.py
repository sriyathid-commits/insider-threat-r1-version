import os
from datetime import datetime
import pandas as pd
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "dataset", "processed")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
NOTEBOOKS_DIR = os.path.join(BASE_DIR, "notebooks")

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(NOTEBOOKS_DIR, exist_ok=True)

print("=" * 70)
print("GENERATING PROJECT ARTIFACTS")
print("=" * 70)

# =========================================================
# Load datasets
# =========================================================

print("\nLoading datasets...")

risk = pd.read_csv(
    os.path.join(
        DATA_DIR,
        "Risk_Scored_Dataset.csv"
    )
)

explanations = pd.read_csv(
    os.path.join(
        DATA_DIR,
        "Threat_Explanations.csv"
    )
)

correlated = pd.read_csv(
    os.path.join(
        DATA_DIR,
        "Threat_Evidence_Correlated.csv"
    )
)

forensic = pd.read_csv(
    os.path.join(
        DATA_DIR,
        "Forensic_Timeline.csv"
    )
)

master = pd.read_csv(
    os.path.join(
        DATA_DIR,
        "CERT_Master_Dataset.csv"
    )
)

print(f"Risk records: {len(risk):,}")
print(f"Explanation records: {len(explanations):,}")
print(f"Forensic events: {len(forensic):,}")

# =========================================================
# 1. Risk distribution
# =========================================================

print("\nCreating risk_distribution.csv...")

risk_distribution = (
    risk["calibrated_risk_level"]
    .value_counts()
    .reindex(
        ["Low", "Medium", "High", "Critical"],
        fill_value=0
    )
    .reset_index()
)

risk_distribution.columns = [
    "risk_level",
    "user_day_count"
]

risk_distribution["percentage"] = (
    risk_distribution["user_day_count"]
    / len(risk)
    * 100
).round(2)

risk_distribution.to_csv(
    os.path.join(
        RESULTS_DIR,
        "risk_distribution.csv"
    ),
    index=False
)

# =========================================================
# 2. Role risk analysis
# =========================================================

print("Creating role_risk_analysis.csv...")

role_risk = (
    risk.groupby("Role")
    .agg(
        user_days=(
            "user_id",
            "count"
        ),
        unique_users=(
            "user_id",
            "nunique"
        ),
        average_risk=(
            "calibrated_risk_score",
            "mean"
        ),
        maximum_risk=(
            "calibrated_risk_score",
            "max"
        ),
        critical_days=(
            "calibrated_risk_level",
            lambda x: (x == "Critical").sum()
        ),
        high_days=(
            "calibrated_risk_level",
            lambda x: (x == "High").sum()
        )
    )
    .reset_index()
)

role_risk["average_risk"] = (
    role_risk["average_risk"]
    .round(2)
)

role_risk["maximum_risk"] = (
    role_risk["maximum_risk"]
    .round(2)
)

role_risk["critical_percentage"] = (
    role_risk["critical_days"]
    / role_risk["user_days"]
    * 100
).round(2)

role_risk = role_risk.sort_values(
    "average_risk",
    ascending=False
)

role_risk.to_csv(
    os.path.join(
        RESULTS_DIR,
        "role_risk_analysis.csv"
    ),
    index=False
)

# =========================================================
# 3. Daily risk trend
# =========================================================

print("Creating daily_risk_trend.csv...")

risk["day"] = pd.to_datetime(
    risk["day"]
)

daily_risk = (
    risk.groupby("day")
    .agg(
        user_days=(
            "user_id",
            "count"
        ),
        unique_users=(
            "user_id",
            "nunique"
        ),
        average_risk=(
            "calibrated_risk_score",
            "mean"
        ),
        maximum_risk=(
            "calibrated_risk_score",
            "max"
        ),
        critical_cases=(
            "calibrated_risk_level",
            lambda x: (x == "Critical").sum()
        ),
        high_cases=(
            "calibrated_risk_level",
            lambda x: (x == "High").sum()
        )
    )
    .reset_index()
)

daily_risk["average_risk"] = (
    daily_risk["average_risk"]
    .round(2)
)

daily_risk["maximum_risk"] = (
    daily_risk["maximum_risk"]
    .round(2)
)

daily_risk.to_csv(
    os.path.join(
        RESULTS_DIR,
        "daily_risk_trend.csv"
    ),
    index=False
)

# =========================================================
# 4. Top investigations
# =========================================================

print("Creating top_investigations.csv...")

top = (
    explanations
    .sort_values(
        "calibrated_risk_score",
        ascending=False
    )
    .head(100)
    .copy()
)

top.to_csv(
    os.path.join(
        RESULTS_DIR,
        "top_investigations.csv"
    ),
    index=False
)

# =========================================================
# 5. Forensic event summary
# =========================================================

print("Creating forensic_event_summary.csv...")

event_summary = (
    forensic["event_type"]
    .value_counts()
    .reset_index()
)

event_summary.columns = [
    "event_type",
    "event_count"
]

event_summary["percentage"] = (
    event_summary["event_count"]
    / len(forensic)
    * 100
).round(2)

event_summary.to_csv(
    os.path.join(
        RESULTS_DIR,
        "forensic_event_summary.csv"
    ),
    index=False
)

# =========================================================
# 6. Investigation priority summary
# =========================================================

print("Creating investigation_priority_summary.csv...")

priority_summary = (
    explanations[
        "investigation_priority"
    ]
    .value_counts()
    .reset_index()
)

priority_summary.columns = [
    "priority",
    "count"
]

priority_summary["percentage"] = (
    priority_summary["count"]
    / len(explanations)
    * 100
).round(2)

priority_summary.to_csv(
    os.path.join(
        RESULTS_DIR,
        "investigation_priority_summary.csv"
    ),
    index=False
)

# =========================================================
# 7. Forensic investigation statistics
# =========================================================

print("Creating forensic_statistics.csv...")

forensic_statistics = pd.DataFrame([
    ["Total forensic events", len(forensic)],
    [
        "LOGON events",
        (forensic["event_type"] == "LOGON").sum()
    ],
    [
        "USB events",
        (forensic["event_type"] == "USB").sum()
    ],
    [
        "HTTP events",
        (forensic["event_type"] == "HTTP").sum()
    ],
    [
        "Investigation user-days",
        len(correlated)
    ],
    [
        "Cases with forensic evidence",
        (correlated["total_events"] > 0).sum()
    ],
    [
        "Total users",
        risk["user_id"].nunique()
    ],
    [
        "Total user-days",
        len(risk)
    ]
], columns=["metric", "value"])

forensic_statistics.to_csv(
    os.path.join(
        RESULTS_DIR,
        "forensic_statistics.csv"
    ),
    index=False
)

# =========================================================
# 8. Project summary
# =========================================================

print("Creating project_summary.txt...")

critical = (
    risk["calibrated_risk_level"]
    == "Critical"
).sum()

high = (
    risk["calibrated_risk_level"]
    == "High"
).sum()

medium = (
    risk["calibrated_risk_level"]
    == "Medium"
).sum()

low = (
    risk["calibrated_risk_level"]
    == "Low"
).sum()

p1 = (
    explanations[
        "investigation_priority"
    ]
    == "P1 - Immediate Investigation"
).sum()

summary = f"""
AI-POWERED INSIDER THREAT DETECTION
AND AUTOMATED DIGITAL FORENSICS SYSTEM
============================================================

Dataset
-------
CERT Insider Threat Test Dataset R1

Dataset characteristics
-----------------------
Unique users: {risk["user_id"].nunique():,}
User-day records: {len(risk):,}
Forensic events: {len(forensic):,}

Risk distribution
-----------------
Low:      {low:,}
Medium:   {medium:,}
High:     {high:,}
Critical: {critical:,}

Investigation priorities
------------------------
P1 - Immediate Investigation: {p1:,}

Forensic events
---------------
LOGON: {(forensic["event_type"] == "LOGON").sum():,}
USB:   {(forensic["event_type"] == "USB").sum():,}
HTTP:  {(forensic["event_type"] == "HTTP").sum():,}

Investigation user-days
-----------------------
{len(correlated):,}

Model
-----
Isolation Forest based behavioral anomaly detection.

Behavioral modeling
-------------------
Personal behavioral baseline
Role-aware behavioral baseline
Behavioral deviation scoring
Calibrated risk scoring
Rule-based threat explanation

Important interpretation
------------------------
The system identifies anomalous behavioral patterns and
prioritizes cases for investigation. Risk scores do not
represent confirmed malicious activity.

The dataset is the synthetic CERT Insider Threat Test Dataset
R1 and should not be interpreted as real employee/company data.

Generated:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

with open(
    os.path.join(
        RESULTS_DIR,
        "project_summary.txt"
    ),
    "w",
    encoding="utf-8"
) as f:
    f.write(summary)

# =========================================================
# 9. Model summary
# =========================================================

print("Creating model_summary.txt...")

model_summary = """
MODEL SUMMARY
============================================================

Model:
Isolation Forest

Purpose:
Unsupervised behavioral anomaly detection.

Unit of analysis:
User-day

Behavioral features:
- Login count
- Logout count
- After-hours login
- Unique PCs
- Work duration
- USB connections
- USB disconnections
- After-hours USB
- Web activity
- Unique domains
- After-hours web activity
- Personal anomaly strength
- Role anomaly strength
- Behavioral deviation score

Risk calibration:
70% ML anomaly risk
30% behavioral deviation percentile

Risk thresholds:
0-39     Low
40-69    Medium
70-89    High
90-100   Critical

Investigation priorities:
P1: Risk >= 90
P2: Risk >= 70
P3: Risk >= 40
P4: Risk < 40

Important:
This is an unsupervised anomaly-detection system.
Anomaly flags and risk scores are not ground-truth labels.
"""

with open(
    os.path.join(
        RESULTS_DIR,
        "model_summary.txt"
    ),
    "w",
    encoding="utf-8"
) as f:
    f.write(model_summary)

# =========================================================
# 10. Logs
# =========================================================

print("Creating pipeline_execution.log...")

log_text = f"""
CERT INSIDER THREAT DETECTION PIPELINE
============================================================

Execution timestamp:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Completed pipeline stages:

01 - Dataset validation
02 - Dataset extraction/organization
03 - Dataset inspection
04 - HTTP preprocessing
05 - User-day feature engineering
06 - LDAP role enrichment
07 - Behavioral baseline generation
08 - Isolation Forest anomaly detection
09 - Risk score calibration
10 - Automated forensic timeline
11 - Threat explanation engine
12 - Threat/evidence correlation
13 - Final dataset generation

Final records:
User-days: {len(risk):,}
Forensic events: {len(forensic):,}
Investigation cases: {len(correlated):,}

Pipeline status:
SUCCESS
"""

with open(
    os.path.join(
        LOGS_DIR,
        "pipeline_execution.log"
    ),
    "w",
    encoding="utf-8"
) as f:
    f.write(log_text)

# =========================================================
# 11. Statistics log
# =========================================================

print("Creating project_statistics.log...")

statistics_log = f"""
PROJECT STATISTICS
============================================================

Users:
{risk["user_id"].nunique():,}

User-day records:
{len(risk):,}

Forensic events:
{len(forensic):,}

LOGON:
{(forensic["event_type"] == "LOGON").sum():,}

USB:
{(forensic["event_type"] == "USB").sum():,}

HTTP:
{(forensic["event_type"] == "HTTP").sum():,}

Critical:
{critical:,}

High:
{high:,}

Medium:
{medium:,}

Low:
{low:,}

P1:
{p1:,}

Investigation cases:
{len(correlated):,}
"""

with open(
    os.path.join(
        LOGS_DIR,
        "project_statistics.log"
    ),
    "w",
    encoding="utf-8"
) as f:
    f.write(statistics_log)

# =========================================================
# 12. Create notebook files
# =========================================================

print("\nCreating analysis notebooks...")

def create_notebook(filename, title, purpose):

    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    f"# {title}\n\n",
                    f"{purpose}\n\n",
                    "Project: AI-Powered Insider Threat Detection and Automated Digital Forensics System\n\n",
                    "Dataset: CERT Insider Threat Test Dataset R1"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "import pandas as pd\n",
                    "import os\n\n",
                    "BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath('')))\n",
                    "DATA_DIR = os.path.join(BASE_DIR, 'dataset', 'processed')\n",
                    "\n",
                    "risk = pd.read_csv(os.path.join(DATA_DIR, 'Risk_Scored_Dataset.csv'))\n",
                    "print(risk.shape)\n",
                    "risk.head()"
                ]
            }
        ],
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

    with open(
        os.path.join(
            NOTEBOOKS_DIR,
            filename
        ),
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            notebook,
            f,
            indent=2
        )


create_notebook(
    "01_dataset_exploration.ipynb",
    "CERT R1 Dataset Exploration",
    "Explores dataset size, users, roles, dates, and behavioral records."
)

create_notebook(
    "02_behavioral_analysis.ipynb",
    "Behavioral Analysis",
    "Analyzes user-day behavioral features and personal/role deviations."
)

create_notebook(
    "03_anomaly_detection_analysis.ipynb",
    "Anomaly Detection Analysis",
    "Analyzes Isolation Forest results and calibrated risk scores."
)

create_notebook(
    "04_forensic_investigation.ipynb",
    "Automated Forensic Investigation",
    "Explores high-risk user-days and their correlated forensic events."
)

# =========================================================
# Final output
# =========================================================

print("\n" + "=" * 70)
print("PROJECT ARTIFACT GENERATION COMPLETE")
print("=" * 70)

print("\nRESULTS:")
for file in sorted(os.listdir(RESULTS_DIR)):
    print("  ", file)

print("\nLOGS:")
for file in sorted(os.listdir(LOGS_DIR)):
    print("  ", file)

print("\nNOTEBOOKS:")
for file in sorted(os.listdir(NOTEBOOKS_DIR)):
    print("  ", file)

print("\n" + "=" * 70)
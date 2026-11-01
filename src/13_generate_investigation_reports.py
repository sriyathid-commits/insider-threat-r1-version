
import os
import pandas as pd
from datetime import datetime

# ============================================================
# 1. CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOP_FILE = os.path.join(
    BASE_DIR, "results", "top_investigations.csv"
)

EVIDENCE_FILE = os.path.join(
    BASE_DIR, "dataset", "processed",
    "threat_evidence_correlated.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR, "results", "investigation_reports"
)

SUMMARY_FILE = os.path.join(
    BASE_DIR, "results", "investigation_summary.csv"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# 2. LOAD DATA
# ============================================================

print("=" * 70)
print("AUTOMATED DIGITAL FORENSIC INVESTIGATION REPORT GENERATOR")
print("=" * 70)

print("\nLoading top investigation cases...")

cases = pd.read_csv(TOP_FILE)

print("Investigation cases:", len(cases))

print("\nLoading correlated forensic evidence...")

evidence = pd.read_csv(EVIDENCE_FILE)

print("Correlated investigation records:", len(evidence))

# ============================================================
# 3. VALIDATE REQUIRED COLUMNS
# ============================================================

required_columns = [
    "user_id",
    "day",
    "total_events",
    "logon_events",
    "usb_events",
    "http_events",
    "first_event",
    "last_event",
    "events_per_hour",
    "forensic_summary"
]

missing = [
    col for col in required_columns
    if col not in evidence.columns
]

if missing:
    raise ValueError(
        f"Missing required evidence columns: {missing}"
    )

# ============================================================
# 4. PREPARE INVESTIGATION DATA
# ============================================================

cases["user_id"] = cases["user_id"].astype(str).str.strip()
evidence["user_id"] = evidence["user_id"].astype(str).str.strip()

cases["day"] = pd.to_datetime(
    cases["day"], errors="coerce"
).dt.strftime("%Y-%m-%d")

evidence["day"] = pd.to_datetime(
    evidence["day"], errors="coerce"
).dt.strftime("%Y-%m-%d")

if cases[["user_id", "day"]].isnull().any().any():
    raise ValueError("Invalid user_id or day in top investigations.")

if evidence.duplicated(["user_id", "day"]).any():
    raise ValueError(
        "Duplicate user_id and day records in correlated evidence."
    )

# ============================================================
# 5. MAP CORRELATED FORENSIC EVIDENCE
# ============================================================

print("\nMapping forensic evidence to investigation cases...")

evidence_columns = [
    "user_id",
    "day",
    "total_events",
    "logon_events",
    "usb_events",
    "http_events",
    "first_event",
    "last_event",
    "events_per_hour",
    "forensic_summary"
]

evidence_subset = evidence[evidence_columns].copy()

df = cases.merge(
    evidence_subset,
    on=["user_id", "day"],
    how="left",
    validate="one_to_one",
    indicator=True
)

unmatched = df[df["_merge"] != "both"]

if not unmatched.empty:
    raise ValueError(
        f"{len(unmatched)} investigation cases have no matching evidence."
    )

df.drop(columns=["_merge"], inplace=True)

# Ensure evidence statistics are numeric
count_columns = [
    "total_events",
    "logon_events",
    "usb_events",
    "http_events"
]

for col in count_columns:
    df[col] = pd.to_numeric(df[col], errors="raise")

# ============================================================
# 6. GENERATE INDIVIDUAL INVESTIGATION REPORTS
# ============================================================

summary_records = []

print("\nGenerating investigation reports...")

for index, row in df.iterrows():

    user_id = row["user_id"]
    day = row["day"]
    role = row["Role"]

    risk_score = row["calibrated_risk_score"]
    risk_level = row["calibrated_risk_level"]
    priority = row["investigation_priority"]

    # Actual correlated evidence statistics
    total_events = int(row["total_events"])
    logon_events = int(row["logon_events"])
    usb_events = int(row["usb_events"])
    http_events = int(row["http_events"])

    first_event = row["first_event"]
    last_event = row["last_event"]

    events_per_hour = row["events_per_hour"]
    forensic_summary = row["forensic_summary"]

    explanation = row["explanation"]

    # --------------------------------------------------------
    # REPORT CONTENT
    # --------------------------------------------------------

    report = f"""
======================================================================
AI-POWERED INSIDER THREAT DETECTION
AUTOMATED DIGITAL FORENSIC INVESTIGATION REPORT
======================================================================

REPORT INFORMATION
----------------------------------------------------------------------

Report Number        : R1-INV-{index + 1:04d}
Generated On         : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
User ID              : {user_id}
Investigation Date   : {day}
Employee Role        : {role}

======================================================================
1. RISK ASSESSMENT
======================================================================

Calibrated Risk Score : {risk_score}
Risk Classification  : {risk_level}
Investigation Priority: {priority}

======================================================================
2. BEHAVIORAL ANALYSIS
======================================================================

Login Count                  : {row['login_count']}
After-Hours Login            : {row['after_hours_login']}
USB Connections              : {row['usb_connect_count']}
USB Disconnections           : {row['usb_disconnect_count']}
After-Hours USB Activity     : {row['after_hours_usb']}
Web Activity Count           : {row['web_activity_count']}
Unique Domains               : {row['unique_domains']}
After-Hours Web Activity     : {row['after_hours_web']}
Unique Computers Used        : {row['unique_pcs']}

Work Duration (Minutes)      : {row['work_duration_minutes']}
Personal Anomaly Strength    : {row['personal_anomaly_strength']}
Role Anomaly Strength        : {row['role_anomaly_strength']}
Behavioral Deviation Score   : {row['behavioral_deviation_score']}

======================================================================
3. CORRELATED FORENSIC EVIDENCE
======================================================================

Total Forensic Events : {total_events}

LOGON Events          : {logon_events}
USB Events            : {usb_events}
HTTP Events           : {http_events}

Events Per Hour       : {events_per_hour}

Forensic Summary:
{forensic_summary}

======================================================================
4. INVESTIGATION TIMELINE
======================================================================

First Forensic Event : {first_event}
Last Forensic Event  : {last_event}

======================================================================
5. DETECTED SUSPICIOUS INDICATORS
======================================================================

{explanation}

======================================================================
6. INVESTIGATOR RECOMMENDATIONS
======================================================================

1. Review employee login activity.
2. Examine USB connection and disconnection records.
3. Investigate unusual web browsing activity.
4. Compare behavior against personal historical patterns.
5. Compare activity against the employee's role baseline.
6. Preserve relevant forensic evidence.
7. Conduct authorized investigation before drawing conclusions.

======================================================================
7. FINAL INVESTIGATION STATUS
======================================================================

Risk Level            : {risk_level}
Priority              : {priority}
Investigation Required: {row['investigation_required']}

NOTE:
An elevated anomaly score indicates unusual behavior.
It does not independently establish malicious intent.
Human verification and additional evidence are required.

======================================================================
END OF INVESTIGATION REPORT
======================================================================
"""

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    filename = f"{user_id}_{day}.txt"

    filepath = os.path.join(
        OUTPUT_DIR, filename
    )

    with open(filepath, "w", encoding="utf-8") as file:
        file.write(report)

    # --------------------------------------------------------
    # SUMMARY RECORD
    # --------------------------------------------------------

    summary_records.append({
        "report_number": f"R1-INV-{index + 1:04d}",
        "user_id": user_id,
        "day": day,
        "role": role,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "priority": priority,
        "total_events": total_events,
        "logon_events": logon_events,
        "usb_events": usb_events,
        "http_events": http_events,
        "first_event": first_event,
        "last_event": last_event,
        "events_per_hour": events_per_hour,
        "forensic_summary": forensic_summary,
        "report_file": filename
    })

    if (index + 1) % 10 == 0:
        print(
            f"Generated {index + 1}/{len(df)} reports"
        )

# ============================================================
# 8. GENERATE INVESTIGATION SUMMARY
# ============================================================

summary_df = pd.DataFrame(summary_records)

summary_df.to_csv(
    SUMMARY_FILE,
    index=False
)

# ============================================================
# 9. VALIDATE GENERATED REPORTS
# ============================================================

print("\nValidating generated reports...")

assert len(summary_df) == len(cases)

assert (
    summary_df["total_events"]
    ==
    summary_df["logon_events"]
    + summary_df["usb_events"]
    + summary_df["http_events"]
).all(), "Forensic event totals do not match."

print("Report count validation: PASSED")
print("Forensic event validation: PASSED")
print("Evidence matching validation: PASSED")

# ============================================================
# 10. FINAL RESULTS
# ============================================================

print("\n" + "=" * 70)
print("INVESTIGATION REPORT GENERATION COMPLETE")
print("=" * 70)

print("\nTotal reports generated:", len(summary_df))

print("\nReport directory:")
print(OUTPUT_DIR)

print("\nInvestigation summary:")
print(SUMMARY_FILE)

print("\nRisk distribution:")
print(summary_df["risk_level"].value_counts())

print("\nTop investigation reports:")

print(
    summary_df.head(10).to_string(index=False)
)

print("\n" + "=" * 70)
print("STEP 13 COMPLETED SUCCESSFULLY")
print("=" * 70)

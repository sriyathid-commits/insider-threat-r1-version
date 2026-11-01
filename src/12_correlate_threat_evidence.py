import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")

EXPLANATIONS_FILE = os.path.join(
    PROCESSED_DIR, "threat_explanations.csv"
)

FORENSIC_FILE = os.path.join(
    PROCESSED_DIR, "forensic_timeline.csv"
)

OUTPUT_FILE = os.path.join(
    PROCESSED_DIR, "threat_evidence_correlated.csv"
)

print("=" * 70)
print("AI THREAT + FORENSIC EVIDENCE CORRELATION")
print("=" * 70)

print("\nLoading threat explanations...")
explanations = pd.read_csv(EXPLANATIONS_FILE)

print(f"Threat explanation records: {len(explanations)}")

print("\nLoading forensic timeline...")
forensic = pd.read_csv(FORENSIC_FILE)

print(f"Forensic events: {len(forensic)}")

# ---------------------------------------------------------
# Prepare dates
# ---------------------------------------------------------

explanations["day"] = pd.to_datetime(
    explanations["day"]
).dt.strftime("%Y-%m-%d")

forensic["day"] = pd.to_datetime(
    forensic["day"]
).dt.strftime("%Y-%m-%d")

# ---------------------------------------------------------
# Select investigation cases
# ---------------------------------------------------------

cases = explanations[
    explanations["investigation_required"] == 1
].copy()

print(
    f"\nInvestigation cases: {len(cases)}"
)

# ---------------------------------------------------------
# Aggregate forensic evidence by user-day
# ---------------------------------------------------------

print("\nAggregating forensic evidence...")

evidence = forensic.groupby(
    ["user_id", "day"],
    as_index=False
).agg(
    total_events=("event_type", "count"),
    logon_events=(
        "event_type",
        lambda x: (x == "LOGON").sum()
    ),
    usb_events=(
        "event_type",
        lambda x: (x == "USB").sum()
    ),
    http_events=(
        "event_type",
        lambda x: (x == "HTTP").sum()
    ),
    first_event=("timestamp", "min"),
    last_event=("timestamp", "max")
)

# ---------------------------------------------------------
# Merge risk/explanation information
# ---------------------------------------------------------

print("\nCorrelating risk with forensic evidence...")

correlated = cases.merge(
    evidence,
    on=["user_id", "day"],
    how="left"
)

# ---------------------------------------------------------
# Fill missing evidence
# ---------------------------------------------------------

numeric_columns = [
    "total_events",
    "logon_events",
    "usb_events",
    "http_events"
]

for column in numeric_columns:
    correlated[column] = (
        correlated[column]
        .fillna(0)
        .astype(int)
    )

# ---------------------------------------------------------
# Calculate evidence density
# ---------------------------------------------------------

correlated["events_per_hour"] = 0.0

first_time = pd.to_datetime(
    correlated["first_event"],
    errors="coerce"
)

last_time = pd.to_datetime(
    correlated["last_event"],
    errors="coerce"
)

duration_hours = (
    (last_time - first_time)
    .dt.total_seconds()
    / 3600
)

correlated["events_per_hour"] = (
    correlated["total_events"]
    / duration_hours.clip(lower=1 / 60)
).round(2)

# ---------------------------------------------------------
# Generate investigation summary
# ---------------------------------------------------------

def build_summary(row):

    evidence = []

    if row["logon_events"] > 0:
        evidence.append(
            f'{row["logon_events"]} logon event(s)'
        )

    if row["usb_events"] > 0:
        evidence.append(
            f'{row["usb_events"]} USB event(s)'
        )

    if row["http_events"] > 0:
        evidence.append(
            f'{row["http_events"]} HTTP event(s)'
        )

    if row["total_events"] > 0:
        evidence.append(
            f'{row["total_events"]} total forensic events'
        )

    if not evidence:
        return "No raw forensic events found"

    return "; ".join(evidence)


correlated["forensic_summary"] = (
    correlated.apply(build_summary, axis=1)
)

# ---------------------------------------------------------
# Sort by risk
# ---------------------------------------------------------

correlated = correlated.sort_values(
    by=[
        "calibrated_risk_score",
        "total_events"
    ],
    ascending=[False, False]
)

# ---------------------------------------------------------
# Save
# ---------------------------------------------------------

correlated.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n" + "=" * 70)
print("FORENSIC CORRELATION COMPLETE")
print("=" * 70)

print(
    f"\nInvestigation cases: {len(correlated)}"
)

print(
    f"Cases with forensic evidence: "
    f"{(correlated['total_events'] > 0).sum()}"
)

print(
    f"Total correlated events: "
    f"{correlated['total_events'].sum()}"
)

print("\nEvidence type totals:")

print(
    f"LOGON events: "
    f"{correlated['logon_events'].sum()}"
)

print(
    f"USB events: "
    f"{correlated['usb_events'].sum()}"
)

print(
    f"HTTP events: "
    f"{correlated['http_events'].sum()}"
)

print("\nTop investigation cases:")

display_columns = [
    "user_id",
    "day",
    "Role",
    "calibrated_risk_score",
    "calibrated_risk_level",
    "investigation_priority",
    "total_events",
    "logon_events",
    "usb_events",
    "http_events",
    "forensic_summary"
]

print(
    correlated[display_columns]
    .head(10)
    .to_string(index=False)
)

print("\nOutput:")
print(OUTPUT_FILE)

print("\n" + "=" * 70)
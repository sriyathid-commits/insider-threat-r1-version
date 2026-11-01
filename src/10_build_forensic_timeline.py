from pathlib import Path

import pandas as pd


EXTRACTED = Path("dataset/extracted")
PROCESSED = Path("dataset/processed")

RISK_FILE = PROCESSED / "risk_scored_dataset_calibrated.csv"
OUTPUT_FILE = PROCESSED / "forensic_timeline.csv"


print("=" * 70)
print("CERT R1 AUTOMATED FORENSIC TIMELINE")
print("=" * 70)


# ============================================================
# 1. LOAD RISK DATA
# ============================================================

print()
print("Loading risk-scored user-days...")

risk = pd.read_csv(
    RISK_FILE,
    parse_dates=["day"]
)

risk["day"] = risk["day"].dt.date

print("Risk records:", len(risk))


# ============================================================
# 2. SELECT INVESTIGATION DAYS
# ============================================================

print()
print("Selecting high-risk investigation days...")

investigation = risk[
    risk["investigation_required"] == 1
].copy()

print(
    "Investigation user-days:",
    len(investigation)
)

investigation_keys = set(
    zip(
        investigation["user_id"].astype(str),
        investigation["day"]
    )
)


# ============================================================
# 3. LOAD LOGON DATA
# ============================================================

print()
print("Loading logon events...")

logon_file = EXTRACTED / "logon.csv"

logon = pd.read_csv(
    logon_file
)

logon.columns = [
    column.strip()
    for column in logon.columns
]

logon["date"] = pd.to_datetime(
    logon["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

logon["user_id"] = (
    logon["user"]
    .astype(str)
    .str.split("/")
    .str[-1]
)

logon["day"] = logon["date"].dt.date

logon = logon[
    logon.apply(
        lambda row:
        (row["user_id"], row["day"])
        in investigation_keys,
        axis=1
    )
].copy()

logon["event_type"] = "LOGON"

logon["event_detail"] = (
    logon["activity"].astype(str)
)

logon_events = logon[
    [
        "date",
        "user",
        "user_id",
        "pc",
        "event_type",
        "event_detail",
        "day"
    ]
].copy()

print(
    "Investigation logon events:",
    len(logon_events)
)


# ============================================================
# 4. LOAD DEVICE DATA
# ============================================================

print()
print("Loading device events...")

device_file = EXTRACTED / "device.csv"

device = pd.read_csv(
    device_file
)

device.columns = [
    column.strip()
    for column in device.columns
]

device["date"] = pd.to_datetime(
    device["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

device["user_id"] = (
    device["user"]
    .astype(str)
    .str.split("/")
    .str[-1]
)

device["day"] = device["date"].dt.date

device = device[
    device.apply(
        lambda row:
        (row["user_id"], row["day"])
        in investigation_keys,
        axis=1
    )
].copy()

device["event_type"] = "USB"

device["event_detail"] = (
    device["activity"].astype(str)
)

device_events = device[
    [
        "date",
        "user",
        "user_id",
        "pc",
        "event_type",
        "event_detail",
        "day"
    ]
].copy()

print(
    "Investigation device events:",
    len(device_events)
)


# ============================================================
# 5. LOAD HTTP DATA
# ============================================================

print()
print("Loading HTTP events...")

http_file = EXTRACTED / "http.csv"

http = pd.read_csv(
    http_file,
    header=None,
    names=[
        "id",
        "date",
        "user",
        "pc",
        "url"
    ]
)

http["date"] = pd.to_datetime(
    http["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

http["user_id"] = (
    http["user"]
    .astype(str)
    .str.split("/")
    .str[-1]
)

http["day"] = http["date"].dt.date

http = http[
    http.apply(
        lambda row:
        (row["user_id"], row["day"])
        in investigation_keys,
        axis=1
    )
].copy()

http["event_type"] = "HTTP"

http["event_detail"] = (
    http["url"].astype(str)
)

http_events = http[
    [
        "date",
        "user",
        "user_id",
        "pc",
        "event_type",
        "event_detail",
        "day"
    ]
].copy()

print(
    "Investigation HTTP events:",
    len(http_events)
)


# ============================================================
# 6. COMBINE EVENTS
# ============================================================

print()
print("Combining forensic events...")

events = pd.concat(
    [
        logon_events,
        device_events,
        http_events
    ],
    ignore_index=True
)

print(
    "Total forensic events:",
    len(events)
)


# ============================================================
# 7. ATTACH RISK INFORMATION
# ============================================================

print()
print("Attaching risk information...")

risk_columns = [
    "user_id",
    "day",
    "Role",
    "calibrated_risk_score",
    "calibrated_risk_level",
    "anomaly",
    "behavioral_deviation_score",
    "investigation_required"
]

risk_context = risk[
    risk_columns
].copy()

events = events.merge(
    risk_context,
    on=["user_id", "day"],
    how="left"
)


# ============================================================
# 8. SORT CHRONOLOGICALLY
# ============================================================

events = events.sort_values(
    [
        "calibrated_risk_score",
        "user_id",
        "date"
    ],
    ascending=[
        False,
        True,
        True
    ]
)


# ============================================================
# 9. RENAME COLUMNS
# ============================================================

events = events[
    [
        "date",
        "day",
        "user",
        "user_id",
        "Role",
        "pc",
        "event_type",
        "event_detail",
        "calibrated_risk_score",
        "calibrated_risk_level",
        "anomaly",
        "behavioral_deviation_score",
        "investigation_required"
    ]
]

events = events.rename(
    columns={
        "date": "timestamp"
    }
)


# ============================================================
# 10. SAVE
# ============================================================

print()
print("Saving forensic timeline...")

events.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 11. RESULTS
# ============================================================

print()
print("=" * 70)
print("FORENSIC TIMELINE COMPLETE")
print("=" * 70)

print()
print("Total forensic events:", len(events))

print()
print("Event type distribution:")

print(
    events["event_type"]
    .value_counts()
)

print()
print("Risk level distribution:")

print(
    events["calibrated_risk_level"]
    .value_counts()
)

print()
print("Top forensic events:")

print(
    events.head(20)
    .to_string(index=False)
)

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("=" * 70)
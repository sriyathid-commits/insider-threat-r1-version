from pathlib import Path

import numpy as np
import pandas as pd


PROCESSED = Path("dataset/processed")

INPUT_FILE = PROCESSED / "risk_scored_dataset.csv"
OUTPUT_FILE = PROCESSED / "risk_scored_dataset_calibrated.csv"


print("=" * 70)
print("CERT R1 RISK SCORE CALIBRATION")
print("=" * 70)


# ============================================================
# 1. LOAD DATA
# ============================================================

print()
print("Loading anomaly results...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["day"]
)

print("Records:", len(df))


# ============================================================
# 2. NORMALIZE BEHAVIORAL DEVIATION
# ============================================================

print()
print("Normalizing behavioral deviation...")

behavior = df["behavioral_deviation_score"].fillna(0)

behavior_percentile = (
    behavior.rank(pct=True) * 100
)


# ============================================================
# 3. COMBINE MODEL SCORE + BEHAVIOR
# ============================================================

print()
print("Combining anomaly evidence...")

model_score = df["risk_score"].fillna(0)

df["calibrated_risk_score"] = (
    0.70 * model_score
    +
    0.30 * behavior_percentile
)


# ============================================================
# 4. CLIP SCORE
# ============================================================

df["calibrated_risk_score"] = (
    df["calibrated_risk_score"]
    .clip(0, 100)
)


# ============================================================
# 5. INVESTIGATION PRIORITY
# ============================================================

def classify_risk(score):

    if score >= 90:
        return "Critical"

    elif score >= 70:
        return "High"

    elif score >= 40:
        return "Medium"

    else:
        return "Low"


df["calibrated_risk_level"] = (
    df["calibrated_risk_score"]
    .apply(classify_risk)
)


# ============================================================
# 6. INVESTIGATION FLAG
# ============================================================

df["investigation_required"] = (
    df["calibrated_risk_score"] >= 70
).astype(int)


# ============================================================
# 7. SORT BY RISK
# ============================================================

df = df.sort_values(
    "calibrated_risk_score",
    ascending=False
)


# ============================================================
# 8. SAVE
# ============================================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 9. RESULTS
# ============================================================

print()
print("=" * 70)
print("RISK CALIBRATION COMPLETE")
print("=" * 70)

print()
print("Total records:", len(df))

print()
print("Risk level distribution:")

print(
    df["calibrated_risk_level"]
    .value_counts()
    .reindex(
        ["Low", "Medium", "High", "Critical"],
        fill_value=0
    )
)

print()
print("Investigation required:")

print(
    df["investigation_required"]
    .value_counts()
    .sort_index()
)

print()
print("Calibrated risk statistics:")

print(
    df["calibrated_risk_score"]
    .describe()
    .to_string()
)

print()
print("Top 20 highest-risk user-days:")

columns = [
    "user",
    "user_id",
    "day",
    "Role",
    "calibrated_risk_score",
    "calibrated_risk_level",
    "anomaly",
    "behavioral_deviation_score",
    "investigation_required"
]

print(
    df[columns]
    .head(20)
    .to_string(index=False)
)

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("=" * 70)
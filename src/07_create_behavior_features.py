from pathlib import Path

import numpy as np
import pandas as pd


PROCESSED = Path("dataset/processed")

INPUT_FILE = PROCESSED / "user_day_features_role.csv"
OUTPUT_FILE = PROCESSED / "ml_features.csv"


print("=" * 70)
print("CERT R1 BEHAVIORAL DEVIATION FEATURES")
print("=" * 70)


# ============================================================
# 1. LOAD DATA
# ============================================================

print()
print("Loading enriched user-day dataset...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["day"]
)

print("Records:", len(df))


# ============================================================
# 2. FEATURE COLUMNS
# ============================================================

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


# ============================================================
# 3. CREATE USER BASELINES
# ============================================================

print()
print("Calculating personal behavioral baselines...")

for column in behavior_columns:

    mean_column = f"{column}_mean"
    std_column = f"{column}_std"

    df[mean_column] = (
        df.groupby("user")[column]
        .transform("mean")
    )

    df[std_column] = (
        df.groupby("user")[column]
        .transform("std")
    )

    df[std_column] = df[std_column].fillna(0)

    # Avoid division by zero
    safe_std = df[std_column].replace(0, 1)

    deviation_column = f"{column}_zscore"

    df[deviation_column] = (
        (df[column] - df[mean_column])
        / safe_std
    )

    df[deviation_column] = (
        df[deviation_column]
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
    )


# ============================================================
# 4. GLOBAL ROLE-BASED BASELINES
# ============================================================

print()
print("Calculating role-based baselines...")

for column in behavior_columns:

    role_mean = f"{column}_role_mean"
    role_std = f"{column}_role_std"

    df[role_mean] = (
        df.groupby("Role")[column]
        .transform("mean")
    )

    df[role_std] = (
        df.groupby("Role")[column]
        .transform("std")
    )

    df[role_std] = df[role_std].fillna(0)

    safe_role_std = (
        df[role_std]
        .replace(0, 1)
    )

    role_zscore = f"{column}_role_zscore"

    df[role_zscore] = (
        (df[column] - df[role_mean])
        / safe_role_std
    )

    df[role_zscore] = (
        df[role_zscore]
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
    )


# ============================================================
# 5. OVERALL BEHAVIORAL DEVIATION
# ============================================================

user_zscore_columns = [
    f"{column}_zscore"
    for column in behavior_columns
]

role_zscore_columns = [
    f"{column}_role_zscore"
    for column in behavior_columns
]


df["personal_anomaly_strength"] = (
    df[user_zscore_columns]
    .abs()
    .mean(axis=1)
)


df["role_anomaly_strength"] = (
    df[role_zscore_columns]
    .abs()
    .mean(axis=1)
)


# ============================================================
# 6. COMBINED BEHAVIORAL SCORE
# ============================================================

df["behavioral_deviation_score"] = (
    0.7 * df["personal_anomaly_strength"]
    +
    0.3 * df["role_anomaly_strength"]
)


# ============================================================
# 7. CLEAN EXTREME VALUES
# ============================================================

score_columns = [
    "personal_anomaly_strength",
    "role_anomaly_strength",
    "behavioral_deviation_score"
]

for column in score_columns:

    df[column] = (
        df[column]
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
        .clip(upper=10)
    )


# ============================================================
# 8. SAVE
# ============================================================

df.to_csv(
    OUTPUT_FILE,
    index=False
)


print()
print("=" * 70)
print("BEHAVIORAL FEATURE ENGINEERING COMPLETE")
print("=" * 70)

print()
print("Records:", len(df))
print("Columns:", len(df.columns))

print()
print("New important features:")

print(" - personal_anomaly_strength")
print(" - role_anomaly_strength")
print(" - behavioral_deviation_score")

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("Behavioral deviation statistics:")

print(
    df[
        [
            "personal_anomaly_strength",
            "role_anomaly_strength",
            "behavioral_deviation_score"
        ]
    ].describe().to_string()
)

print()
print("=" * 70)

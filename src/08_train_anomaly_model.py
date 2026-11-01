from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest


PROCESSED = Path("dataset/processed")
MODELS = Path("models")

INPUT_FILE = PROCESSED / "ml_features.csv"
MODEL_FILE = MODELS / "isolation_forest.pkl"
OUTPUT_FILE = PROCESSED / "risk_scored_dataset.csv"


print("=" * 70)
print("CERT R1 INSIDER THREAT ANOMALY DETECTION")
print("=" * 70)


# ============================================================
# 1. LOAD DATA
# ============================================================

print()
print("Loading ML features...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["day"]
)

print("Records:", len(df))


# ============================================================
# 2. SELECT ML FEATURES
# ============================================================

feature_columns = [
    "login_count",
    "logout_count",
    "after_hours_login",
    "unique_pcs",
    "work_duration_minutes",
    "usb_connect_count",
    "usb_disconnect_count",
    "after_hours_usb",
    "usb_user",
    "web_activity_count",
    "unique_domains",
    "after_hours_web",
    "personal_anomaly_strength",
    "role_anomaly_strength",
    "behavioral_deviation_score"
]


print()
print("ML features:")

for feature in feature_columns:
    print(" -", feature)


X = df[feature_columns].copy()


# ============================================================
# 3. CLEAN DATA
# ============================================================

print()
print("Cleaning feature matrix...")

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)

print("Feature matrix shape:", X.shape)


# ============================================================
# 4. TRAIN ISOLATION FOREST
# ============================================================

print()
print("Training Isolation Forest...")

model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

model.fit(X)


# ============================================================
# 5. GENERATE ANOMALY SCORES
# ============================================================

print()
print("Generating anomaly scores...")

decision_scores = model.decision_function(X)

raw_anomaly_score = -decision_scores


# ============================================================
# 6. CONVERT TO 0-100 RISK SCORE
# ============================================================

print()
print("Calculating risk scores...")

percentile_ranks = (
    pd.Series(raw_anomaly_score)
    .rank(pct=True)
)

df["risk_score"] = (
    percentile_ranks * 100
)


# ============================================================
# 7. ANOMALY LABEL
# ============================================================

predictions = model.predict(X)

df["anomaly"] = (
    predictions == -1
).astype(int)


# ============================================================
# 8. RISK LEVEL
# ============================================================

def classify_risk(score):

    if score >= 75:
        return "Critical"

    elif score >= 50:
        return "High"

    elif score >= 25:
        return "Medium"

    else:
        return "Low"


df["risk_level"] = (
    df["risk_score"]
    .apply(classify_risk)
)


# ============================================================
# 9. SAVE MODEL
# ============================================================

print()
print("Saving trained model...")

MODELS.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)


# ============================================================
# 10. SAVE RISK DATASET
# ============================================================

print()
print("Saving risk-scored dataset...")

df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 11. RESULTS
# ============================================================

print()
print("=" * 70)
print("ANOMALY DETECTION COMPLETE")
print("=" * 70)

print()
print("Total records:", len(df))

print()
print("Anomalies detected:")

print(
    df["anomaly"]
    .value_counts()
    .sort_index()
)

print()
print("Risk level distribution:")

print(
    df["risk_level"]
    .value_counts()
    .reindex(
        ["Low", "Medium", "High", "Critical"],
        fill_value=0
    )
)

print()
print("Risk score statistics:")

print(
    df["risk_score"]
    .describe()
    .to_string()
)

print()
print("Top 10 highest-risk user-days:")

top_risk = (
    df[
        [
            "user",
            "user_id",
            "day",
            "Role",
            "risk_score",
            "risk_level",
            "anomaly",
            "behavioral_deviation_score"
        ]
    ]
    .sort_values(
        "risk_score",
        ascending=False
    )
    .head(10)
)

print(
    top_risk.to_string(index=False)
)

print()
print("Model:")
print(MODEL_FILE)

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("=" * 70)
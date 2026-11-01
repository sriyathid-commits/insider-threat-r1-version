from pathlib import Path

import pandas as pd


PROCESSED = Path("dataset/processed")

INPUT_FILE = PROCESSED / "risk_scored_dataset_calibrated.csv"
OUTPUT_FILE = PROCESSED / "threat_explanations.csv"


print("=" * 70)
print("CERT R1 AUTOMATED THREAT EXPLANATION ENGINE")
print("=" * 70)


# ============================================================
# 1. LOAD DATA
# ============================================================

print()
print("Loading risk-scored dataset...")

df = pd.read_csv(
    INPUT_FILE,
    parse_dates=["day"]
)

print("Records:", len(df))


# ============================================================
# 2. FEATURE-BASED EXPLANATION
# ============================================================

def generate_explanation(row):

    reasons = []

    if row["after_hours_login"] > 0:
        reasons.append(
            "after-hours login activity"
        )

    if row["after_hours_usb"] > 0:
        reasons.append(
            "after-hours USB activity"
        )

    if row["usb_connect_count"] > 0:
        reasons.append(
            f'{int(row["usb_connect_count"])} USB connection(s)'
        )

    if row["web_activity_count"] > 0:
        if row["web_activity_count"] >= 50:
            reasons.append(
                "unusually high web activity"
            )
        elif row["web_activity_count"] >= 20:
            reasons.append(
                "elevated web activity"
            )

    if row["unique_domains"] >= 15:
        reasons.append(
            "large number of unique domains"
        )

    if row["after_hours_web"] > 0:
        reasons.append(
            "after-hours web activity"
        )

    if row["unique_pcs"] > 1:
        reasons.append(
            f'{int(row["unique_pcs"])} different PCs used'
        )

    if row["work_duration_minutes"] > 720:
        reasons.append(
            "unusually long work session"
        )

    if row["personal_anomaly_strength"] >= 1:
        reasons.append(
            "strong deviation from personal behavior"
        )

    if row["role_anomaly_strength"] >= 1:
        reasons.append(
            "behavior differs from role baseline"
        )

    if row["behavioral_deviation_score"] >= 2:
        reasons.append(
            "high overall behavioral deviation"
        )

    if not reasons:
        reasons.append(
            "behavioral pattern identified as anomalous by the ML model"
        )

    return reasons


# ============================================================
# 3. GENERATE EXPLANATIONS
# ============================================================

print()
print("Generating explanations...")

df["explanation_reasons"] = (
    df.apply(
        generate_explanation,
        axis=1
    )
)


# ============================================================
# 4. CREATE HUMAN-READABLE EXPLANATION
# ============================================================

df["explanation"] = (
    df["explanation_reasons"]
    .apply(
        lambda reasons:
        "; ".join(reasons)
    )
)


# ============================================================
# 5. INVESTIGATION PRIORITY
# ============================================================

def priority(score):

    if score >= 90:
        return "P1 - Immediate Investigation"

    elif score >= 70:
        return "P2 - High Priority"

    elif score >= 40:
        return "P3 - Review"

    return "P4 - Monitor"


df["investigation_priority"] = (
    df["calibrated_risk_score"]
    .apply(priority)
)


# ============================================================
# 6. SELECT OUTPUT COLUMNS
# ============================================================

output_columns = [
    "user",
    "user_id",
    "day",
    "Role",

    "calibrated_risk_score",
    "calibrated_risk_level",
    "investigation_priority",

    "login_count",
    "after_hours_login",

    "usb_connect_count",
    "usb_disconnect_count",
    "after_hours_usb",

    "web_activity_count",
    "unique_domains",
    "after_hours_web",

    "unique_pcs",
    "work_duration_minutes",

    "personal_anomaly_strength",
    "role_anomaly_strength",
    "behavioral_deviation_score",

    "anomaly",
    "investigation_required",

    "explanation"
]


output = df[output_columns].copy()


# ============================================================
# 7. SORT BY RISK
# ============================================================

output = output.sort_values(
    "calibrated_risk_score",
    ascending=False
)


# ============================================================
# 8. SAVE
# ============================================================

print()
print("Saving threat explanations...")

output.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 9. RESULTS
# ============================================================

print()
print("=" * 70)
print("THREAT EXPLANATION COMPLETE")
print("=" * 70)

print()
print("Total records:", len(output))

print()
print("Priority distribution:")

print(
    output["investigation_priority"]
    .value_counts()
)


print()
print("Top 10 AI-generated explanations:")

print()

for _, row in output.head(10).iterrows():

    print("-" * 70)

    print(
        "User:",
        row["user_id"]
    )

    print(
        "Date:",
        row["day"].date()
        if hasattr(row["day"], "date")
        else row["day"]
    )

    print(
        "Role:",
        row["Role"]
    )

    print(
        "Risk:",
        round(
            row["calibrated_risk_score"],
            2
        )
    )

    print(
        "Level:",
        row["calibrated_risk_level"]
    )

    print(
        "Priority:",
        row["investigation_priority"]
    )

    print(
        "Explanation:",
        row["explanation"]
    )


print()
print("Output:")
print(OUTPUT_FILE)

print()
print("=" * 70)
from pathlib import Path

import pandas as pd


DATASET = Path("dataset/extracted")
PROCESSED = Path("dataset/processed")

INPUT_FILE = PROCESSED / "user_day_features.csv"
OUTPUT_FILE = PROCESSED / "user_day_features_role.csv"


print("=" * 70)
print("CERT R1 LDAP ROLE ENRICHMENT")
print("=" * 70)


# ============================================================
# 1. LOAD USER-DAY FEATURES
# ============================================================

print()
print("Loading user-day features...")

features = pd.read_csv(
    INPUT_FILE,
    parse_dates=["day"]
)

print("User-day records:", len(features))


# ============================================================
# 2. NORMALIZE USER ID
# ============================================================

print()
print("Normalizing user IDs...")

features["user_id"] = (
    features["user"]
    .astype(str)
    .str.split("/")
    .str[-1]
)

print("Example event user:")
print(features["user"].iloc[0])

print("Normalized user ID:")
print(features["user_id"].iloc[0])


# ============================================================
# 3. LOAD LDAP FILES
# ============================================================

print()
print("Loading LDAP files...")

ldap_dir = DATASET / "LDAP"

ldap_files = sorted(
    ldap_dir.glob("*.csv")
)

print("LDAP files found:", len(ldap_files))


ldap_frames = []

for file in ldap_files:

    print("Reading:", file.name)

    ldap = pd.read_csv(file)

    ldap["ldap_month"] = file.stem

    ldap_frames.append(
        ldap[
            [
                "user_id",
                "Role",
                "ldap_month"
            ]
        ]
    )


ldap_all = pd.concat(
    ldap_frames,
    ignore_index=True
)

print()
print("LDAP records:", len(ldap_all))


# ============================================================
# 4. CREATE MONTH KEY
# ============================================================

features["ldap_month"] = (
    features["day"]
    .dt.to_period("M")
    .astype(str)
)


# ============================================================
# 5. MERGE LDAP ROLE
# ============================================================

print()
print("Attaching employee roles...")

features = features.merge(
    ldap_all,
    on=["user_id", "ldap_month"],
    how="left"
)


features["Role"] = features["Role"].fillna(
    "Unknown"
)


# ============================================================
# 6. CHECK MATCH QUALITY
# ============================================================

matched = (
    features["Role"] != "Unknown"
).sum()

unknown = (
    features["Role"] == "Unknown"
).sum()

total = len(features)

match_percentage = (
    matched / total * 100
)


print()
print("=" * 70)
print("LDAP MATCH RESULTS")
print("=" * 70)

print()
print("Total user-day records:", total)
print("Matched records:", matched)
print("Unknown records:", unknown)
print(f"Match percentage: {match_percentage:.2f}%")


# ============================================================
# 7. ROLE DISTRIBUTION
# ============================================================

print()
print("Role distribution:")

print(
    features["Role"]
    .value_counts()
    .to_string()
)


# ============================================================
# 8. SAVE
# ============================================================

features.to_csv(
    OUTPUT_FILE,
    index=False
)


print()
print("=" * 70)
print("LDAP ENRICHMENT COMPLETE")
print("=" * 70)

print()
print("Total records:", len(features))
print("Total columns:", len(features.columns))

print()
print("Output:")
print(OUTPUT_FILE)

print()
print("Sample:")

print(
    features[
        [
            "user",
            "user_id",
            "day",
            "Role",
            "login_count",
            "after_hours_login",
            "usb_connect_count",
            "web_activity_count"
        ]
    ]
    .head(10)
    .to_string(index=False)
)

print()
print("=" * 70)
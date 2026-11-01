from pathlib import Path
from urllib.parse import urlparse

import pandas as pd


DATASET = Path("dataset/extracted")
PROCESSED = Path("dataset/processed")

PROCESSED.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("CERT R1 USER-DAY FEATURE ENGINEERING")
print("=" * 70)


# ============================================================
# 1. LOGON FEATURES
# ============================================================

print()
print("[1/4] Processing logon.csv...")

logon_file = DATASET / "logon.csv"

logon = pd.read_csv(logon_file)

logon["date"] = pd.to_datetime(
    logon["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

logon["day"] = logon["date"].dt.date
logon["hour"] = logon["date"].dt.hour

logon["is_after_hours"] = (
    (logon["hour"] < 7) |
    (logon["hour"] >= 19)
)

logon_features = (
    logon.groupby(["user", "day"])
    .agg(
        login_count=("activity", lambda x: (x == "Logon").sum()),
        logout_count=("activity", lambda x: (x == "Logoff").sum()),
        after_hours_login=("is_after_hours", "sum"),
        unique_pcs=("pc", "nunique"),
        first_activity=("date", "min"),
        last_activity=("date", "max")
    )
    .reset_index()
)

logon_features["work_duration_minutes"] = (
    (
        logon_features["last_activity"]
        - logon_features["first_activity"]
    ).dt.total_seconds() / 60
)

logon_features = logon_features.drop(
    columns=["first_activity", "last_activity"]
)

print("Logon user-day records:", len(logon_features))


# ============================================================
# 2. DEVICE / USB FEATURES
# ============================================================

print()
print("[2/4] Processing device.csv...")

device_file = DATASET / "device.csv"

device = pd.read_csv(device_file)

device["date"] = pd.to_datetime(
    device["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

device["day"] = device["date"].dt.date
device["hour"] = device["date"].dt.hour

device["is_after_hours"] = (
    (device["hour"] < 7) |
    (device["hour"] >= 19)
)

device_features = (
    device.groupby(["user", "day"])
    .agg(
        usb_connect_count=("activity", lambda x: (x == "Connect").sum()),
        usb_disconnect_count=("activity", lambda x: (x == "Disconnect").sum()),
        after_hours_usb=("is_after_hours", "sum")
    )
    .reset_index()
)

device_features["usb_user"] = (
    device_features["usb_connect_count"] > 0
).astype(int)

print("Device user-day records:", len(device_features))


# ============================================================
# 3. HTTP FEATURES
# ============================================================

print()
print("[3/4] Processing HTTP data...")

http_file = PROCESSED / "http_prepared.csv"

http = pd.read_csv(
    http_file,
    parse_dates=["date"]
)

http["day"] = pd.to_datetime(http["date"]).dt.date
http["hour"] = pd.to_datetime(http["date"]).dt.hour

http["is_after_hours"] = (
    (http["hour"] < 7) |
    (http["hour"] >= 19)
)


def extract_domain(url):
    try:
        return urlparse(str(url)).netloc.lower()
    except Exception:
        return ""


print("Extracting domains...")

http["domain"] = http["url"].map(extract_domain)

http_features = (
    http.groupby(["user", "day"])
    .agg(
        web_activity_count=("url", "count"),
        unique_domains=("domain", "nunique"),
        after_hours_web=("is_after_hours", "sum")
    )
    .reset_index()
)

print("HTTP user-day records:", len(http_features))


# ============================================================
# 4. MERGE ALL BEHAVIORAL FEATURES
# ============================================================

print()
print("[4/4] Merging behavioral features...")

features = logon_features.merge(
    device_features,
    on=["user", "day"],
    how="outer"
)

features = features.merge(
    http_features,
    on=["user", "day"],
    how="outer"
)

numeric_columns = [
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
    "after_hours_web"
]

for column in numeric_columns:
    if column in features.columns:
        features[column] = features[column].fillna(0)


features["day"] = pd.to_datetime(features["day"])

features = features.sort_values(
    ["user", "day"]
).reset_index(drop=True)


# ============================================================
# SAVE
# ============================================================

output_file = PROCESSED / "user_day_features.csv"

features.to_csv(
    output_file,
    index=False
)

print()
print("=" * 70)
print("FEATURE ENGINEERING COMPLETE")
print("=" * 70)

print()
print("Total user-day records:", len(features))
print("Total features:", len(features.columns))

print()
print("Columns:")
for column in features.columns:
    print(" -", column)

print()
print("Output:")
print(output_file)

print()
print("Sample:")
print(features.head(10).to_string(index=False))

print()
print("=" * 70)
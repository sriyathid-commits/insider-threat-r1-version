from pathlib import Path
import pandas as pd

DATASET = Path("dataset/extracted")
OUTPUT = Path("dataset/processed")

HTTP_FILE = DATASET / "http.csv"
OUTPUT.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("CERT R1 HTTP DATA PREPARATION")
print("=" * 70)

columns = ["id", "date", "user", "pc", "url"]

print()
print("Reading HTTP dataset...")
print("File:", HTTP_FILE)

df = pd.read_csv(
    HTTP_FILE,
    header=None,
    names=columns
)

print()
print("HTTP records:", len(df))
print("Columns:", list(df.columns))

print()
print("First 5 records:")
print(df.head().to_string(index=False))

print()
print("Converting date column...")

df["date"] = pd.to_datetime(
    df["date"],
    format="%m/%d/%Y %H:%M:%S",
    errors="coerce"
)

invalid_dates = df["date"].isna().sum()

print("Invalid dates:", invalid_dates)

print()
print("Creating day column...")

df["day"] = df["date"].dt.date

print()
print("Unique users:", df["user"].nunique())
print("Unique PCs:", df["pc"].nunique())
print("Unique days:", df["day"].nunique())

output_file = OUTPUT / "http_prepared.csv"

print()
print("Saving:")
print(output_file)

df.to_csv(output_file, index=False)

print()
print("=" * 70)
print("HTTP PREPARATION COMPLETE")
print("=" * 70)
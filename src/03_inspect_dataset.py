from pathlib import Path
import pandas as pd

DATASET = Path("dataset/extracted")

print("=" * 70)
print("CERT R1 DATASET INSPECTION")
print("=" * 70)

files = [
    "logon.csv",
    "device.csv",
    "http.csv"
]

for filename in files:
    path = DATASET / filename

    print()
    print("-" * 70)
    print(filename)
    print("-" * 70)

    df = pd.read_csv(path, nrows=5)

    print("Columns:")
    print(list(df.columns))

    print()
    print("Sample:")
    print(df.to_string(index=False))

    print()
    print("Data types:")
    print(df.dtypes)

ldap_dir = DATASET / "LDAP"

ldap_files = sorted(ldap_dir.glob("*.csv"))

print()
print("=" * 70)
print("LDAP FILES")
print("=" * 70)

print("Number of LDAP files:", len(ldap_files))

if ldap_files:
    df = pd.read_csv(ldap_files[0])

    print()
    print("Example LDAP file:", ldap_files[0].name)
    print("Columns:")
    print(list(df.columns))

    print()
    print(df.head().to_string(index=False))

print()
print("=" * 70)
print("INSPECTION COMPLETE")
print("=" * 70)
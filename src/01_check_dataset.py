from pathlib import Path
import shutil


SOURCE_DIR = Path(r"C:\Users\yathi\Downloads\r1\r1")
TARGET_DIR = Path("dataset/extracted")


print("=" * 70)
print("CERT R1 DATASET PREPARATION")
print("=" * 70)

print()
print("Source:")
print(SOURCE_DIR)

print()
print("Target:")
print(TARGET_DIR)


# ============================================================
# 1. CHECK SOURCE
# ============================================================

if not SOURCE_DIR.exists():

    print()
    print("ERROR: Source dataset was not found.")
    print("Expected:")
    print(SOURCE_DIR)

    raise SystemExit


# ============================================================
# 2. CREATE TARGET
# ============================================================

TARGET_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# 3. COPY DATASET
# ============================================================

print()
print("Copying CERT R1 dataset...")

for item in SOURCE_DIR.iterdir():

    destination = TARGET_DIR / item.name

    if item.is_dir():

        shutil.copytree(
            item,
            destination,
            dirs_exist_ok=True
        )

    else:

        shutil.copy2(
            item,
            destination
        )

    print("Copied:", item.name)


# ============================================================
# 4. VERIFY
# ============================================================

print()
print("Verifying copied files...")

files = [
    file
    for file in TARGET_DIR.rglob("*")
    if file.is_file()
]

print()
print("Files copied:", len(files))

for file in files:
    print(" -", file)


# ============================================================
# 5. IMPORTANT CERT FILES
# ============================================================

print()
print("Checking important files...")

required_files = [
    TARGET_DIR / "logon.csv",
    TARGET_DIR / "device.csv",
    TARGET_DIR / "http.csv",
    TARGET_DIR / "readme.txt",
    TARGET_DIR / "license.txt"
]

for file in required_files:

    if file.exists():
        print("OK:", file.name)
    else:
        print("MISSING:", file.name)


# ============================================================
# 6. LDAP
# ============================================================

ldap_dir = TARGET_DIR / "LDAP"

if ldap_dir.exists():

    ldap_files = list(
        ldap_dir.glob("*.csv")
    )

    print()
    print("LDAP files:", len(ldap_files))

else:

    print()
    print("WARNING: LDAP directory not found.")


print()
print("=" * 70)
print("CERT R1 DATASET PREPARATION COMPLETE")
print("=" * 70)

print()
print("Dataset location:")
print(TARGET_DIR)
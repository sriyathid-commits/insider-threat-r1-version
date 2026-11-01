import os
import shutil
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "dataset", "processed")

print("=" * 70)
print("FINAL DATASET GENERATION")
print("=" * 70)

# ---------------------------------------------------------
# Source files
# ---------------------------------------------------------

user_day_file = os.path.join(
    PROCESSED_DIR,
    "user_day_features_role.csv"
)

ml_file = os.path.join(
    PROCESSED_DIR,
    "ml_features.csv"
)

risk_file = os.path.join(
    PROCESSED_DIR,
    "risk_scored_dataset_calibrated.csv"
)

forensic_file = os.path.join(
    PROCESSED_DIR,
    "forensic_timeline.csv"
)

explanation_file = os.path.join(
    PROCESSED_DIR,
    "threat_explanations.csv"
)

correlated_file = os.path.join(
    PROCESSED_DIR,
    "threat_evidence_correlated.csv"
)

# ---------------------------------------------------------
# Final file names
# ---------------------------------------------------------

master_output = os.path.join(
    PROCESSED_DIR,
    "CERT_Master_Dataset.csv"
)

ml_output = os.path.join(
    PROCESSED_DIR,
    "ML_Dataset.csv"
)

risk_output = os.path.join(
    PROCESSED_DIR,
    "Risk_Scored_Dataset.csv"
)

forensic_output = os.path.join(
    PROCESSED_DIR,
    "Forensic_Timeline.csv"
)

explanation_output = os.path.join(
    PROCESSED_DIR,
    "Threat_Explanations.csv"
)

correlated_output = os.path.join(
    PROCESSED_DIR,
    "Threat_Evidence_Correlated.csv"
)

# ---------------------------------------------------------
# 1. Master Dataset
# ---------------------------------------------------------

print("\nCreating CERT_Master_Dataset.csv...")

master = pd.read_csv(user_day_file)

master.to_csv(
    master_output,
    index=False
)

print(f"Records: {len(master)}")
print(f"Columns: {len(master.columns)}")

# ---------------------------------------------------------
# 2. ML Dataset
# ---------------------------------------------------------

print("\nCreating ML_Dataset.csv...")

ml = pd.read_csv(ml_file)

ml.to_csv(
    ml_output,
    index=False
)

print(f"Records: {len(ml)}")
print(f"Columns: {len(ml.columns)}")

# ---------------------------------------------------------
# 3. Risk Dataset
# ---------------------------------------------------------

print("\nCreating Risk_Scored_Dataset.csv...")

risk = pd.read_csv(risk_file)

risk.to_csv(
    risk_output,
    index=False
)

print(f"Records: {len(risk)}")
print(f"Columns: {len(risk.columns)}")

# ---------------------------------------------------------
# 4. Forensic Timeline
# ---------------------------------------------------------

print("\nCreating Forensic_Timeline.csv...")

forensic = pd.read_csv(forensic_file)

forensic.to_csv(
    forensic_output,
    index=False
)

print(f"Events: {len(forensic)}")

# ---------------------------------------------------------
# 5. Threat Explanations
# ---------------------------------------------------------

print("\nCreating Threat_Explanations.csv...")

explanations = pd.read_csv(explanation_file)

explanations.to_csv(
    explanation_output,
    index=False
)

print(f"Records: {len(explanations)}")

# ---------------------------------------------------------
# 6. Correlated Evidence
# ---------------------------------------------------------

print("\nCreating Threat_Evidence_Correlated.csv...")

correlated = pd.read_csv(correlated_file)

correlated.to_csv(
    correlated_output,
    index=False
)

print(f"Investigation cases: {len(correlated)}")

# ---------------------------------------------------------
# Final summary
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("FINAL DATASETS CREATED")
print("=" * 70)

files = [
    master_output,
    ml_output,
    risk_output,
    forensic_output,
    explanation_output,
    correlated_output
]

for file in files:
    size_mb = os.path.getsize(file) / (1024 * 1024)

    print(
        f"{os.path.basename(file):35} "
        f"{size_mb:8.2f} MB"
    )

print("\n" + "=" * 70)
print("DATASET GENERATION COMPLETE")
print("=" * 70)

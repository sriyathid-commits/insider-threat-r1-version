# 🛡️ AI-Powered Insider Threat Detection & Automated Digital Forensics System

### CMU CERT Insider Threat Dataset — Release R1

An AI-powered cybersecurity analytics platform designed to identify unusual employee behaviour, assess insider threat risks, generate explainable alerts, and support digital forensic investigations using machine learning and behavioural analysis.

---

## 📌 Project Overview

Insider threats are a major cybersecurity challenge because potentially harmful activities can originate from users who already have legitimate access to organisational systems.

This project presents an intelligent insider threat detection and digital forensics platform using the **CMU CERT Insider Threat Test Dataset – Release R1**.

The system analyses employee activities across login records, removable device usage, web browsing behaviour, and employee directory information. It applies behavioural feature engineering and the Isolation Forest algorithm to identify unusual user activity.

The platform further incorporates risk scoring, human-readable threat explanations, forensic evidence correlation, investigation reports, and security analytics dashboards.

The system is designed to assist security analysts in prioritising suspicious activities and conducting evidence-based investigations.

## 🎯 Project Objectives

- Detect unusual employee behaviour using machine learning.
- Analyse login, USB/device, and HTTP activities.
- Develop user-day behavioural profiles.
- Identify anomalous activities using Isolation Forest.
- Calculate risk scores and classify investigation priorities.
- Generate human-readable explanations for suspicious behaviour.
- Correlate digital forensic evidence across activity sources.
- Generate user-specific forensic timelines and investigation reports.
- Provide a centralised security analytics dashboard.

## 🏗️ System Architecture

The system follows a modular data-processing and threat-investigation pipeline.

```text
             CERT INSIDER THREAT DATASET R1
                         |
             +-----------+-----------+
             |           |           |
          LOGON        DEVICE       HTTP
             |           |           |
             +-----------+-----------+
                         |
                DATA PREPROCESSING
                         |
                DATA INTEGRATION
                         |
              LDAP EMPLOYEE CONTEXT
                         |
              FEATURE ENGINEERING
                         |
                USER-DAY PROFILES
                         |
              ISOLATION FOREST MODEL
                         |
                ANOMALY DETECTION
                         |
                 RISK SCORING
                         |
              THREAT EXPLANATIONS
                         |
             FORENSIC EVIDENCE
                  CORRELATION
                         |
               FORENSIC TIMELINES
                         |
             INVESTIGATION REPORTS
                         |
                SECURITY DASHBOARD
```

## ⚙️ Key Features

### 1. Dataset Inspection and Processing
- Inspection of CERT dataset files.
- Data extraction and validation.
- Missing-value and data-quality handling.
- Timestamp standardisation.
- User and computer activity mapping.

### 2. Behavioural Feature Engineering
- User-day activity aggregation.
- Login activity analysis.
- Device usage analysis.
- HTTP activity analysis.
- Employee role enrichment using LDAP information.
- Generation of machine-learning-ready features.

### 3. Machine Learning Anomaly Detection
- Isolation Forest-based unsupervised anomaly detection.
- Behavioural deviation identification.
- Anomaly score generation.
- Identification of unusual user-day activity patterns.

### 4. Risk Assessment
- Risk score calculation.
- Risk categorisation.
- Investigation prioritisation.
- Employee-role-aware analysis.

### 5. Explainable Threat Detection
- Human-readable suspicious activity explanations.
- Identification of behavioural indicators.
- Explanation-based investigation support.

### 6. Automated Digital Forensics
- Evidence collection and correlation.
- Login, device, and HTTP activity analysis.
- Forensic event reconstruction.
- User-specific investigation timelines.
- Automated investigation report generation.

### 7. Security Analytics Dashboard

The platform provides the following investigation sections:

- **Security Overview** – Centralised security monitoring and key indicators.
- **Risk Analytics** – Risk distribution and behavioural analysis.
- **User Investigation** – Individual user activity investigation.
- **Forensic Evidence** – Correlated digital evidence.
- **Investigation Reports** – Generated investigation summaries and reports.

## 🧠 Machine Learning Methodology

**Algorithm:** Isolation Forest

Isolation Forest is an unsupervised anomaly detection algorithm that identifies unusual observations by isolating data points through random partitioning.

The model is applied to engineered behavioural features to identify user-day records that differ significantly from observed activity patterns.

The resulting anomaly indicators are combined with the project's risk assessment logic to support investigation prioritisation.

**Important:** An anomaly represents unusual behaviour that requires further investigation. It does not automatically establish malicious intent.

## 📂 Dataset Information

**Dataset:** CERT Insider Threat Test Dataset – Release 1

**Source:** Carnegie Mellon University, Software Engineering Institute (CMU SEI).

**Dataset DOI:** https://doi.org/10.1184/R1/12841247

| Dataset file | Purpose |
|---|---|
| `logon.csv` | Employee login and logout activities |
| `device.csv` | Removable device activity |
| `http.csv` | Web browsing activity |
| LDAP | Employee and organisational information |

The dataset is used for research and academic experimentation in insider threat detection.

Raw datasets and large generated outputs are not included in this GitHub repository.

## 🛠️ Technologies Used

| Technology | Application |
|---|---|
| Python | Core programming |
| Pandas | Data processing |
| NumPy | Numerical operations |
| Scikit-learn | Machine learning |
| Isolation Forest | Anomaly detection |
| CSV | Dataset and result storage |
| Git and GitHub | Version control |

## 📁 Project Structure

```text
AI_Insider_Threat_Detection/
│
├── dataset/
│   ├── extracted/
│   └── processed/
│
├── src/
│   ├── 01_check_dataset.py
│   ├── 02_extract_dataset.py
│   ├── 03_inspect_dataset.py
│   ├── 04_prepare_http.py
│   ├── 05_build_features.py
│   ├── 06_add_ldap_context.py
│   ├── 07_create_behavior_features.py
│   ├── 08_train_anomaly_model.py
│   ├── 09_calibrate_risk_scores.py
│   ├── 10_build_forensic_timeline.py
│   ├── 11_generate_threat_explanations.py
│   ├── 12_correlate_threat_evidence.py
│   ├── 13_create_final_datasets.py
│   ├── 13_generate_investigation_reports.py
│   ├── 14_generate_project_artifacts.py
│   ├── 15_build_analysis_notebooks.py
│   │
│   └── email_alerts/
│
├── results/
│   ├── investigation_reports/
│   ├── investigation_summary.csv
│   ├── model_summary.txt
│   ├── project_summary.txt
│   ├── risk_distribution.csv
│   ├── role_risk_analysis.csv
│   └── top_investigations.csv
│
├── .gitignore
└── README.md
```

*Note: Large raw datasets, processed datasets, and generated security-report CSV files are maintained locally and excluded from Git tracking.*

## 🚀 Installation and Setup

### Prerequisites

- Python 3.10 or later
- Git
- Visual Studio Code (recommended)

### Step 1: Clone the repository

```bash
git clone https://github.com/sriyathid-commits/insider-threat-r1-version.git
```

### Step 2: Navigate to the project

```bash
cd insider-threat-r1-version
```

### Step 3: Create a virtual environment

```bash
python -m venv venv
```

### Step 4: Activate the environment

**Windows CMD:**

```cmd
venv\Scripts\activate
```

### Step 5: Install dependencies

```bash
pip install pandas numpy scikit-learn matplotlib seaborn jupyter
```

Install any additional packages required by the dashboard and project scripts.

### Step 6: Prepare the dataset

Obtain the CERT Insider Threat Test Dataset R1 from its official research source and place the required files in the expected dataset directories.

### Step 7: Execute the processing pipeline

Run the scripts in their intended processing order, beginning with dataset inspection and extraction, followed by preprocessing, feature engineering, anomaly detection, risk assessment, and forensic analysis.

Example:

```bash
python src/01_check_dataset.py
python src/02_extract_dataset.py
python src/03_inspect_dataset.py
```

Continue with the remaining scripts according to their dependencies and configured input/output paths.

## 📊 Expected System Outputs

The R1 implementation generates outputs for:

- Processed activity datasets.
- User-day behavioural features.
- Machine learning anomaly indicators.
- Risk-scored records.
- Human-readable threat explanations.
- Correlated forensic evidence.
- Forensic activity timelines.
- User-specific investigation reports.
- Risk distribution and investigation summaries.

## 🔐 Security and Privacy

- No personal credentials or SMTP passwords should be committed.
- Environment variables should be used for email configuration.
- Raw datasets and large generated files are excluded from the repository.
- Investigation findings should be reviewed by authorised security personnel.
- Anomaly detection results should not be treated as proof of malicious activity.

## 🔬 Research Significance

This project demonstrates how machine learning, behavioural analytics, and digital forensic techniques can be integrated into a unified insider threat investigation workflow.

Rather than relying only on predefined security rules, the proposed approach analyses user behaviour and highlights unusual activity patterns that may require further examination.

The combination of anomaly detection, risk prioritisation, explainable findings, and forensic evidence correlation supports a more structured and investigation-oriented cybersecurity workflow.



**Department of Artificial Intelligence and Data Science**  
Chaitanya Bharathi Institute of Technology (CBIT), Hyderabad.


| D. Sriyathi |

**Project Guide:** Dr. Satya Kiranmai Tadepalli  
Associate Professor

**Academic Year:** 2026–2027

## 📚 References

1. Carnegie Mellon University, Software Engineering Institute. CERT Insider Threat Test Dataset R1. https://doi.org/10.1184/R1/12841247
2. Liu, F. T., Ting, K. M., and Zhou, Z. H. (2008). Isolation Forest. IEEE International Conference on Data Mining.
3. Chandola, V., Banerjee, A., and Kumar, V. (2009). Anomaly Detection: A Survey. ACM Computing Surveys.
4. NIST Special Publication 800-86. Guide to Integrating Forensic Techniques into Incident Response.

---

**Project:** AI-Powered Insider Threat Detection & Automated Digital Forensics System  
**Version:** R1  
**Repository:** https://github.com/sriyathid-commits/insider-threat-r1-version

*Developed as an academic cybersecurity and artificial intelligence project.*

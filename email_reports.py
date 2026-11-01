
import os
import smtplib
from pathlib import Path
from datetime import datetime
from email.message import EmailMessage

import pandas as pd
from dotenv import load_dotenv

# ============================================================
# AI INSIDER THREAT DETECTION - TERMINAL EMAIL REPORTING
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = (
    BASE_DIR
    / "dataset"
    / "processed"
    / "risk_scored_dataset_calibrated.csv"
)
REPORT_DIR = BASE_DIR / "results"

load_dotenv(BASE_DIR / ".env")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_report():
    """Generate a timestamped CSV report from the existing dataset."""

    print("\n" + "=" * 60)
    print("     AI INSIDER THREAT DETECTION")
    print("             EMAIL REPORT SYSTEM")
    print("=" * 60)

    if not DATA_FILE.exists():
        print(f"\nERROR: Dataset not found:\n{DATA_FILE}")
        return None

    try:
        df = pd.read_csv(DATA_FILE)

        if df.empty:
            print("\nERROR: The dataset contains no records.")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = REPORT_DIR / f"security_report_{timestamp}.csv"

        df.to_csv(report_file, index=False)

        print(f"\nGenerated: {datetime.now():%Y-%m-%d %H:%M:%S}")
        print(f"Total records: {len(df):,}")
        print(f"Total columns: {len(df.columns)}")

        for column in df.columns:
            if any(
                term in column.lower()
                for term in ("risk_level", "risk_category", "severity")
            ):
                print(f"\n{column} distribution:")
                print(df[column].value_counts(dropna=False).to_string())

        print(f"\nReport saved:\n{report_file}")
        return report_file

    except (OSError, ValueError, pd.errors.ParserError) as error:
        print(f"\nReport generation failed: {error}")
        return None


def send_email(report_file):
    """Email the report to configured authorized recipients."""

    sender = os.getenv("SENDER_EMAIL", "").strip()
    password = os.getenv("SENDER_APP_PASSWORD", "").strip()
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        print("ERROR: SMTP_PORT must be a number.")
        return False

    recipients = [
        address.strip()
        for address in os.getenv("AUTHORIZED_EMAILS", "").split(",")
        if address.strip()
    ]

    if not sender or not password:
        print("\nERROR: Configure SENDER_EMAIL and SENDER_APP_PASSWORD in .env.")
        return False

    if not recipients:
        print("\nERROR: No recipients configured in AUTHORIZED_EMAILS.")
        return False

    if not report_file.exists():
        print("\nERROR: Report attachment does not exist.")
        return False

    message = EmailMessage()
    message["Subject"] = "AI Insider Threat Detection - Security Report"
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(
        "Hello,\n\n"
        "The latest AI Insider Threat Detection security report is attached.\n\n"
        "This report contains potentially sensitive security information. "
        "Please handle it according to your organization's security policy "
        "and share it only with authorized personnel.\n\n"
        "This report is generated from the existing calibrated risk dataset. "
        "It does not independently confirm that every flagged record is "
        "a genuine insider threat.\n"
    )

    try:
        with open(report_file, "rb") as file:
            message.add_attachment(
                file.read(),
                maintype="text",
                subtype="csv",
                filename=report_file.name,
            )

        print("\nConnecting to email server...")

        with smtplib.SMTP(smtp_host, smtp_port, timeout=60) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender, password)
            server.send_message(message)

        print("\nSUCCESS: Email sent.")
        print("Recipients:", ", ".join(recipients))
        return True

    except (smtplib.SMTPException, OSError, ValueError) as error:
        print(f"\nEMAIL DELIVERY FAILED: {error}")
        return False


def main():
    """Run the interactive terminal workflow."""

    report_file = generate_report()

    if report_file is None:
        return

    print("\nOPTIONS")
    print("1. Save report only")
    print("2. Email report to authorized recipients")
    print("3. Exit")

    choice = input("\nSelect option (1/2/3): ").strip()

    if choice == "1":
        print("\nReport saved. No email sent.")

    elif choice == "2":
        confirm = input(
            "Send this report to configured recipients? (y/n): "
        ).strip().lower()

        if confirm == "y":
            send_email(report_file)
        else:
            print("Email cancelled. Report remains saved.")

    elif choice == "3":
        print("Exiting.")

    else:
        print("Invalid option. Run the program again.")


if __name__ == "__main__":
    main()

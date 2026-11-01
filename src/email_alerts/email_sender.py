
import smtplib
import ssl
from datetime import datetime

from .smtp_config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_EMAIL,
    SMTP_PASSWORD,
    ALERT_RECEIVER
)

from .alert_template import create_alert_email


def send_security_alert(
    employee_id,
    incident_id,
    risk_level,
    risk_score,
    detection_source,
    explanation
):
    if risk_level.lower() not in ("high", "critical"):
        print("[INFO] Email not required for this risk level.")
        return False

    timestamp = datetime.now().astimezone().isoformat()

    message = create_alert_email(
        employee_id,
        incident_id,
        risk_level,
        risk_score,
        detection_source,
        timestamp,
        explanation
    )

    message["From"] = SMTP_EMAIL
    message["To"] = ALERT_RECEIVER

    context = ssl.create_default_context()

    try:
        print("[INFO] Connecting to Gmail SSL...")

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=25
        ) as server:

            print("[INFO] Authenticating Gmail...")
            server.login(SMTP_EMAIL, SMTP_PASSWORD)

            print("[INFO] Sending security alert...")
            server.send_message(message)

        print("[SUCCESS] Email sent successfully.")
        return True

    except Exception as error:
        print("[EMAIL ERROR]", type(error).__name__, str(error))
        return False

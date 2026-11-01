from email.message import EmailMessage


def create_alert_email(
    employee_id,
    incident_id,
    risk_level,
    risk_score,
    detection_source,
    timestamp,
    explanation
):
    message = EmailMessage()

    message["Subject"] = (
        f"[{risk_level.upper()} ALERT] "
        f"Insider Threat Detected - {incident_id}"
    )

    message.set_content(f"""
R1 INSIDER THREAT DETECTION SYSTEM

Dear Security Administrator,

Suspicious employee activity has been detected.

INCIDENT DETAILS
----------------
Incident ID: {incident_id}
Employee ID: {employee_id}
Risk Level: {risk_level}
Risk Score: {risk_score}
Detection Source: {detection_source}
Timestamp: {timestamp}

THREAT EXPLANATION
------------------
{explanation}

Please investigate the associated forensic evidence.

Regards,
R1 Automated Security Monitoring System
""")

    return message
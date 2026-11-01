import os
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_RECEIVER = os.getenv("ALERT_RECEIVER")

if not all([SMTP_EMAIL, SMTP_PASSWORD, ALERT_RECEIVER]):
    raise ValueError("SMTP configuration is incomplete.")
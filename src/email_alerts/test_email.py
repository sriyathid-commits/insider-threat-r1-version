from .email_sender import send_security_alert

if __name__ == "__main__":

    print("Testing R1 Gmail SMTP Integration...")

    result = send_security_alert(
        employee_id="TEST_USER_001",
        incident_id="R1-TEST-001",
        risk_level="critical",
        risk_score=94,
        detection_source="EMAIL + USB",
        explanation=(
            "This is a test notification "
            "for the R1 security system."
        )
    )

    if result:
        print("R1 EMAIL SYSTEM TEST PASSED")
    else:
        print("R1 EMAIL SYSTEM TEST FAILED")
from datetime import datetime
import os


ALERT_FILE = "alerts.log"


def generate_alert(src_ip, session_id, risk_score, risk_level, action):
    """
    Generate an admin alert for MEDIUM, HIGH and CRITICAL activity.
    LOW-risk activity does not generate an alert.
    """

    if risk_level == "LOW":
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert_key = f"{session_id}|{risk_score}|{risk_level}|{action}"

    # Avoid creating the same alert repeatedly
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as file:
            if alert_key in file.read():
                return

    alert = (
        f"[{timestamp}] "
        f"IP: {src_ip} | "
        f"Session: {session_id} | "
        f"Risk: {risk_score} | "
        f"Level: {risk_level} | "
        f"Action: {action} | "
        f"Key: {alert_key}\n"
    )

    print("\n🚨 HONEYTRACK SECURITY ALERT 🚨")
    print(alert.strip())

    with open(ALERT_FILE, "a") as file:
        file.write(alert)

import sqlite3
from datetime import datetime, timedelta

DATABASE = "database/honeytrack.db"


def get_firewall_action(risk_score):
    """
    Decide the firewall action based on the risk score.
    """

    if risk_score < 30:
        return "Monitor"

    elif risk_score < 60:
        return "Alert + Block 30 min"

    elif risk_score < 80:
        return "Block 30 min"

    else:
        return "Permanent Block"


def get_risk_level(risk_score):
    """
    Convert risk score into a risk level.
    """

    if risk_score < 30:
        return "LOW"

    elif risk_score < 60:
        return "MEDIUM"

    elif risk_score < 80:
        return "HIGH"

    else:
        return "CRITICAL"


def create_firewall_rule(src_ip, risk_score, session_id=None):
    """
    Create a firewall rule in the HoneyTrack database.
    """

    action = get_firewall_action(risk_score)
    risk_level = get_risk_level(risk_score)

    # LOW risk does not create a firewall rule
    if action == "Monitor":
        print(f"[FIREWALL] {src_ip} -> Monitor")
        return action

    # Calculate expiry time
    expires_at = None

    if action == "Alert + Block 30 min" or action == "Block 30 min":
        expires_at = (
            datetime.now() + timedelta(minutes=30)
        ).strftime("%Y-%m-%d %H:%M:%S")

    # Permanent block has no expiry
    if action == "Permanent Block":
        expires_at = None

    reason = (
        f"Risk Level: {risk_level}, "
        f"Risk Score: {risk_score}"
    )

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if the same active rule already exists
    cursor.execute("""
        SELECT COUNT(*)
        FROM firewall_rules
        WHERE src_ip = ?
        AND action = ?
        AND status = 'ACTIVE'
    """, (src_ip, action))

    exists = cursor.fetchone()[0]

    if exists == 0:

        cursor.execute("""
            INSERT INTO firewall_rules
            (
                timestamp,
                src_ip,
                action,
                reason,
                status,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip,
            action,
            reason,
            "ACTIVE",
            expires_at
        ))

        conn.commit()

        print()
        print("========== FIREWALL ACTION ==========")
        print(f"Session ID : {session_id}")
        print(f"Source IP  : {src_ip}")
        print(f"Risk Score : {risk_score}")
        print(f"Risk Level : {risk_level}")
        print(f"Action     : {action}")
        print(f"Expires    : {expires_at if expires_at else 'Never'}")
        print("======================================")
        print()

    else:
        print(
            f"[FIREWALL] Existing active rule for "
            f"{src_ip}: {action}"
        )

    conn.close()

    return action


def terminate_session(session_id):
    """
    Placeholder for terminating the current Cowrie session.

    Cowrie session termination will be connected here once
    the exact Cowrie session-control method is integrated.
    """

    print()
    print("========== SESSION TERMINATION ==========")
    print(f"Session ID: {session_id}")
    print("Action: Current Cowrie session should be terminated.")
    print("=========================================")
    print()


def process_firewall_decision(src_ip, risk_score, session_id=None):
    """
    Main firewall function used by HoneyTrack.
    """

    action = create_firewall_rule(
        src_ip,
        risk_score,
        session_id
    )

    # Critical = Permanent Block
    if action == "Permanent Block":

        print(
            f"[ALERT] CRITICAL threat detected from {src_ip}"
        )

        if session_id:
            terminate_session(session_id)

    elif action == "Block 30 min":

        print(
            f"[ALERT] HIGH risk detected from {src_ip}"
        )

    elif action == "Alert + Block 30 min":

        print(
            f"[ALERT] MEDIUM risk detected from {src_ip}"
        )

    return action

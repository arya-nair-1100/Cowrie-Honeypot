import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone


DB_PATH = "database/honeytrack.db"
TEMP_BLOCK_MINUTES = 30


# ---------------------------------------------------------
# Check whether an IP is already blocked by UFW
# ---------------------------------------------------------
def is_ip_blocked(ip):
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            print("Unable to check UFW status.")
            return False

        for line in result.stdout.splitlines():
            if "DENY" in line and ip in line:
                return True

        return False

    except Exception as e:
        print("Error checking firewall:", e)
        return False


# ---------------------------------------------------------
# Block an IP using UFW
# ---------------------------------------------------------
def block_ip(ip):

    # Never block localhost during testing
    if ip in ("127.0.0.1", "::1"):
        print(f"Safety check: {ip} will not be blocked.")
        return False

    # Avoid duplicate UFW rules
    if is_ip_blocked(ip):
        print(f"{ip} is already blocked.")
        return True

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            print(f"Firewall: {ip} blocked successfully.")
            return True

        print("UFW error:", result.stderr.strip())
        return False

    except Exception as e:
        print("Error blocking IP:", e)
        return False


# ---------------------------------------------------------
# Unblock an IP using UFW
# ---------------------------------------------------------
def unblock_ip(ip):

    try:
        result = subprocess.run(
            ["sudo", "ufw", "delete", "deny", "from", ip],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            print(f"Firewall: {ip} unblocked successfully.")
            return True

        print("UFW error:", result.stderr.strip())
        return False

    except Exception as e:
        print("Error unblocking IP:", e)
        return False


# ---------------------------------------------------------
# Record firewall action in database
# ---------------------------------------------------------
def record_firewall_action(ip, action, reason, expires_at=None):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check for an existing ACTIVE rule
    cursor.execute("""
        SELECT id, action
        FROM firewall_rules
        WHERE src_ip = ?
        AND status = 'ACTIVE'
    """, (ip,))

    existing = cursor.fetchone()

    if existing:

        existing_id, existing_action = existing

        # If it is already permanently blocked,
        # do not replace it with a temporary block.
        if existing_action == "Permanent Block":
            conn.close()
            return

        # If current action is Permanent Block,
        # upgrade the existing rule.
        if action == "Permanent Block":
            cursor.execute("""
                UPDATE firewall_rules
                SET action = ?,
                    reason = ?,
                    expires_at = NULL,
                    status = 'ACTIVE'
                WHERE id = ?
            """, (
                action,
                reason,
                existing_id
            ))

        conn.commit()
        conn.close()
        return

    # No active rule exists, so create one
    timestamp = datetime.now(timezone.utc).isoformat()

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
        timestamp,
        ip,
        action,
        reason,
        "ACTIVE",
        expires_at
    ))

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Apply firewall action
# ---------------------------------------------------------
def apply_firewall_action(ip, action, risk_score=None):

    # LOW → Monitor → Do nothing
    if action == "Monitor":
        print(f"{ip}: Monitor only. No firewall action.")
        return

    reason = (
        f"Risk Score {risk_score}"
        if risk_score is not None
        else "Risk based firewall action"
    )

    # -----------------------------------------------------
    # MEDIUM / HIGH → Temporary block
    # -----------------------------------------------------
    if action in (
        "Alert + Block 30 min",
        "Block 30 min"
    ):

        # Already permanently blocked
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT action
            FROM firewall_rules
            WHERE src_ip = ?
            AND status = 'ACTIVE'
        """, (ip,))

        existing = cursor.fetchone()
        conn.close()

        if existing and existing[0] == "Permanent Block":
            print(f"{ip} is permanently blocked.")
            return

        # Block IP
        if block_ip(ip):

            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(minutes=TEMP_BLOCK_MINUTES)
            ).isoformat()

            record_firewall_action(
                ip,
                action,
                reason,
                expires_at
            )

            print(
                f"{ip}: Temporary block applied "
                f"for {TEMP_BLOCK_MINUTES} minutes."
            )

        return

    # -----------------------------------------------------
    # CRITICAL → Permanent block
    # -----------------------------------------------------
    if action == "Permanent Block":

        if block_ip(ip):

            record_firewall_action(
                ip,
                action,
                reason,
                None
            )

            print(f"{ip}: Permanent block applied.")

        return

    print(f"Unknown firewall action: {action}")


# ---------------------------------------------------------
# Expire temporary firewall blocks
# ---------------------------------------------------------
def expire_temporary_blocks():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, src_ip, expires_at
        FROM firewall_rules
        WHERE status = 'ACTIVE'
        AND expires_at IS NOT NULL
    """)

    rules = cursor.fetchall()

    now = datetime.now(timezone.utc)

    for rule_id, ip, expires_at in rules:

        try:
            expiry_time = datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )

            if expiry_time <= now:

                print(f"Temporary block expired for {ip}")

                # Remove UFW rule
                if unblock_ip(ip):

                    cursor.execute("""
                        UPDATE firewall_rules
                        SET status = 'EXPIRED'
                        WHERE id = ?
                    """, (rule_id,))

                    print(
                        f"{ip}: Database status changed to EXPIRED."
                    )

        except Exception as e:
            print(
                f"Error processing expiry for {ip}:",
                e
            )

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# Process firewall rules from database
# ---------------------------------------------------------
def process_firewall_rules():

    # First remove expired temporary blocks
    expire_temporary_blocks()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT src_ip, action, reason
        FROM firewall_rules
        WHERE status = 'ACTIVE'
    """)

    rules = cursor.fetchall()

    conn.close()

    for ip, action, reason in rules:

        if action == "Monitor":
            continue

        # Extract risk score if available
        risk_score = None

        if reason and "Risk Score" in reason:
            try:
                risk_score = int(
                    reason.replace("Risk Score", "").strip()
                )
            except ValueError:
                pass

        apply_firewall_action(
            ip,
            action,
            risk_score
        )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
if __name__ == "__main__":

    print("================================")
    print(" HoneyTrack Firewall Module")
    print("================================")

    process_firewall_rules()

    print("\nFirewall processing completed.")

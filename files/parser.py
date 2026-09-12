import json
import sqlite3
from datetime import datetime, timedelta

from risk_engine import calculate_risk
from command_risk import get_command_score


# ================= CONFIGURATION =================

LOGFILE = "/home/neha/cowrie/var/log/cowrie/cowrie.json"
DB_PATH = "database/honeytrack.db"


# ================= DATABASE CONNECTION =================

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


# ================= STORE LOGIN INFORMATION =================

sessions = {}

with open(LOGFILE, "r") as file:

    for line in file:

        try:
            log = json.loads(line)

            eventid = log.get("eventid", "")
            session_id = log.get("session")

            if not session_id:
                continue


            # ================= LOGIN EVENTS =================

            if eventid in [
                "cowrie.login.failed",
                "cowrie.login.success"
            ]:

                if session_id not in sessions:

                    sessions[session_id] = {
                        "timestamp": log.get("timestamp"),
                        "src_ip": log.get("src_ip"),
                        "protocol": log.get("protocol", ""),
                        "username": log.get("username", ""),
                        "password": log.get("password", ""),
                        "failed_attempts": 0,
                        "successful": False
                    }

                session = sessions[session_id]

                session["timestamp"] = log.get("timestamp")
                session["username"] = log.get("username", "")
                session["password"] = log.get("password", "")
                session["protocol"] = log.get("protocol", "")

                if eventid == "cowrie.login.failed":
                    session["failed_attempts"] += 1

                elif eventid == "cowrie.login.success":
                    session["successful"] = True


        except Exception as e:
            print("Error reading login:", e)


# ================= PROCESS SESSIONS =================

for session_id, data in sessions.items():

    try:

        # Calculate authentication risk using the final login
        # and the number of failed attempts.

        final_event = (
            "cowrie.login.success"
            if data["successful"]
            else "cowrie.login.failed"
        )

        score, level, action = calculate_risk(
            username=data["username"],
            password=data["password"],
            eventid=final_event,
            protocol=data["protocol"],
            attempts=max(1, data["failed_attempts"]),
            previous_attacks=0
        )


        # ================= COMMAND RISK =================

        cursor.execute("""
            SELECT COALESCE(SUM(command_risk), 0)
            FROM commands
            WHERE session_id=?
        """, (session_id,))

        command_risk = cursor.fetchone()[0]

        final_score = min(100, score + command_risk)


        # ================= FINAL RISK LEVEL =================

        if final_score < 30:
            level = "LOW"
            action = "Monitor"

        elif final_score < 60:
            level = "MEDIUM"
            action = "Alert + Block 30 min"

        elif final_score < 80:
            level = "HIGH"
            action = "Block 30 min"

        else:
            level = "CRITICAL"
            action = "Permanent Block"


        # ================= INSERT / UPDATE SESSION =================

        cursor.execute("""
            SELECT session_id
            FROM sessions
            WHERE session_id=?
        """, (session_id,))

        existing = cursor.fetchone()


        if existing:

            cursor.execute("""
                UPDATE sessions
                SET timestamp=?,
                    src_ip=?,
                    protocol=?,
                    username=?,
                    password=?,
                    login_status=?,
                    risk_score=?,
                    risk_level=?,
                    firewall_action=?
                WHERE session_id=?
            """, (
                data["timestamp"],
                data["src_ip"],
                data["protocol"],
                data["username"],
                data["password"],
                final_event,
                final_score,
                level,
                action,
                session_id
            ))

        else:

            cursor.execute("""
                INSERT INTO sessions(
                    session_id,
                    timestamp,
                    src_ip,
                    protocol,
                    username,
                    password,
                    login_status,
                    risk_score,
                    risk_level,
                    firewall_action
                )
                VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (
                session_id,
                data["timestamp"],
                data["src_ip"],
                data["protocol"],
                data["username"],
                data["password"],
                final_event,
                final_score,
                level,
                action
            ))


        # ================= FIREWALL RULE =================

        if action != "Monitor":

            cursor.execute("""
                SELECT COUNT(*)
                FROM firewall_rules
                WHERE src_ip=?
                AND action=?
                AND status='ACTIVE'
            """, (
                data["src_ip"],
                action
            ))

            exists = cursor.fetchone()[0]


            if exists == 0:

                if action == "Permanent Block":

                    expires_at = None

                else:

                    try:
                        dt = datetime.fromisoformat(
                            data["timestamp"].replace("Z", "+00:00")
                        )

                        expires_at = (
                            dt + timedelta(minutes=30)
                        ).isoformat()

                    except:
                        expires_at = None


                cursor.execute("""
                    INSERT INTO firewall_rules(
                        timestamp,
                        src_ip,
                        action,
                        reason,
                        status,
                        expires_at
                    )
                    VALUES(?,?,?,?,?,?)
                """, (
                    data["timestamp"],
                    data["src_ip"],
                    action,
                    f"Risk Score {final_score}",
                    "ACTIVE",
                    expires_at
                ))


    except Exception as e:

        print("Error processing session:", e)


# ================= COMMAND INSERTION =================

# Insert commands only if they don't already exist.

with open(LOGFILE, "r") as file:

    for line in file:

        try:
            log = json.loads(line)

            if log.get("eventid") != "cowrie.command.input":
                continue

            session_id = log.get("session")
            timestamp = log.get("timestamp")
            command = log.get("input", "")

            if not session_id:
                continue

            command_score = get_command_score(command)

            cursor.execute("""
                SELECT COUNT(*)
                FROM commands
                WHERE session_id=?
                AND timestamp=?
                AND command=?
            """, (
                session_id,
                timestamp,
                command
            ))

            exists = cursor.fetchone()[0]

            if exists == 0:

                cursor.execute("""
                    INSERT INTO commands(
                        session_id,
                        timestamp,
                        command,
                        command_risk
                    )
                    VALUES(?,?,?,?)
                """, (
                    session_id,
                    timestamp,
                    command,
                    command_score
                ))


        except Exception as e:

            print("Error reading command:", e)


# ================= SAVE =================

conn.commit()
conn.close()

print("HoneyTrack database updated successfully.")

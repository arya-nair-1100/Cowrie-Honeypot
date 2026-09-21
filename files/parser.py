import json
import sqlite3
from datetime import datetime, timedelta

from risk_engine import calculate_risk
from command_risk import get_command_score, sequence_risk
from alerts import generate_alert


# ================= CONFIGURATION =================

LOGFILE = "/home/devika2007/cowrie/var/log/cowrie/cowrie.json"
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

                session["timestamp"] = log.get(
                    "timestamp",
                    session["timestamp"]
                )

                session["src_ip"] = log.get(
                    "src_ip",
                    session["src_ip"]
                )

                session["username"] = log.get(
                    "username",
                    session["username"]
                )

                session["password"] = log.get(
                    "password",
                    session["password"]
                )

                session["protocol"] = log.get(
                    "protocol",
                    session["protocol"]
                )

                if eventid == "cowrie.login.failed":

                    session["failed_attempts"] += 1

                elif eventid == "cowrie.login.success":

                    session["successful"] = True

        except Exception as e:

            print("Error reading login:", e)


# ================= COMMAND INSERTION =================
# Commands must be inserted before risk calculation.

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

            # Avoid duplicate command entries

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


# ================= PROCESS SESSIONS =================

for session_id, data in sessions.items():

    try:

        # ================= FINAL LOGIN EVENT =================

        final_event = (
            "cowrie.login.success"
            if data["successful"]
            else "cowrie.login.failed"
        )


        # ================= GET COMMANDS =================

        cursor.execute("""
            SELECT command, command_risk
            FROM commands
            WHERE session_id=?
            ORDER BY timestamp
        """, (session_id,))

        command_rows = cursor.fetchall()

        command_list = [
            row["command"]
            for row in command_rows
        ]


        # ================= COMMAND RISK =================

        command_risk = sum(
            row["command_risk"]
            for row in command_rows
        )


        # ================= SUSPICIOUS COMMANDS =================

        suspicious_commands = sum(
            1
            for row in command_rows
            if row["command_risk"] >= 10
        )


        # ================= COMMAND SEQUENCE RISK =================

        sequence_score = sequence_risk(command_list)


        # ================= COMMAND CATEGORIES =================

        categories = set()

        for command in command_list:

            command = command.lower().strip()

            if command.startswith(("sudo", "su")):

                categories.add("privilege")

            elif command.startswith(("wget", "curl")):

                categories.add("download")

            elif command.startswith("scp"):

                categories.add("transfer")

            elif command.startswith(("rm", "shred", "mkfs")):

                categories.add("destructive")

            elif command.startswith(("chmod", "chown")):

                categories.add("permission")

            elif command.startswith((
                "netstat",
                "ifconfig",
                "ip",
                "ss",
                "route",
                "arp"
            )):

                categories.add("network")

            elif command.startswith((
                "cat",
                "find",
                "ps",
                "grep",
                "locate",
                "whoami",
                "id",
                "uname",
                "hostname"
            )):

                categories.add("discovery")

            elif command.startswith((
                "bash",
                "sh",
                "python",
                "python3",
                "perl"
            )):

                categories.add("execution")

            elif command.startswith((
                "kill",
                "pkill",
                "systemctl"
            )):

                categories.add("process_control")

            else:

                categories.add("normal")


        command_categories = len(categories)


        # ================= TOTAL COMMAND CONTRIBUTION =================

        # Individual command risk + behavioural sequence risk

        total_command_risk = min(
            command_risk + sequence_score,
            50
        )


        # ================= ADVANCED RISK CALCULATION =================

        score, level, action = calculate_risk(

            username=data["username"],

            password=data["password"],

            eventid=final_event,

            protocol=data["protocol"],

            attempts=max(
                1,
                data["failed_attempts"]
            ),

            previous_attacks=0,

            command_risk=total_command_risk,

            suspicious_commands=suspicious_commands,

            command_categories=command_categories
        )


        # ================= FINAL SCORE =================

        final_score = min(
            100,
            score
        )


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


        # ================= ADMIN ALERT =================

        generate_alert(
            src_ip=data["src_ip"],
            session_id=session_id,
            risk_score=final_score,
            risk_level=level,
            action=action
        )


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

                # Permanent block has no expiry

                if action == "Permanent Block":

                    expires_at = None

                # Temporary block expires after 30 minutes

                else:

                    try:

                        dt = datetime.fromisoformat(
                            data["timestamp"].replace(
                                "Z",
                                "+00:00"
                            )
                        )

                        expires_at = (
                            dt + timedelta(minutes=30)
                        ).isoformat()

                    except Exception:

                        expires_at = (
                            datetime.now()
                            + timedelta(minutes=30)
                        ).isoformat()


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

        print(
            f"Error processing session {session_id}:",
            e
        )


# ================= SAVE =================

conn.commit()
conn.close()

print("HoneyTrack database updated successfully.")

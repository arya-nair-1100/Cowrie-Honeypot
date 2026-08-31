import json
import sqlite3

from risk_engine import calculate_risk
from command_risk import get_command_score

LOGFILE = "/home/arya/cowrie/var/log/cowrie/cowrie.json"

conn = sqlite3.connect("database/honeytrack.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

with open(LOGFILE, "r") as file:
    for line in file:

        try:
            log = json.loads(line)

            # ================= LOGIN EVENTS =================

            if "username" in log:

                session_id = log.get("session")
                src_ip = log.get("src_ip")

                cursor.execute(
                    "SELECT COUNT(*) FROM sessions WHERE src_ip=?",
                    (src_ip,)
                )

                previous = cursor.fetchone()[0]

                score, level, action = calculate_risk(
                    username=log.get("username", ""),
                    password=log.get("password", ""),
                    eventid=log.get("eventid", ""),
                    protocol=log.get("protocol", ""),
                    attempts=1,
                    previous_attacks=previous
                )

                cursor.execute("""
                    INSERT OR IGNORE INTO sessions(
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
                    log.get("timestamp"),
                    src_ip,
                    log.get("protocol"),
                    log.get("username"),
                    log.get("password"),
                    log.get("eventid"),
                    score,
                    level,
                    action
                ))

            # ================= COMMAND EVENTS =================

            elif log.get("eventid") == "cowrie.command.input":

                session_id = log.get("session")
                command = log.get("input", "")

                command_score = get_command_score(command)

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
                    log.get("timestamp"),
                    command,
                    command_score
                ))

                cursor.execute("""
                    SELECT risk_score, src_ip
                    FROM sessions
                    WHERE session_id=?
                """, (session_id,))

                row = cursor.fetchone()

                if row:

                    new_score = row["risk_score"] + command_score

                    if new_score > 100:
                        new_score = 100

                    if new_score < 30:
                        level = "LOW"
                        action = "Monitor"

                    elif new_score < 60:
                        level = "MEDIUM"
                        action = "Alert + Block 30 min"

                    elif new_score < 80:
                        level = "HIGH"
                        action = "Block 30 min"

                    else:
                        level = "CRITICAL"
                        action = "Permanent Block"

                    cursor.execute("""
                        UPDATE sessions
                        SET risk_score=?,
                            risk_level=?,
                            firewall_action=?
                        WHERE session_id=?
                    """, (
                        new_score,
                        level,
                        action,
                        session_id
                    ))

                    # ================= FIREWALL RULES =================

                    if action != "Monitor":

                        cursor.execute("""
                            SELECT COUNT(*)
                            FROM firewall_rules
                            WHERE src_ip=? AND action=? AND status='ACTIVE'
                        """, (
                            row["src_ip"],
                            action
                        ))

                        exists = cursor.fetchone()[0]

                        if exists == 0:

                            cursor.execute("""
                                INSERT INTO firewall_rules(
                                    timestamp,
                                    src_ip,
                                    action,
                                    reason,
                                    status
                                )
                                VALUES(?,?,?,?,?)
                            """, (
                                log.get("timestamp"),
                                row["src_ip"],
                                action,
                                f"Risk Score {new_score}",
                                "ACTIVE"
                            ))

        except Exception as e:
            print("Error:", e)

conn.commit()
conn.close()

print("HoneyTrack database updated successfully.")

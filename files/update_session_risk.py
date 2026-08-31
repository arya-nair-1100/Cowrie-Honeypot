import sqlite3
from command_risk import get_command_score

conn = sqlite3.connect("database/honeytrack.db")
cursor = conn.cursor()

# Get all sessions
cursor.execute("SELECT session_id FROM sessions")
sessions = cursor.fetchall()

for (session_id,) in sessions:

    # Get all commands for this session
    cursor.execute(
        "SELECT command FROM commands WHERE session_id = ?",
        (session_id,)
    )

    commands = cursor.fetchall()

    total_score = 0

    for (command,) in commands:
        total_score += get_command_score(command)

    # Decide level and action
    if total_score >= 90:
        level = "CRITICAL"
        action = "Permanent Block"

    elif total_score >= 60:
        level = "HIGH"
        action = "Block 30 min"

    elif total_score >= 30:
        level = "MEDIUM"
        action = "Alert + Monitor"

    else:
        level = "LOW"
        action = "Monitor"

    cursor.execute("""
        UPDATE sessions
        SET risk_score = ?,
            risk_level = ?,
            firewall_action = ?
        WHERE session_id = ?
    """, (
        total_score,
        level,
        action,
        session_id
    ))

conn.commit()
conn.close()

print("Session risks updated successfully.")

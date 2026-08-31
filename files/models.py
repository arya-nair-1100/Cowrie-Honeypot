import sqlite3

DB_PATH = "database/honeytrack.db"

def insert_attack(timestamp, src_ip, username, password, eventid, risk_score, action_taken):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO attacks
    (timestamp, src_ip, username, password, eventid, risk_score, action_taken)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        src_ip,
        username,
        password,
        eventid,
        risk_score,
        action_taken
    ))

    conn.commit()
    conn.close()

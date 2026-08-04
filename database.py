
import sqlite3

DB_NAME = "honeytrack.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS attacks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        username TEXT,
        password TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        firewall_action TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_attack(timestamp, ip, username, password,
                  risk_score, risk_level, firewall_action):

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
    INSERT INTO attacks(
        timestamp,
        ip,
        username,
        password,
        risk_score,
        risk_level,
        firewall_action
    )
    VALUES (?,?,?,?,?,?,?)
    """,
    (
        timestamp,
        ip,
        username,
        password,
        risk_score,
        risk_level,
        firewall_action
    ))

    conn.commit()
    conn.close()


def get_all_attacks():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
    SELECT *
    FROM attacks
    ORDER BY id DESC
    """)

    rows = c.fetchall()

    conn.close()

    return rows

import sqlite3
import os

# ================= CONFIGURATION =================

DB_PATH = "database/honeytrack.db"

# Make sure database folder exists
os.makedirs("database", exist_ok=True)


# ================= DATABASE CONNECTION =================

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()


# ================= SESSIONS TABLE =================

cursor.execute("""
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    timestamp TEXT,
    src_ip TEXT,
    protocol TEXT,
    username TEXT,
    password TEXT,
    login_status TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    firewall_action TEXT,
    risk_reasons TEXT
)
""")


# ================= COMMANDS TABLE =================

cursor.execute("""
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    timestamp TEXT,
    command TEXT,
    command_risk INTEGER
)
""")


# ================= FIREWALL RULES TABLE =================

cursor.execute("""
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    action TEXT,
    reason TEXT,
    status TEXT,
    expires_at TEXT
)
""")


# ================= SAVE =================

conn.commit()
conn.close()

print("HoneyTrack database initialized successfully.")

import sqlite3
import os

os.makedirs("database", exist_ok=True)

conn = sqlite3.connect("database/honeytrack.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    username TEXT,
    password TEXT,
    eventid TEXT,
    risk_score INTEGER,
    action_taken TEXT
)
""")

conn.commit()
conn.close()

print("Database created successfully!")

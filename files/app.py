from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE = "database/honeytrack.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():

    conn = get_db_connection()

    # Latest sessions
    sessions = conn.execute("""
        SELECT *
        FROM sessions
        ORDER BY timestamp DESC
        LIMIT 10
    """).fetchall()

    # Latest commands
    commands = conn.execute("""
        SELECT *
        FROM commands
        ORDER BY timestamp DESC
        LIMIT 10
    """).fetchall()

    # Dashboard statistics
    total_sessions = conn.execute("""
        SELECT COUNT(*) FROM sessions
    """).fetchone()[0]

    total_commands = conn.execute("""
        SELECT COUNT(*) FROM commands
    """).fetchone()[0]

    high_risk = conn.execute("""
        SELECT COUNT(*)
        FROM sessions
        WHERE risk_score >= 70
    """).fetchone()[0]

    blocked = conn.execute("""
        SELECT COUNT(*)
        FROM sessions
        WHERE firewall_action != 'Monitor'
    """).fetchone()[0]

    # Active Firewall Rules
    firewall_rules = conn.execute("""
        SELECT *
        FROM firewall_rules
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html","style.css",
        sessions=sessions,
        commands=commands,
        firewall_rules=firewall_rules,
        total_sessions=total_sessions,
        total_commands=total_commands,
        high_risk=high_risk,
        blocked=blocked
    )


if __name__ == "__main__":
    app.run(debug=True)

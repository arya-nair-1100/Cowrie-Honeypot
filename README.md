# Cowrie-Honeypot


# 🐝 HoneyTrack+

### Intelligent SSH Honeypot Monitoring System with Adaptive Firewall

**Version:** 1.0
**Project Type:** Final Year Cybersecurity Project

## 📌 Overview

HoneyTrack+ is an intelligent SSH honeypot monitoring system built using **Cowrie**. It is designed to capture SSH attack activity, analyse attacker behaviour, calculate dynamic risk scores, and display security events through a Flask-based dashboard.

The project simulates a lightweight **Security Operations Center (SOC)** by combining honeypot monitoring, risk assessment, database storage, and adaptive firewall decisions.

> **Note:** HoneyTrack+ is intended for cybersecurity education, controlled lab environments, and security research.

## 🎯 Objectives

* Capture SSH login attempts and attacker activity.
* Record usernames, passwords, source IPs, and executed commands.
* Calculate a dynamic risk score for each session.
* Categorise sessions into risk levels.
* Generate adaptive firewall decisions.
* Store attack data in SQLite.
* Display monitoring information through a web dashboard.

## 🏗️ System Architecture

```text
Attacker
   ↓
SSH Login Attempt (Port 2222)
   ↓
Cowrie Honeypot
   ↓
cowrie.json
   ↓
Python Parser
   ↓
Risk Scoring Engine
   ↓
SQLite Database
   ↓
Adaptive Firewall Decision
   ↓
Flask Dashboard
```

## 🛠️ Technology Stack

| Component            | Technology            |
| -------------------- | --------------------- |
| Programming Language | Python                |
| Honeypot             | Cowrie                |
| Database             | SQLite                |
| Backend              | Flask                 |
| Frontend             | HTML, CSS, JavaScript |
| Operating System     | Kali Linux            |
| Version Control      | Git                   |

## 📂 Project Structure

```text
HoneyTrack/
│
├── app.py                    # Flask dashboard backend
├── parser.py                 # Parses Cowrie logs
├── risk_engine.py            # Calculates session risk
├── command_risk.py           # Evaluates command risk
├── database.py               # Database operations
├── models.py                 # Data models
├── firewall.py               # Adaptive firewall decisions
├── config.py                 # Project configuration
├── update_session_risk.py    # Updates session risk
├── requirements.txt          # Python dependencies
│
├── templates/
│   └── dashboard.html        # Dashboard interface
│
├── static/
│   └── css/
│       └── style.css         # Dashboard styling
│
└── database/
    └── honeytrack.db         # SQLite database
```

## ⚙️ Main Features

### 1. SSH Honeypot Monitoring

Cowrie acts as a fake SSH environment and captures login attempts and commands executed by connecting users.

### 2. Log Parsing

The parser reads Cowrie's JSON logs and extracts information such as:

* Source IP
* Username
* Password
* Timestamp
* Session ID
* Executed commands

### 3. Risk Scoring

HoneyTrack+ calculates a risk score based on multiple factors, including:

* Username risk
* Password risk
* Authentication result
* Brute-force attempts
* Network protocol
* Previous attack history
* Executed command risk

**Maximum Risk Score:** 100

### 4. Risk Levels

| Risk Level |    Score | Firewall Action         |
| ---------- | -------: | ----------------------- |
| LOW        | Below 30 | Monitor                 |
| MEDIUM     |    30–59 | Alert + Temporary Block |
| HIGH       |    60–79 | Alert + Temporary Block |
| CRITICAL   |   80–100 | Alert + Permanent Block |

### 5. Adaptive Firewall

Firewall decisions are generated based on the calculated risk score.

Currently, firewall actions are stored in SQLite. Future versions may integrate real firewall tools such as `iptables` or `ufw` in a controlled environment.

### 6. Monitoring Dashboard

The Flask dashboard displays:

* Total sessions
* Total commands
* High-risk sessions
* Blocked sessions
* Recent login attempts
* Attacker IP addresses
* Usernames
* Risk scores
* Risk levels
* Executed commands
* Firewall actions
* Firewall rules

## 🗄️ Database

HoneyTrack+ uses SQLite with three main tables:

### `sessions`

Stores SSH session information and calculated risk details.

### `commands`

Stores commands executed during each session.

### `firewall_rules`

Stores adaptive firewall decisions, including actions, reasons, statuses, and expiry information.

## 🚀 Setup and Usage

### Prerequisites

Make sure you have:

* Kali Linux
* Python 3
* Cowrie
* SQLite3
* Git

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/HoneyTrack.git
cd HoneyTrack
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a Virtual Environment (Optional)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Start Cowrie

Start Cowrie using your existing Cowrie setup.

Make sure the honeypot is listening on port **2222** and generating `cowrie.json`.

### 5. Run the Parser

Run the parser using the project's existing parser workflow:

```bash
python3 parser.py
```

> The exact parser execution method may depend on the current implementation.

### 6. Start the Flask Dashboard

```bash
python3 app.py
```

Open the dashboard at:

```text
http://127.0.0.1:5000
```

## 🧪 Example Demonstration

In a controlled lab environment, a test user can connect to the honeypot:

```bash
ssh root@<KALI-IP> -p 2222
```

Cowrie captures the login attempt and commands. HoneyTrack+ then processes the logs, calculates a risk score, stores the results, and displays them on the dashboard.

```text
SSH Attempt
    ↓
Cowrie Captures Activity
    ↓
Parser Processes Logs
    ↓
Risk Score Generated
    ↓
Firewall Action Selected
    ↓
Dashboard Updated
```

## 🔐 Security and Ethical Use

HoneyTrack+ should only be deployed in an authorised and controlled environment.

* Do not expose an unprotected honeypot to the public internet without proper isolation.
* Do not use real personal passwords in testing.
* Use test credentials and a dedicated lab environment.
* Do not execute real firewall changes without understanding their impact.
* Only monitor systems and users you have permission to monitor.

## 🔮 Future Enhancements

* Real-time dashboard auto-refresh.
* Automated parser execution.
* Integration with `iptables` or `ufw`.
* Email or notification alerts.
* Graphs for attack trends.
* IP reputation checking.
* Improved session correlation.
* Exportable security reports.

## 👩‍💻 Project Information

**Project:** HoneyTrack+
**Version:** 1.0
**Category:** Cybersecurity / Honeypot Monitoring / SOC Simulation

---

*Built for cybersecurity learning, research, and controlled security testing.*

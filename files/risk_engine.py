import math


# ============================================================
# 1. USERNAME RISK
# ============================================================

COMMON_USERS = {
    "root": 15,
    "admin": 12,
    "administrator": 12,
    "ubuntu": 8,
    "guest": 5
}


def username_risk(username):
    if not username:
        return 2

    return COMMON_USERS.get(username.lower(), 2)


# ============================================================
# 2. PASSWORD / CREDENTIAL RISK
# ============================================================

WEAK_PASSWORDS = {
    "root",
    "admin",
    "password",
    "123456",
    "12345678",
    "qwerty",
    "toor",
    "letmein",
    "welcome"
}


def password_risk(password):
    if not password:
        return 0

    password = password.lower()

    if password in WEAK_PASSWORDS:
        return 20

    if len(password) <= 5:
        return 15

    return 5


# ============================================================
# 3. AUTHENTICATION RISK
# ============================================================

def authentication_risk(eventid):
    if not eventid:
        return 0

    eventid = eventid.lower()

    if "success" in eventid:
        return 20

    if "failed" in eventid:
        return 10

    return 0


# ============================================================
# 4. BRUTE FORCE RISK
# ============================================================

def brute_force_risk(attempts):
    attempts = max(1, attempts)

    if attempts == 1:
        return 0

    if attempts <= 3:
        return 8

    if attempts <= 5:
        return 15

    if attempts <= 10:
        return 22

    return 30


# ============================================================
# 5. NETWORK / PROTOCOL RISK
# ============================================================

def network_risk(protocol):
    if not protocol:
        return 0

    protocol = protocol.lower()

    if protocol == "ssh":
        return 10

    if protocol == "telnet":
        return 15

    return 5


# ============================================================
# 6. ATTACKER HISTORY
# ============================================================

def history_risk(previous_attacks):
    previous_attacks = max(0, previous_attacks)

    return min(20, previous_attacks * 4)


# ============================================================
# 7. BEHAVIOURAL ESCALATION
# ============================================================

def behavioural_escalation(
        command_risk=0,
        suspicious_commands=0,
        command_categories=0):

    escalation = 0

    # High accumulated command risk
    if command_risk >= 50:
        escalation += 8

    elif command_risk >= 30:
        escalation += 5

    # Repeated suspicious activity
    if suspicious_commands >= 3:
        escalation += 8

    elif suspicious_commands >= 2:
        escalation += 4

    # Activity across multiple categories
    if command_categories >= 4:
        escalation += 10

    elif command_categories >= 2:
        escalation += 5

    return min(escalation, 20)


# ============================================================
# 8. COMMAND BEHAVIOUR
# ============================================================

def command_behavior_risk(command_risk):
    """
    Converts accumulated command risk into
    a behavioural contribution.
    """

    command_risk = max(0, command_risk)

    if command_risk >= 100:
        return 25

    if command_risk >= 70:
        return 20

    if command_risk >= 50:
        return 15

    if command_risk >= 30:
        return 10

    if command_risk > 0:
        return 5

    return 0


# ============================================================
# 9. FINAL RISK CALCULATION
# ============================================================

def calculate_risk(
        username,
        password,
        eventid,
        protocol,
        attempts=1,
        previous_attacks=0,
        command_risk=0,
        suspicious_commands=0,
        command_categories=0):

    # -------------------------------
    # Individual risk components
    # -------------------------------

    U = username_risk(username)

    P = password_risk(password)

    A = authentication_risk(eventid)

    B = brute_force_risk(attempts)

    N = network_risk(protocol)

    H = history_risk(previous_attacks)

    C = command_behavior_risk(command_risk)

    E = behavioural_escalation(
        command_risk,
        suspicious_commands,
        command_categories
    )

    # -------------------------------
    # Weighted total
    # -------------------------------

    raw_score = (
        U +
        P +
        A +
        B +
        N +
        H +
        C +
        E
    )

    score = min(100, raw_score)

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score < 30:

        level = "LOW"
        action = "Monitor"

    elif score < 60:

        level = "MEDIUM"
        action = "Alert + Block 30 min"

    elif score < 80:

        level = "HIGH"
        action = "Block 30 min"

    else:

        level = "CRITICAL"
        action = "Permanent Block"

    return score, level, action

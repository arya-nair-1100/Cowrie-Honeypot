import math

# Common usernames
COMMON_USERS = {
    "root": 15,
    "admin": 12,
    "administrator": 12,
    "ubuntu": 8,
    "guest": 5
}

# Weak passwords
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


def username_risk(username):
    if not username:
        return 2
    return COMMON_USERS.get(username.lower(), 2)


def password_risk(password):
    if not password:
        return 0

    if password.lower() in WEAK_PASSWORDS:
        return 20

    return 10


def authentication_risk(eventid):
    if not eventid:
        return 0

    if "success" in eventid:
        return 30

    elif "failed" in eventid:
        return 10

    return 0


def brute_force_risk(attempts):
    return min(25, round(5 * math.log2(attempts + 1)))


def network_risk(protocol):
    if protocol == "ssh":
        return 15

    if protocol == "telnet":
        return 20

    return 0


def history_risk(previous_attacks):
    return min(20, previous_attacks * 2)


def calculate_risk(
        username,
        password,
        eventid,
        protocol,
        attempts=1,
        previous_attacks=0):

    U = username_risk(username)
    P = password_risk(password)
    A = authentication_risk(eventid)
    B = brute_force_risk(attempts)
    N = network_risk(protocol)
    H = history_risk(previous_attacks)

    score = U + P + A + B + N + H

    score = min(score, 100)

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

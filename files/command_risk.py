
# ============================================================
# ADVANCED COMMAND RISK ENGINE
# ============================================================

COMMAND_SCORES = {

    # Basic reconnaissance
    "pwd": 1,
    "ls": 2,
    "whoami": 5,
    "id": 5,
    "who": 8,
    "w": 8,
    "last": 10,
    "uname": 5,
    "hostname": 5,

    # File / information discovery
    "cat": 10,
    "find": 10,
    "ps": 10,
    "grep": 8,
    "locate": 10,
    "env": 8,
    "printenv": 8,
    "history": 8,
    "strings": 15,

    # Network reconnaissance
    "netstat": 15,
    "ifconfig": 15,
    "ip": 15,
    "ss": 15,
    "route": 15,
    "arp": 15,
    "nmap": 35,

    # Network tools
    "nc": 35,
    "netcat": 35,
    "telnet": 25,

    # Remote access
    "ssh": 20,

    # Privilege escalation
    "sudo": 30,
    "su": 30,

    # Download / transfer
    "wget": 40,
    "curl": 40,
    "scp": 40,
    "ftp": 35,

    # Permission modification
    "chmod": 25,
    "chown": 25,

    # Destructive commands
    "rm": 35,
    "rm -rf": 50,
    "shred": 40,
    "mkfs": 45,
    "dd": 40,

    # Shell execution
    "bash": 25,
    "sh": 25,
    "python": 20,
    "python3": 20,
    "perl": 25,

    # Process / service manipulation
    "kill": 25,
    "pkill": 30,
    "systemctl": 25,

    # Package installation
    "apt": 20,
    "apt-get": 20,
    "yum": 20,
    "dnf": 20,

    # Persistence
    "crontab": 30,
    "nohup": 25,

    # Account manipulation
    "useradd": 35,
    "adduser": 35,

    # Credential manipulation
    "passwd": 30,
    "chpasswd": 35,

    # Security manipulation
    "iptables": 35,
    "ufw": 30,

    # System manipulation
    "mount": 20,
    "umount": 20
}


def get_command_score(command):

    if not command:
        return 0

    command = command.lower().strip()

    # Check longer commands first
    # so "rm -rf" gets 50 instead of "rm" getting 35
    sorted_commands = sorted(
        COMMAND_SCORES.keys(),
        key=len,
        reverse=True
    )

    for cmd in sorted_commands:

        if command == cmd or command.startswith(cmd + " "):
            return COMMAND_SCORES[cmd]

    return 0


# ============================================================
# COMMAND CATEGORY
# ============================================================

def get_command_category(command):

    if not command:
        return "unknown"

    command = command.lower().strip()

    def matches(commands):
        return any(
            command == cmd or command.startswith(cmd + " ")
            for cmd in commands
        )

    if matches([
        "whoami", "id", "pwd", "ls",
        "uname", "hostname", "who",
        "w", "last"
    ]):
        return "reconnaissance"

    if matches([
        "cat", "find", "ps", "grep",
        "locate", "env", "printenv",
        "history", "strings"
    ]):
        return "information_gathering"

    if matches([
        "netstat", "ifconfig", "ip",
        "ss", "route", "arp", "nmap"
    ]):
        return "network_recon"

    if matches([
        "nc", "netcat", "telnet"
    ]):
        return "network_tool"

    if matches(["ssh"]):
        return "remote_access"

    if matches(["sudo", "su"]):
        return "privilege_escalation"

    if matches([
        "wget", "curl", "scp", "ftp"
    ]):
        return "download"

    if matches(["chmod", "chown"]):
        return "permission_change"

    if matches([
        "rm", "shred", "mkfs", "dd"
    ]):
        return "destructive"

    if matches([
        "bash", "sh", "python",
        "python3", "perl"
    ]):
        return "execution"

    if matches([
        "kill", "pkill", "systemctl"
    ]):
        return "process_control"

    if matches([
        "apt", "apt-get", "yum", "dnf"
    ]):
        return "package_management"

    if matches(["crontab", "nohup"]):
        return "persistence"

    if matches(["useradd", "adduser"]):
        return "account_manipulation"

    if matches(["passwd", "chpasswd"]):
        return "credential_manipulation"

    if matches(["iptables", "ufw"]):
        return "security_manipulation"

    if matches(["mount", "umount"]):
        return "system_manipulation"

    return "normal"


# ============================================================
# SUSPICIOUS COMMAND DETECTION
# ============================================================

def is_suspicious(command):

    if not command:
        return False

    score = get_command_score(command)

    return score >= 10


# ============================================================
# COMMAND SEQUENCE ANALYSIS
# ============================================================

def sequence_risk(commands):

    if not commands:
        return 0

    categories = [
        get_command_category(command)
        for command in commands
    ]

    risk = 0

    # Network reconnaissance
    if (
        "network_recon" in categories
        and "reconnaissance" in categories
    ):
        risk += 8

    # Privilege escalation
    if "privilege_escalation" in categories:
        risk += 10

    # Download + execution
    if (
        "download" in categories
        and "execution" in categories
    ):
        risk += 15

    # Download + permission modification
    if (
        "download" in categories
        and "permission_change" in categories
    ):
        risk += 15

    # Download + destructive behaviour
    if (
        "download" in categories
        and "destructive" in categories
    ):
        risk += 15

    # Privilege escalation + destructive behaviour
    if (
        "privilege_escalation" in categories
        and "destructive" in categories
    ):
        risk += 20

    # Multiple suspicious categories
    suspicious_categories = set(categories) - {"normal"}

    if len(suspicious_categories) >= 4:
        risk += 15
    elif len(suspicious_categories) >= 3:
        risk += 10
    elif len(suspicious_categories) >= 2:
        risk += 5

    return min(risk, 30)


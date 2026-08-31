COMMAND_SCORES = {
    "pwd": 1,
    "ls": 2,
    "whoami": 5,
    "id": 5,
    "cat": 10,
    "find": 10,
    "ps": 10,
    "netstat": 15,
    "ifconfig": 15,
    "ip": 15,
    "sudo": 30,
    "su": 30,
    "wget": 40,
    "curl": 40,
    "scp": 40,
    "chmod": 25,
    "chown": 25,
    "rm": 35,
    "rm -rf": 50
}


def get_command_score(command):
    if not command:
        return 0

    command = command.lower()

    for cmd, score in COMMAND_SCORES.items():
        if command.startswith(cmd):
            return score

    return 0

import json
from database import insert_attack


LOG_FILE = "/home/arya/cowrie/var/log/cowrie/cowrie.json"


def calculate_risk(password):

    length = len(password)

    if length < 5:
        score = 20

    elif length < 8:
        score = 50

    else:
        score = 80

    if score >= 80:
        level = "HIGH"
        action = "Blocked Permanently"

    elif score >= 50:
        level = "MEDIUM"
        action = "Blocked for 30 Minutes + Alert"

    else:
        level = "LOW"
        action = "Monitoring"

    return score, level, action


def parse_logs():

    with open(LOG_FILE) as f:

        for line in f:

            try:

                data = json.loads(line)

                if data["eventid"] == "cowrie.login.failed":

                    score, level, action = calculate_risk(
                        data["password"]
                    )

                    insert_attack(
                        data["timestamp"],
                        data["src_ip"],
                        data["username"],
                        data["password"],
                        score,
                        level,
                        action
                    )

            except:
                pass


if __name__ == "__main__":
    parse_logs()

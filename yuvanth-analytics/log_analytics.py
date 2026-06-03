import re

def parse_line(line):

    failed_pattern = re.compile(
        r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    success_pattern = re.compile(
        r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    result = {
        "event_type": None,
        "username": None,
        "ip": None,
        "hour": None,
        "invalid_user": False
    }

    result["hour"] = line.split()[2].split(":")[0]

    failed = failed_pattern.search(line)

    if failed:
        result["event_type"] = "failed_login"
        result["username"] = failed.group(2)
        result["ip"] = failed.group(3)
        result["invalid_user"] = "invalid user" in line
        return result

    success = success_pattern.search(line)

    if success:
        result["event_type"] = "successful_login"
        result["username"] = success.group(1)
        result["ip"] = success.group(2)
        return result

    return result


event_counts = {
    "ssh_failures": 0,
    "root_attack_attempts": 0,
    "successful_logins": 0,
    "invalid_user_attempts": 0
}

with open("/var/log/auth.log", "r", errors="ignore") as logfile:

    for line in logfile:

        parsed = parse_line(line)

        if parsed["event_type"] == "failed_login":

            event_counts["ssh_failures"] += 1

            if parsed["username"] == "root":
                event_counts["root_attack_atempts"] += 1

            if parsed["invalid_user"]:
                event_counts["invalid_user_attempts"] += 1

        elif parsed["event_type"] == "successful_login":

            event_counts["successful_logins"] += 1


print("\n===== EVENT COUNTS =====")

print("SSH failures:",
      event_counts["ssh_failures"])

print("Root attack attempts:",
      event_counts["root_attack_attempts"])

print("Successful logins:",
      event_counts["successful_logins"])

print("Invalid user attempts:",
      event_counts["invalid_user_attempts"])

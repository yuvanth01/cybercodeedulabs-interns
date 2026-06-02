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
        "hour": None
    }

    result["hour"] = line.split()[2].split(":")[0]

    failed = failed_pattern.search(line)

    if failed:
        result["event_type"] = "failed_login"
        result["username"] = failed.group(2)
        result["ip"] = failed.group(3)
        return result

    success = success_pattern.search(line)

    if success:
        result["event_type"] = "successful_login"
        result["username"] = success.group(1)
        result["ip"] = success.group(2)
        return result

    return result

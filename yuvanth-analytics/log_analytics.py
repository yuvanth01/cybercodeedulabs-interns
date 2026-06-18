import re
import json
from collections import Counter, defaultdict


def parse_auth_line(line):

    result = {
        "event_type": None,
        "username": None,
        "ip": None,
        "hour": None,
        "invalid_user": False
    }

    parts = line.split()

    if len(parts) > 2 and ":" in parts[2]:
        result["hour"] = parts[2].split(":")[0]

    failed_pattern = re.search(
        r"Failed password for (invalid user )?(\S+) from (\S+)",
        line
    )

    if failed_pattern:
        result["event_type"] = "failed_login"
        result["username"] = failed_pattern.group(2)
        result["ip"] = failed_pattern.group(3)
        result["invalid_user"] = "invalid user" in line
        return result

    success_pattern = re.search(
        r"Accepted password for (\S+) from (\S+)",
        line
    )

    if success_pattern:
        result["event_type"] = "successful_login"
        result["username"] = success_pattern.group(1)
        result["ip"] = success_pattern.group(2)
        return result

    return result


def parse_syslog(line):

    if "UFW BLOCK" not in line:
        return None

    result = {
        "ip": None,
        "port": None
    }

    src = re.search(r"SRC=([0-9.]+)", line)
    dpt = re.search(r"DPT=(\d+)", line)

    if src:
        result["ip"] = src.group(1)

    if dpt:
        result["port"] = dpt.group(1)

    return result


def parse_nginx(line):

    pattern = re.search(
        r'"(?:GET|POST|PUT|DELETE|HEAD) ([^ ]+) [^"]+" (\d+)',
        line
    )

    if not pattern:
        return None

    return {
        "path": pattern.group(1),
        "status": pattern.group(2)
    }


event_counts = {
    "ssh_failures": 0,
    "root_attack_attempts": 0,
    "successful_logins": 0,
    "invalid_user_attempts": 0
}

attacking_ips = Counter()
targeted_usernames = Counter()
hourly_events = defaultdict(int)

ufw_blocks = 0
blocked_ports = Counter()
blocked_ips = Counter()

total_http_requests = 0
path_counter = Counter()
count_404 = 0
scanner_requests = 0

total_lines = 0


with open("/var/log/auth.log", "r", errors="ignore") as file:

    for line in file:

        total_lines += 1

        parsed = parse_auth_line(line)

        if parsed["hour"]:
            hourly_events[parsed["hour"]] += 1

        if parsed["event_type"] == "failed_login":

            event_counts["ssh_failures"] += 1

            if parsed["ip"]:
                attacking_ips[parsed["ip"]] += 1

            if parsed["username"]:
                targeted_usernames[parsed["username"]] += 1

            if parsed["username"] == "root":
                event_counts["root_attack_attempts"] += 1

            if parsed["invalid_user"]:
                event_counts["invalid_user_attempts"] += 1

        elif parsed["event_type"] == "successful_login":
            event_counts["successful_logins"] += 1


with open("/var/log/syslog", "r", errors="ignore") as file:

    for line in file:

        parsed = parse_syslog(line)

        if parsed:

            ufw_blocks += 1

            if parsed["port"]:
                blocked_ports[parsed["port"]] += 1

            if parsed["ip"]:
                blocked_ips[parsed["ip"]] += 1


try:
    with open("/var/log/nginx/access.log", "r", errors="ignore") as file:

        for line in file:

            total_http_requests += 1

            parsed = parse_nginx(line)

            if parsed:

                path_counter[parsed["path"]] += 1

                if parsed["status"] == "404":
                    count_404 += 1

            lower_line = line.lower()

            if (
                "nikto" in lower_line
                or "sqlmap" in lower_line
                or "nmap" in lower_line
            ):
                scanner_requests += 1

except FileNotFoundError:
    pass


attack_surface = {
    "auth_log_events": total_lines,
    "syslog_events": ufw_blocks,
    "nginx_events": total_http_requests
}

most_active_source = max(
    attack_surface,
    key=attack_surface.get
)


report = {
    "total_lines_processed": total_lines,
    "event_counts": event_counts,
    "top_5_attacking_ips": dict(attacking_ips.most_common(5)),
    "top_5_targeted_usernames": dict(targeted_usernames.most_common(5)),
    "events_by_hour": dict(sorted(hourly_events.items())),
    "syslog": {
        "ufw_blocks": ufw_blocks,
        "top_5_blocked_ports": dict(blocked_ports.most_common(5)),
        "top_5_blocked_ips": dict(blocked_ips.most_common(5))
    },
    "nginx": {
        "total_http_requests": total_http_requests,
        "top_5_requested_paths": dict(path_counter.most_common(5)),
        "404_responses": count_404,
        "scanner_user_agents": scanner_requests
    },
    "attack_surface": {
        "event_counts": attack_surface,
        "most_active_source": most_active_source
    }
}


with open("report.json", "w") as f:
    json.dump(report, f, indent=4)


print("\n========== AUTH LOG ANALYTICS ==========")
print(f"Total Lines Processed: {total_lines}")

print("\nEvent Counts:")
for key, value in event_counts.items():
    print(f"  {key}: {value}")

print("\nTop 5 Attacking IPs:")
if attacking_ips:
    for ip, count in attacking_ips.most_common(5):
        print(f"  {ip} -> {count}")
else:
    print("  None")

print("\nTop 5 Targeted Usernames:")
if targeted_usernames:
    for user, count in targeted_usernames.most_common(5):
        print(f"  {user} -> {count}")
else:
    print("  None")

print("\nEvents By Hour:")
for hour in sorted(hourly_events):
    print(f"  {hour}:00 -> {hourly_events[hour]}")


print("\n========== SYSLOG ANALYTICS ==========")
print(f"UFW Block Events: {ufw_blocks}")

print("\nTop 5 Blocked Ports:")
if blocked_ports:
    for port, count in blocked_ports.most_common(5):
        print(f"  Port {port} -> {count}")
else:
    print("  None")

print("\nTop 5 Blocked IPs:")
if blocked_ips:
    for ip, count in blocked_ips.most_common(5):
        print(f"  {ip} -> {count}")
else:
    print("  None")


print("\n========== NGINX ANALYTICS ==========")
print(f"Total HTTP Requests: {total_http_requests}")
print(f"404 Responses: {count_404}")
print(f"Scanner User Agent Requests: {scanner_requests}")

print("\nTop 5 Requested Paths:")
if path_counter:
    for path, count in path_counter.most_common(5):
        print(f"  {path} -> {count}")
else:
    print("  None")


print("\n========== ATTACK SURFACE ==========")
print(f"Most Active Source: {most_active_source}")

print("\nReport saved as report.json")

print("\n===== AUTH LOG SUMMARY =====")

print("+---------------------------+-------+")
print("| Metric                    | Value |")
print("+---------------------------+-------+")

for key, value in event_counts.items():
    print(f"| {key:<25} | {value:<5} |")

print("+---------------------------+-------+")

print("\n===== TOP ATTACKING IPS =====")

print("+-------------------+-------+")
print("| IP Address        | Count |")
print("+-------------------+-------+")

for ip, count in attacking_ips.most_common(5):
    print(f"| {ip:<17} | {count:<5} |")

print("+-------------------+-------+")

print("\n===== NGINX ANALYTICS =====")

print("+---------------------------+-------+")
print("| Metric                    | Value |")
print("+---------------------------+-------+")

print(f"| Total HTTP Requests       | {total_http_requests:<5} |")
print(f"| 404 Responses             | {count_404:<5} |")
print(f"| Scanner User Agents       | {scanner_requests:<5} |")

print("+---------------------------+-------+")


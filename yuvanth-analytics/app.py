from flask import Flask, jsonify, request
from flask_cors import CORS
from collections import Counter, defaultdict
from datetime import datetime
import re

app = Flask(__name__)
CORS(app)

AUTH_LOG = "/var/log/auth.log"
SYSLOG = "/var/log/syslog"

events = []
attacker_stats = Counter()
attack_types = defaultdict(set)


def load_logs():

    global events
    events = []

    try:
        with open(AUTH_LOG, "r", errors="ignore") as file:

            for line in file:

                if "Failed password" in line:

                    ip_match = re.search(r"from ([0-9.]+)", line)
                    user_match = re.search(r"for (invalid user )?(\\S+)", line)

                    ip = ip_match.group(1) if ip_match else "unknown"
                    username = user_match.group(2) if user_match else "unknown"

                    event = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "type": "ssh_failure",
                        "src_ip": ip,
                        "username": username,
                        "severity": "MEDIUM"
                    }

                    events.append(event)

                    attacker_stats[ip] += 1
                    attack_types[ip].add("ssh_failure")

                if "Accepted password" in line:

                    ip_match = re.search(r"from ([0-9.]+)", line)

                    ip = ip_match.group(1) if ip_match else "unknown"

                    event = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "type": "successful_login",
                        "src_ip": ip,
                        "severity": "LOW"
                    }

                    events.append(event)

    except:
        pass

    try:
        with open(SYSLOG, "r", errors="ignore") as file:

            for line in file:

                if "UFW BLOCK" in line:

                    ip_match = re.search(r"SRC=([0-9.]+)", line)

                    ip = ip_match.group(1) if ip_match else "unknown"

                    event = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "type": "port_scan",
                        "src_ip": ip,
                        "severity": "HIGH"
                    }

                    events.append(event)

                    attacker_stats[ip] += 1
                    attack_types[ip].add("port_scan")

    except:
        pass


@app.route("/api/stats")
def stats():

    load_logs()

    ssh_failures = len([e for e in events if e["type"] == "ssh_failure"])

    root_attacks = len([
        e for e in events
        if e.get("username") == "root"
    ])

    port_scans = len([
        e for e in events
        if e["type"] == "port_scan"
    ])

    brute_force = 0

    for ip, count in attacker_stats.items():
        if count > 10:
            brute_force += 1

    top_attacker = (
        attacker_stats.most_common(1)[0][0]
        if attacker_stats
        else "none"
    )

    return jsonify({
        "total_events": len(events),
        "ssh_failures": ssh_failures,
        "root_attacks": root_attacks,
        "brute_force": brute_force,
        "port_scans": port_scans,
        "top_attacker": top_attacker,
        "last_updated": datetime.utcnow().isoformat() + "Z"
    })


@app.route("/api/events")
def get_events():

    load_logs()

    limit = int(request.args.get("limit", 50))
    event_type = request.args.get("type")

    filtered = events

    if event_type:
        filtered = [
            e for e in events
            if e["type"] == event_type
        ]

    return jsonify(filtered[:limit])


@app.route("/api/attackers")
def attackers():

    load_logs()

    data = []

    for ip, count in attacker_stats.items():

        data.append({
            "ip": ip,
            "total_attacks": count,
            "types": list(attack_types[ip])
        })

    return jsonify(data)


@app.route("/api/timeline")
def timeline():

    load_logs()

    hourly = defaultdict(int)

    for event in events:

        hour = datetime.utcnow().strftime("%H:00")
        hourly[hour] += 1

    result = []

    for hour, count in sorted(hourly.items()):

        result.append({
            "hour": hour,
            "count": count
        })

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

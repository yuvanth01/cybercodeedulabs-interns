from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import subprocess
import json

app = Flask(__name__)
CORS(app)

@app.route("/")
def dashboard():
    return render_template("analytics.html")


def get_report():

    subprocess.run(
        ["python3", "log_analytics.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    with open("report.json", "r") as file:
        return json.load(file)


@app.route("/report")
def report():

    data = get_report()
    return jsonify(data)


@app.route("/report/auth")
def auth_report():

    data = get_report()

    return jsonify({
        "total_lines_processed": data["total_lines_processed"],
        "event_counts": data["event_counts"],
        "top_5_attacking_ips": data["top_5_attacking_ips"],
        "top_5_targeted_usernames": data["top_5_targeted_usernames"],
        "events_by_hour": data["events_by_hour"]
    })


@app.route("/report/firewall")
def firewall_report():

    data = get_report()
    return jsonify(data["syslog"])


@app.route("/report/web")
def web_report():

    data = get_report()
    return jsonify(data["nginx"])


@app.route("/top-attackers")
def top_attackers():

    report = get_report()

    attackers = []

    for ip, count in report["top_5_attacking_ips"].items():
        attackers.append({
            "ip": ip,
            "total_attacks": count
        })

    return jsonify(attackers)


@app.route("/timeline")
def timeline():

    report = get_report()

    events = []

    for hour, count in report["events_by_hour"].items():
        events.append({
            "hour": hour,
            "count": count
        })

    return jsonify(events)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

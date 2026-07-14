from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json

app = Flask(__name__)
CORS(app)


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

    data = get_report()
    return jsonify(data["top_5_attacking_ips"])


@app.route("/timeline")
def timeline():

    data = get_report()

    hours = request.args.get("hours")

    if hours:
        hours = int(hours)

        events = list(data["events_by_hour"].items())[-hours:]

        return jsonify(dict(events))

    return jsonify(data["events_by_hour"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

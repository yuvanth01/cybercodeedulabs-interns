from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "events.db")


# ─────────────────────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row

    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)

    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()

        db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL
                    DEFAULT (datetime('now')),

                source_ip TEXT,
                dest_ip TEXT,

                attack_type TEXT NOT NULL,

                severity TEXT NOT NULL
                    CHECK(severity IN (
                        'LOW',
                        'MEDIUM',
                        'HIGH',
                        'CRITICAL'
                    )),

                mitre_tactic TEXT,
                mitre_technique TEXT,

                description TEXT,
                raw_log TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_attack_type
                ON events(attack_type);

            CREATE INDEX IF NOT EXISTS idx_severity
                ON events(severity);

            CREATE INDEX IF NOT EXISTS idx_timestamp
                ON events(timestamp);
        """)

        db.commit()


# ─────────────────────────────────────────────────────────────
# HOME
# ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "CyberCode Module 3 — Event Storage API",
        "version": "1.0.0",
        "status": "running",

        "endpoints": {
            "POST /events":
                "Insert one or more enriched events",

            "GET /events":
                "List events with filtering and pagination",

            "GET /events/<id>":
                "Get one event",

            "GET /events/stats":
                "Get event statistics",

            "DELETE /events/<id>":
                "Delete an event"
        }
    })


# ─────────────────────────────────────────────────────────────
# POST /events
# ─────────────────────────────────────────────────────────────

@app.route("/events", methods=["POST"])
def ingest_events():

    payload = request.get_json(silent=True)

    if payload is None:
        return jsonify({
            "error": "Request body must be valid JSON"
        }), 400

    # Accept either:
    #
    # {
    #   "attack_type": "...",
    #   "severity": "HIGH"
    # }
    #
    # OR:
    #
    # [
    #   {...},
    #   {...}
    # ]

    events = payload if isinstance(payload, list) else [payload]

    valid_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    inserted_ids = []
    errors = []

    db = get_db()

    for index, event in enumerate(events):

        if not isinstance(event, dict):
            errors.append({
                "index": index,
                "error": "Each event must be a JSON object"
            })
            continue

        # Validate attack_type
        attack_type = event.get("attack_type")

        if not attack_type:
            errors.append({
                "index": index,
                "error": "attack_type is required"
            })
            continue

        # Validate severity
        severity = str(
            event.get("severity", "")
        ).upper()

        if severity not in valid_severities:
            errors.append({
                "index": index,
                "error": (
                    "severity must be one of "
                    "LOW, MEDIUM, HIGH, CRITICAL"
                )
            })
            continue

        # Timestamp
        timestamp = (
            event.get("timestamp")
            or datetime.utcnow().isoformat()
        )

        # Insert event
        cursor = db.execute(
            """
            INSERT INTO events (
                timestamp,
                source_ip,
                dest_ip,
                attack_type,
                severity,
                mitre_tactic,
                mitre_technique,
                description,
                raw_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event.get("source_ip"),
                event.get("dest_ip"),
                attack_type,
                severity,
                event.get("mitre_tactic"),
                event.get("mitre_technique"),
                event.get("description"),
                event.get("raw_log")
            )
        )

        inserted_ids.append(cursor.lastrowid)

    db.commit()

    response = {
        "inserted": len(inserted_ids),
        "ids": inserted_ids
    }

    if errors:
        response["errors"] = errors

    if errors and inserted_ids:
        status_code = 207

    elif errors:
        status_code = 400

    else:
        status_code = 201

    return jsonify(response), status_code


# ─────────────────────────────────────────────────────────────
# GET /events
# ─────────────────────────────────────────────────────────────

@app.route("/events", methods=["GET"])
def list_events():

    attack_type = request.args.get("attack_type")

    severity_raw = request.args.get("severity")

    # Limit
    try:
        limit = int(
            request.args.get("limit", 50)
        )
    except ValueError:
        return jsonify({
            "error": "limit must be an integer"
        }), 400

    # Offset
    try:
        offset = int(
            request.args.get("offset", 0)
        )
    except ValueError:
        return jsonify({
            "error": "offset must be an integer"
        }), 400

    # Protect API from excessively large requests
    limit = min(max(limit, 1), 500)

    offset = max(offset, 0)

    # Sort order
    order_param = request.args.get(
        "order",
        "desc"
    ).lower()

    if order_param == "asc":
        order = "ASC"
    else:
        order = "DESC"

    # Base query
    query = """
        SELECT *
        FROM events
        WHERE 1 = 1
    """

    params = []

    # Filter attack type
    if attack_type:
        query += """
            AND LOWER(attack_type) LIKE ?
        """

        params.append(
            f"%{attack_type.lower()}%"
        )

    # Filter severity
    severities = []

    if severity_raw:

        severities = [
            s.strip().upper()
            for s in severity_raw.split(",")
            if s.strip()
        ]

        valid_severities = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        }

        invalid = [
            s for s in severities
            if s not in valid_severities
        ]

        if invalid:
            return jsonify({
                "error": "Invalid severity",
                "invalid": invalid
            }), 400

        placeholders = ",".join(
            ["?"] * len(severities)
        )

        query += f"""
            AND severity IN ({placeholders})
        """

        params.extend(severities)

    # Order + pagination
    query += f"""
        ORDER BY timestamp {order}
        LIMIT ?
        OFFSET ?
    """

    query_params = params + [
        limit,
        offset
    ]

    db = get_db()

    rows = db.execute(
        query,
        query_params
    ).fetchall()

    # Count query
    count_query = """
        SELECT COUNT(*)
        FROM events
        WHERE 1 = 1
    """

    count_params = []

    if attack_type:
        count_query += """
            AND LOWER(attack_type) LIKE ?
        """

        count_params.append(
            f"%{attack_type.lower()}%"
        )

    if severities:
        placeholders = ",".join(
            ["?"] * len(severities)
        )

        count_query += f"""
            AND severity IN ({placeholders})
        """

        count_params.extend(severities)

    count_row = db.execute(
        count_query,
        count_params
    ).fetchone()

    return jsonify({
        "total": count_row[0],
        "limit": limit,
        "offset": offset,
        "events": [
            dict(row)
            for row in rows
        ]
    })


# ─────────────────────────────────────────────────────────────
# GET /events/stats
# ─────────────────────────────────────────────────────────────

@app.route("/events/stats", methods=["GET"])
def event_stats():

    db = get_db()

    # Total events
    total_events = db.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    ).fetchone()[0]

    # Events by attack type
    by_type = db.execute(
        """
        SELECT
            attack_type,
            COUNT(*) AS count
        FROM events
        GROUP BY attack_type
        ORDER BY count DESC
        """
    ).fetchall()

    # Events by severity
    by_severity = db.execute(
        """
        SELECT
            severity,
            COUNT(*) AS count
        FROM events
        GROUP BY severity
        ORDER BY count DESC
        """
    ).fetchall()

    # Events by MITRE tactic
    by_tactic = db.execute(
        """
        SELECT
            mitre_tactic,
            COUNT(*) AS count
        FROM events
        WHERE mitre_tactic IS NOT NULL
        GROUP BY mitre_tactic
        ORDER BY count DESC
        """
    ).fetchall()

    return jsonify({
        "total_events": total_events,

        "by_attack_type": [
            dict(row)
            for row in by_type
        ],

        "by_severity": [
            dict(row)
            for row in by_severity
        ],

        "by_mitre_tactic": [
            dict(row)
            for row in by_tactic
        ]
    })


# ─────────────────────────────────────────────────────────────
# GET /events/<id>
# ─────────────────────────────────────────────────────────────

@app.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id):

    db = get_db()

    row = db.execute(
        """
        SELECT *
        FROM events
        WHERE id = ?
        """,
        (event_id,)
    ).fetchone()

    if row is None:
        return jsonify({
            "error": f"Event {event_id} not found"
        }), 404

    return jsonify(dict(row))


# ─────────────────────────────────────────────────────────────
# DELETE /events/<id>
# ─────────────────────────────────────────────────────────────

@app.route("/events/<int:event_id>", methods=["DELETE"])
def delete_event(event_id):

    db = get_db()

    cursor = db.execute(
        """
        DELETE FROM events
        WHERE id = ?
        """,
        (event_id,)
    )

    db.commit()

    if cursor.rowcount == 0:
        return jsonify({
            "error": f"Event {event_id} not found"
        }), 404

    return jsonify({
        "deleted": event_id
    })


# ─────────────────────────────────────────────────────────────
# START APPLICATION
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    init_db()

    print("========================================")
    print(" CyberCode Module 3 Event API")
    print("========================================")
    print(f"Database: {DB_PATH}")
    print("Server: http://0.0.0.0:5000")
    print("========================================")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

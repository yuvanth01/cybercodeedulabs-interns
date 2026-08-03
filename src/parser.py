"""
parser.py

Loads and validates incident JSON files.
"""

import json
import os


# ---------------- LOAD INCIDENT ---------------- #

def load_incident(file_path):
    """
    Loads an incident JSON file.

    Args:
        file_path (str): Path to JSON file.

    Returns:
        dict: Incident data.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    with open(file_path, "r") as file:
        incident = json.load(file)

    return incident


# ---------------- REQUIRED FIELDS ---------------- #

REQUIRED_FIELDS = [
    "incident_id",
    "title",
    "severity",
    "timestamp",
    "source_ip",
    "destination_ip",
    "affected_host",
    "attack_type",
    "status",
    "evidence"
]


# ---------------- VALIDATE INCIDENT ---------------- #

def validate_incident(incident):
    """
    Validates the incident JSON structure.

    Args:
        incident (dict)

    Returns:
        True if valid.

    Raises:
        ValueError if required fields are missing.
    """

    missing_fields = []

    for field in REQUIRED_FIELDS:

        if field not in incident:

            missing_fields.append(field)

    if missing_fields:

        raise ValueError(
            "Missing required fields: "
            + ", ".join(missing_fields)
        )

    if not isinstance(incident["evidence"], list):

        raise ValueError(
            "'evidence' must be a list."
        )

    return True


# ---------------- PRINT INCIDENT ---------------- #

def print_incident_summary(incident):
    """
    Prints a simple incident summary.
    Useful for terminal testing.
    """

    print("=" * 50)
    print("INCIDENT SUMMARY")
    print("=" * 50)

    print(f"Incident ID      : {incident['incident_id']}")
    print(f"Title            : {incident['title']}")
    print(f"Severity         : {incident['severity']}")
    print(f"Attack Type      : {incident['attack_type']}")
    print(f"Status           : {incident['status']}")
    print(f"Source IP        : {incident['source_ip']}")
    print(f"Destination IP   : {incident['destination_ip']}")
    print(f"Affected Host    : {incident['affected_host']}")
    print(f"Timestamp        : {incident['timestamp']}")

    print("\nEvidence:")

    for item in incident["evidence"]:
        print(f"  • {item}")

    print("=" * 50)
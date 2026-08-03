"""
utils.py

Helper functions for the AI Incident Report Generator.
"""

# ---------------- MITRE ATT&CK Mapping ---------------- #

MITRE_MAPPING = {
    "SSH Brute Force": (
        "Credential Access",
        "T1110 - Brute Force"
    ),

    "SQL Injection": (
        "Initial Access",
        "T1190 - Exploit Public-Facing Application"
    ),

    "Phishing": (
        "Initial Access",
        "T1566 - Phishing"
    ),

    "Ransomware": (
        "Impact",
        "T1486 - Data Encrypted for Impact"
    ),

    "Port Scan": (
        "Reconnaissance",
        "T1595 - Active Scanning"
    ),

    "HTTP Probe": (
        "Reconnaissance",
        "T1595 - Active Scanning"
    ),

    "Privilege Escalation": (
        "Privilege Escalation",
        "T1068 - Exploitation for Privilege Escalation"
    ),

    "Lateral Movement": (
        "Lateral Movement",
        "T1021 - Remote Services"
    ),

    "Data Exfiltration": (
        "Exfiltration",
        "T1041 - Exfiltration Over C2 Channel"
    ),

    "DNS Tunnel": (
        "Command and Control",
        "T1071.004 - DNS"
    ),

    "Malware": (
        "Execution",
        "T1204 - User Execution"
    ),

    "Unknown": (
        "Unknown",
        "Unknown"
    )
}


# ---------------- GET MITRE MAPPING ---------------- #

def get_mitre_mapping(attack_type):
    """
    Returns MITRE ATT&CK tactic and technique.
    """

    return MITRE_MAPPING.get(
        attack_type,
        ("Unknown", "Unknown")
    )


# ---------------- THREAT SCORE ---------------- #

def calculate_threat_score(incident):
    """
    Calculates a threat score out of 100.
    """

    score = 0

    severity = incident.get("severity", "").lower()

    if severity == "critical":
        score += 50

    elif severity == "high":
        score += 40

    elif severity == "medium":
        score += 25

    else:
        score += 10

    evidence = incident.get("evidence", [])

    score += min(len(evidence) * 10, 30)

    status = incident.get("status", "").lower()

    if status == "resolved":
        score -= 10

    elif status == "ongoing":
        score += 20

    score = max(0, min(score, 100))

    return score


# ---------------- INCIDENT STATISTICS ---------------- #

def incident_statistics(incident):
    """
    Returns useful statistics.
    """

    return {

        "Evidence Count": len(
            incident.get("evidence", [])
        ),

        "Attack Type": incident.get(
            "attack_type",
            "Unknown"
        ),

        "Severity": incident.get(
            "severity",
            "Unknown"
        ),

        "Threat Score": calculate_threat_score(
            incident
        )

    }


# ---------------- SEVERITY COLOR ---------------- #

def severity_color(severity):
    """
    Returns a color based on severity.
    """

    severity = severity.lower()

    if severity == "critical":
        return "red"

    elif severity == "high":
        return "orange"

    elif severity == "medium":
        return "gold"

    else:
        return "green"
import re

MITRE_MAPPING = {

    "SSH_FAILURE": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "kill_chain": "Credential Access"
    },

    "ROOT_ATTACK": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "kill_chain": "Exploitation"
    },

    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique": "Password Guessing",
        "kill_chain": "Credential Access"
    },

    "PORT_SCAN": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "kill_chain": "Reconnaissance"
    },

    "UFW_BLOCK": {
        "tactic": "Defense Evasion",
        "technique_id": "T1562",
        "technique": "Impair Defenses",
        "kill_chain": "Weaponization"
    },

    "FIREWALL_BLOCK": {
        "tactic": "Defense Evasion",
        "technique_id": "T1562.004",
        "technique": "Disable or Modify Firewall",
        "kill_chain": "Defense Evasion"
    },

    "HTTP_PROBE": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
        "kill_chain": "Reconnaissance"
    },

    "SQL_INJECTION": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "kill_chain": "Exploitation"
    },

    "DDOS": {
        "tactic": "Impact",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "kill_chain": "Actions on Objectives"
    },

    "LATERAL_MOVEMENT": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "technique": "Remote Services",
        "kill_chain": "Installation"
    },

    "PHISHING": {
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique": "Phishing",
        "kill_chain": "Delivery"
    },

    "MALWARE": {
        "tactic": "Execution",
        "technique_id": "T1204",
        "technique": "User Execution",
        "kill_chain": "Execution"
    }
}

INPUT_FILE = "module1_output.txt"

with open(INPUT_FILE, "r", errors="ignore") as file:

    for line in file:

        line = line.strip()

        if not line:
            continue

        if "SUMMARY" in line:
            continue

        if "PORTS =" in line:
            continue

        if "Top 3" in line:
            continue

        if "Highest severity" in line:
            continue

        if "Recommendation" in line:
            continue

        match = re.search(r"] ([A-Z_]+) \|", line)

        if not match:
            continue

        event_type = match.group(1)

        mapping = MITRE_MAPPING.get(event_type)

        if not mapping:
            continue

        print("\n========================================")
        print("ORIGINAL EVENT")
        print(line)

        print("\nMITRE ENRICHED EVENT")

        print(f"Tactic          : {mapping['tactic']}")
        print(f"Technique ID    : {mapping['technique_id']}")
        print(f"Technique Name  : {mapping['technique']}")
        print(f"Kill Chain      : {mapping['kill_chain']}")

        print("========================================")


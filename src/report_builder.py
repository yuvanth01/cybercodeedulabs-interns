def generate_report(incident):
    report = f"""
===============================
 CYBERSECURITY INCIDENT REPORT
===============================

Incident ID: {incident['incident_id']}
Title: {incident['title']}
Severity: {incident['severity']}
Attack Type: {incident['attack_type']}
Status: {incident['status']}

--------------------------------
Executive Summary
--------------------------------
A {incident['severity']} severity {incident['attack_type']} attack was detected on the system {incident['affected_host']}.

--------------------------------
Evidence
--------------------------------
"""

    for item in incident["evidence"]:
        report += f"- {item}\n"

    report += f"""

--------------------------------
Recommendations
--------------------------------
- Enable Multi-Factor Authentication (MFA)
- Disable Root Login
- Monitor SSH Login Attempts
- Block Malicious IP Addresses

--------------------------------
Conclusion
--------------------------------
The incident has been resolved successfully. Continuous monitoring and stronger security controls are recommended.
"""

    return report
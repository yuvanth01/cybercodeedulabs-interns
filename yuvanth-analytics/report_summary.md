# Log Analytics Report Summary

## Overview

This project analyzes authentication logs, firewall logs, and web server logs to identify suspicious activity, attack attempts, and security events.

## Auth Log Metrics

| Metric | Value |
|----------|----------|
| Total Lines Processed | 215 |
| SSH Failures | 64 |
| Root Attack Attempts | 12 |
| Successful Logins | 0 |
| Invalid User Attempts | 0 |

## Top 5 Attacking IPs

| IP Address | Count |
|------------|-------|
| 185.220.101.47 | 64 |

## Top 5 Targeted Usernames

| Username | Count |
|----------|-------|
| root | 12 |
| admin | 4 |
| deploy | 4 |
| ubuntu | 4 |
| test | 4 |

## Syslog Metrics

| Metric | Value |
|----------|----------|
| UFW Block Events | 64 |

## Top 5 Blocked Ports

| Port | Count |
|------|-------|
| 21 (FTP) | 4 |
| 23 (Telnet) | 4 |
| 25 (SMTP) | 4 |
| 3306 (MySQL) | 4 |
| 5432 (PostgreSQL) | 4 |

## Top 5 Blocked IPs

| IP Address | Count |
|------------|-------|
| 185.220.101.47 | 64 |

## Nginx Metrics

| Metric | Value |
|----------|----------|
| Total HTTP Requests | 24 |
| 404 Responses | 24 |
| Scanner User Agents | 24 |

## Top 5 Requested Paths

| Path | Count |
|------|-------|
| /admin | 4 |
| /.env | 4 |
| /phpmyadmin | 4 |
| /.git/config | 4 |
| /wp-login.php | 4 |

## Attack Surface Analysis

| Source | Event Count |
|---------|------------|
| Auth Log | 215 |
| Syslog | 64 |
| Nginx Access Log | 24 |

**Most Active Source:** Auth Log (215 Events)

## Findings

- A total of 64 SSH login failures were detected from the IP address 185.220.101.47.
- The username "root" was the most targeted account with 12 attack attempts.
- Firewall logs recorded 64 blocked connections targeting common service ports such as FTP, Telnet, MySQL, and PostgreSQL.
- Web server logs showed 24 suspicious requests targeting sensitive paths such as `/admin`, `/.env`, `/.git/config`, and `/wp-login.php`.
- All web requests resulted in 404 responses and matched known scanner behavior.

## Lesson learned

- Learned how to parse Linux authentication, firewall, and web server logs using Python and regular expressions.
- Learned to identify brute-force attacks, port scanning activity, and web reconnaissance attempts.
- Learned how to generate structured JSON reports and Markdown summaries for security monitoring and incident analysis.

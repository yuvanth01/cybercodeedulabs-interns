# TABLE: security_events

| Column Name      | Data Type    | Example Value               | Why this column is needed        |
| ---------------- | ------------ | --------------------------- | -------------------------------- |
| event_id         | INTEGER      | 1001                        | Unique identifier for each event |
| timestamp        | DATETIME     | 2026-06-18 19:27:30         | Stores when the event occurred   |
| event_type       | VARCHAR(50)  | heartbeat                   | Type of security event           |
| severity         | VARCHAR(20)  | LOW                         | Indicates severity level         |
| source_ip        | VARCHAR(45)  | 10.103.1.204                | Source IP generating event       |
| attacker_ip      | VARCHAR(45)  | 185.220.101.47              | Suspicious or attacker IP        |
| hostname         | VARCHAR(100) | c3-gyuvanth-885464          | Host/agent generating logs       |
| attack_type      | VARCHAR(50)  | Port Scan                   | Category of attack               |
| protocol         | VARCHAR(20)  | TCP                         | Network protocol used            |
| destination_port | INTEGER      | 22                          | Targeted network port            |
| action_taken     | VARCHAR(50)  | Blocked                     | Security action performed        |
| status           | VARCHAR(20)  | Active                      | Current event status             |
| location         | VARCHAR(100) | Fremont, United States      | Geo-location of source IP        |
| monitored_agent  | VARCHAR(100) | HYD SERVER                  | System being monitored           |
| log_source       | VARCHAR(50)  | SIEM                        | Source of security log           |
| event_message    | TEXT         | C3 Agent heartbeat detected | Detailed event description       |


# FILTERS AVAILABLE



| Filter Name               | Used For                                 |

| ------------------------- | ---------------------------------------- |

| Severity Filter           | LOW / MEDIUM / HIGH alerts               |

| Event Type Filter         | heartbeat, brute force, firewall block   |

| IP Search Filter          | Search attacker or source IP             |

| Time Range Filter         | Last 24 hours / real-time logs           |

| Attack Type Filter        | Port scan, HTTP probe, brute force       |

| Device Filter             | Firewall, server, database events        |

| Status Filter             | Active, blocked, resolved events         |

| Hostname Filter           | Logs from specific monitored agents      |

| SOC Filter                | View SOC-related monitoring events       |

| SIEM Filter               | Filter SIEM-generated logs               |

| Firewall Filter           | Show firewall alerts and blocked traffic |

| Phishing Filter           | Display phishing-related incidents  for practice     | 

| Forensics Filter          | Filter forensic investigation logs       |

| Vulnerability Scan Filter | Show vulnerability scan results          |

| Incident Filter           | This tab tracks which stage the current attack has reached based on the events detected. | 

| Packet Replay Filter      | This tab shows every attack event as a packet |

| Learn Filter              | learn About attack type , kill chain , MITRE ATT&CK  | 




# TABLE: events_per_hour_summary

| Column Name    | Data Type   | Example Value       | Why this column is needed     |
| -------------- | ----------- | ------------------- | ----------------------------- |
| summary_id     | INTEGER     | 1                   | Unique identifier for summary |
| hour_timestamp | DATETIME    | 2026-06-18 19:00:00 | Hour being summarized         |
| attack_type    | VARCHAR(50) | Port Scan           | Type of attack                |
| total_events   | INTEGER     | 65                  | Number of events in that hour |
| severity       | VARCHAR(20) | HIGH                | Severity of grouped events    |
| blocked_count  | INTEGER     | 20                  | Number of blocked attacks     |
| source_count   | INTEGER     | 12                  | Unique source IP count        |





# TABLE: source_ip_stats

| Column Name    | Data Type    | Example Value       | Why this column is needed       |
| -------------- | ------------ | ------------------- | ------------------------------- |
| ip_id          | INTEGER      | 101                 | Unique identifier for IP record |
| source_ip      | VARCHAR(45)  | 185.220.101.47      | Attacker/source IP              |
| total_attempts | INTEGER      | 218                 | Total attempts from IP          |
| first_seen     | DATETIME     | 2026-06-18 18:10:00 | First detected activity         |
| last_seen      | DATETIME     | 2026-06-18 19:27:30 | Latest detected activity        |
| attack_type    | VARCHAR(50)  | Brute Force         | Attack associated with IP       |
| severity       | VARCHAR(20)  | HIGH                | Severity triggered              |
| country        | VARCHAR(100) | United States       | Geo-location of IP              |
| status         | VARCHAR(20)  | Blocked             | Security response status        |
| blocked_count  | INTEGER      | 15                  | Number of blocked attempts      |




# Python Pseudocode Based on Security CSV Logs

## Reading Events from CSV File

1. Open the CSV security log file
2. Read the column headers:

   * Time
   * Event Type
   * Severity
   * Source IP
   * Destination Port
   * Service
   * Raw Log
3. Read each row one by one
4. Extract values from every row
5. Store event data into `security_events` table
6. Continue until all rows are processed
7. Close the CSV file

---

## Counting Events Per Attack Type

1. Create an empty counter/dictionary
2. Read every event from the CSV file
3. Check the `Event Type` column
4. Increase count for that attack type
5. Repeat for all rows
6. Display total counts

Expected Results from CSV:

* port_scan → many events
* firewall_block → many events
* brute_force → multiple events
* http_probe → multiple events
* root_attack → multiple events
* ssh_failure → multiple events
* process_anomaly → multiple events

---

## Finding Top 10 Most Active Source IPs

1. Create an empty counter for source IP addresses
2. Read all events from CSV file
3. Check the `Source IP` column
4. Count how many times each IP appears
5. Ignore empty IP values
6. Sort IPs from highest to lowest activity
7. Select top 10 IP addresses
8. Display:

   * IP address
   * total attempts

Expected Result:

* 185.220.101.47 → highest activity

---

## Detecting Port Scanning Activity

1. Read all events from dataset
2. Check for `port_scan` events
3. Group events by source IP
4. Count repeated scans from same IP
5. If scans exceed threshold:

   * mark IP as suspicious
   * generate alert
   * block attacker IP

---

## Detecting Brute Force Attacks

1. Read all events
2. Check for `brute_force` or `ssh_failure`
3. Count repeated failures from same IP
4. If repeated attempts are detected:

   * classify as brute-force attack
   * raise HIGH severity alert
   * notify SOC analyst

---

## Generating Hourly Attack Summary

1. Group events by hour using timestamp
2. Group events again by attack type
3. Count total events for each attack type
4. Store results into `events_per_hour_summary`
5. Display attack trends in dashboard

Example:

* 14:00 hour:

  * port_scan → high count
  * firewall_block → high count
  * brute_force → medium count

---

## Creating Source IP Statistics

1. Read all events
2. Group events by source IP
3. Count total attempts for each IP
4. Record:

   * first_seen timestamp
   * last_seen timestamp
   * attack types used
5. Store results into `source_ip_stats`

Example:

* IP: 185.220.101.47
* Total Attempts: high
* Attack Types:

  * port_scan
  * brute_force
  * root_attack
  * http_probe

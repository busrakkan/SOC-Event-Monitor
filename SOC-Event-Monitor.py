import re
from datetime import datetime
import csv
from collections import defaultdict

# Event Parsing & Collection

LOG_FILE = "sample_logs.txt"

# Store parsed events
events = []

def parse_log_line(line):
    """
    Parse a log line in the format:
    YYYY-MM-DD HH:MM:SS user=<username> ip=<ip_address> status=<success|failed>
    """
    try:
        timestamp_str = re.search(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line).group()
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        user = re.search(r"user=(\w+)", line).group(1)
        ip = re.search(r"ip=([\d.]+)", line).group(1)
        status = re.search(r"status=(\w+)", line).group(1)
        return {"timestamp": timestamp, "user": user, "ip": ip, "status": status}
    except:
        return None

# Read log file and parse events
with open(LOG_FILE, "r") as f:
    for line in f:
        event = parse_log_line(line)
        if event:
            events.append(event)

# Test output
print(f"Parsed {len(events)} events:")
for e in events:
    print(e)


# Anomaly Detection & Alerting

# Configuration
FAILED_LOGIN_THRESHOLD = 3
SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]

# Track failed logins per user per hour
failed_logins = defaultdict(list)
alerts = []

for event in events:
    user = event["user"]
    ip = event["ip"]
    status = event["status"]
    timestamp = event["timestamp"]

    # --- Detect failed logins ---
    if status.lower() == "failed":
        # Round timestamp to hour for grouping
        hour = timestamp.replace(minute=0, second=0)
        failed_logins[(user, hour)].append(event)

        if len(failed_logins[(user, hour)]) > FAILED_LOGIN_THRESHOLD:
            alerts.append(
                f"[HIGH] {len(failed_logins[(user, hour)])} failed logins for user '{user}' around {hour}"
            )

    # --- Detect suspicious IPs ---
    if ip in SUSPICIOUS_IPS:
        alerts.append(
            f"[MEDIUM] Suspicious login from IP {ip} by user '{user}' at {timestamp}"
        )

# --- Output Alerts ---
print("\n=== ALERTS DETECTED ===")
if alerts:
    for alert in alerts:
        print(alert)
else:
    print("No alerts detected.")

# --- Save alerts to CSV ---
with open("alerts_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Alert"])
    for alert in alerts:
        writer.writerow([alert])


# --- Visualization: Failed Logins per User ---
import matplotlib.pyplot as plt

# Prepare data for visualization
users = [user for (user, _) in failed_logins.keys()]
failed_counts = [len(events) for events in failed_logins.values()]

if failed_counts:
    plt.figure(figsize=(8,5))
    plt.bar(users, failed_counts, color='salmon')
    plt.xlabel("Users")
    plt.ylabel("Number of Failed Logins")
    plt.title("Failed Login Attempts per User (SOC-Event-Monitor)")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.show()

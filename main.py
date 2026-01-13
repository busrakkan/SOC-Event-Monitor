import csv
from parser import parse_log_line
from detection import detect_failed_logins, detect_brute_force
import matplotlib.pyplot as plt

LOG_FILE = "sample_logs.txt"

# --- Event Parsing ---
events = []
with open(LOG_FILE, "r") as f:
    for line in f:
        event = parse_log_line(line)
        if event:
            events.append(event)

print(f"Parsed {len(events)} events:")
for e in events:
    print(e)

# --- Detection ---
alerts, failed_logins = detect_failed_logins(events)
enhanced_alerts = detect_brute_force(events)
all_alerts = alerts + enhanced_alerts

# --- Output Alerts ---
print("\n=== ALERTS DETECTED ===")
if all_alerts:
    for alert in all_alerts:
        print(alert)
else:
    print("No alerts detected.")

# --- Save alerts to CSV ---
with open("alerts_report.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Alert"])
    for alert in all_alerts:
        writer.writerow([alert])

# --- Visualization: Failed Logins per User ---
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

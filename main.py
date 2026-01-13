from parser import parse_log_line
from detection import detect_failed_logins, detect_brute_force_and_escalation
from alerts import print_alerts, save_alerts_to_csv
import matplotlib.pyplot as plt
from visualization import plot_failed_logins, plot_failed_logins_over_time, plot_ip_user_heatmap


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
enhanced_alerts = detect_brute_force_and_escalation(events)
all_alerts = alerts + enhanced_alerts

# --- Output Alerts using alerts.py ---
print_alerts(all_alerts)
save_alerts_to_csv(all_alerts)

# --- Visualization: Failed Logins per User ---
plot_failed_logins(failed_logins)
plot_failed_logins_over_time(events)
plot_ip_user_heatmap(events)

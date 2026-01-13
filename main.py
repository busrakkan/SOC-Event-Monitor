import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

from alerts import create_alert, save_alerts_to_json, print_alerts

# ----------------------------
# Configuration
# ----------------------------

LOG_FILE = "sample_logs.txt"

WINDOW_MINUTES = 5
FAIL_THRESHOLD = 5

SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]

# ----------------------------
# Event Parsing
# ----------------------------

def parse_log_line(line):
    """
    Format:
    YYYY-MM-DD HH:MM:SS user=<username> ip=<ip> status=<success|failed>
    """
    try:
        timestamp_str = re.search(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line
        ).group()

        return {
            "timestamp": datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"),
            "user": re.search(r"user=(\w+)", line).group(1),
            "ip": re.search(r"ip=([\d.]+)", line).group(1),
            "status": re.search(r"status=(\w+)", line).group(1).lower()
        }
    except Exception:
        return None


# ----------------------------
# Load Events
# ----------------------------

events = []

with open(LOG_FILE, "r") as f:
    for line in f:
        event = parse_log_line(line)
        if event:
            events.append(event)

print(f"Parsed {len(events)} events")

# ----------------------------
# Detection Logic
# ----------------------------

recent_failures_by_ip = defaultdict(lambda: deque())
structured_alerts = []

# Deduplication trackers
alerted_suspicious_ips = set()
alerted_bruteforce_ips = set()

for event in events:
    ip = event["ip"]
    user = event["user"]
    status = event["status"]
    timestamp = event["timestamp"]

    # ---- Failed login tracking (IP-based) ----
    if status == "failed":
        recent_failures_by_ip[ip].append((timestamp, user))

        # Remove failures outside time window
        while (
            recent_failures_by_ip[ip]
            and timestamp - recent_failures_by_ip[ip][0][0]
            > timedelta(minutes=WINDOW_MINUTES)
        ):
            recent_failures_by_ip[ip].popleft()

        # Brute-force detection (deduplicated)
        if (
            len(recent_failures_by_ip[ip]) >= FAIL_THRESHOLD
            and ip not in alerted_bruteforce_ips
        ):
            start_time = recent_failures_by_ip[ip][0][0]
            end_time = timestamp

            structured_alerts.append(
                create_alert(
                    severity="HIGH",
                    attack_type="BRUTE_FORCE",
                    source_ip=ip,
                    username=user,
                    attempts=len(recent_failures_by_ip[ip]),
                    start_time=start_time,
                    end_time=end_time,
                    description=f"{len(recent_failures_by_ip[ip])} failed logins from IP {ip}"
                )
            )

            alerted_bruteforce_ips.add(ip)

    # ---- Success after failures (escalation) ----
    if status == "success" and ip in recent_failures_by_ip:
        failures = recent_failures_by_ip[ip]

        if len(failures) >= FAIL_THRESHOLD:
            start_time = failures[0][0]

            structured_alerts.append(
                create_alert(
                    severity="CRITICAL",
                    attack_type="SUCCESS_AFTER_BRUTE_FORCE",
                    source_ip=ip,
                    username=user,
                    attempts=len(failures),
                    start_time=start_time,
                    end_time=timestamp,
                    description="Successful login after multiple failures"
                )
            )

            recent_failures_by_ip[ip].clear()

    # ---- Suspicious IP detection (deduplicated) ----
    if ip in SUSPICIOUS_IPS and ip not in alerted_suspicious_ips:
        structured_alerts.append(
            create_alert(
                severity="MEDIUM",
                attack_type="SUSPICIOUS_IP",
                source_ip=ip,
                username=user,
                attempts=1,
                start_time=timestamp,
                end_time=timestamp,
                description="Login attempt from known suspicious IP"
            )
        )

        alerted_suspicious_ips.add(ip)

# ----------------------------
# Output
# ----------------------------

print_alerts(structured_alerts)
save_alerts_to_json(structured_alerts)

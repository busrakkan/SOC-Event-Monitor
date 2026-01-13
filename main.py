import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

from alerts import create_alert, save_alerts_to_json, print_alerts
from normalizer import normalize_event

# ----------------------------
# Configuration
# ----------------------------

LOG_FILE = "sample_logs.txt"

WINDOW_MINUTES = 5
FAIL_THRESHOLD = 5

SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]

# ----------------------------
# Raw Log Parsing
# ----------------------------

def parse_log_line(line):
    """
    Raw format:
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
# Load & Normalize Events
# ----------------------------

raw_events = []
normalized_events = []

with open(LOG_FILE, "r") as f:
    for line in f:
        raw = parse_log_line(line)
        if raw:
            raw_events.append(raw)

for raw in raw_events:
    normalized = normalize_event(raw)
    if normalized:
        normalized_events.append(normalized)

print(f"Parsed {len(raw_events)} raw events")
print(f"Normalized {len(normalized_events)} events")

# ----------------------------
# Detection & Aggregation
# ----------------------------

recent_failures_by_ip = defaultdict(lambda: deque())
structured_alerts = []

alerted_suspicious_ips = set()
alerted_bruteforce_ips = set()

# SOC summaries
failures_per_ip = defaultdict(int)
users_per_ip = defaultdict(set)
event_counters = defaultdict(int)

for event in normalized_events:
    ip = event["source_ip"]
    user = event["username"]
    outcome = event["outcome"]
    timestamp = event["timestamp"]

    event_counters[outcome] += 1
    users_per_ip[ip].add(user)

    # ---- Failed login tracking ----
    if outcome == "FAILURE":
        failures_per_ip[ip] += 1
        recent_failures_by_ip[ip].append((timestamp, user))

        while (
            recent_failures_by_ip[ip]
            and timestamp - recent_failures_by_ip[ip][0][0]
            > timedelta(minutes=WINDOW_MINUTES)
        ):
            recent_failures_by_ip[ip].popleft()

        if (
            len(recent_failures_by_ip[ip]) >= FAIL_THRESHOLD
            and ip not in alerted_bruteforce_ips
        ):
            structured_alerts.append(
                create_alert(
                    severity="HIGH",
                    attack_type="BRUTE_FORCE",
                    source_ip=ip,
                    username=user,
                    attempts=len(recent_failures_by_ip[ip]),
                    start_time=recent_failures_by_ip[ip][0][0],
                    end_time=timestamp,
                    description="Multiple authentication failures detected"
                )
            )
            alerted_bruteforce_ips.add(ip)

    # ---- Success after brute-force ----
    if outcome == "SUCCESS" and ip in recent_failures_by_ip:
        failures = recent_failures_by_ip[ip]

        if len(failures) >= FAIL_THRESHOLD:
            structured_alerts.append(
                create_alert(
                    severity="CRITICAL",
                    attack_type="SUCCESS_AFTER_BRUTE_FORCE",
                    source_ip=ip,
                    username=user,
                    attempts=len(failures),
                    start_time=failures[0][0],
                    end_time=timestamp,
                    description="Successful authentication after brute-force activity"
                )
            )
            recent_failures_by_ip[ip].clear()

    # ---- Suspicious IP ----
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
                description="Authentication attempt from suspicious IP"
            )
        )
        alerted_suspicious_ips.add(ip)

# ----------------------------
# Output
# ----------------------------

print_alerts(structured_alerts)
save_alerts_to_json(structured_alerts)

# ----------------------------
# SOC SUMMARY
# ----------------------------

print("\n=== SOC SUMMARY REPORT ===")
print(f"Total events: {len(normalized_events)}")
print(f"Successful logins: {event_counters['SUCCESS']}")
print(f"Failed logins: {event_counters['FAILURE']}")

print("\nTop IPs by failed attempts:")
for ip, count in sorted(
    failures_per_ip.items(), key=lambda x: x[1], reverse=True
):
    print(f"- {ip}: {count} failures (users: {', '.join(users_per_ip[ip])})")

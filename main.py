import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

from alerts import create_alert, save_alerts_to_json, print_alerts
from normalizer import normalize_event
from ssh_parser import parse_ssh_auth_log


GENERIC_LOG_FILE = "sample_logs.txt"
SSH_LOG_FILE = "ssh_auth.log"

WINDOW_MINUTES = 5
FAIL_THRESHOLD = 5

SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]


def parse_generic_log(line):
    try:
        timestamp_str = re.search(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line
        ).group()

        return {
            "timestamp": datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"),
            "user": re.search(r"user=(\w+)", line).group(1),
            "ip": re.search(r"ip=([\d.]+)", line).group(1),
            "status": re.search(r"status=(\w+)", line).group(1).lower(),
            "source": "GENERIC_AUTH"
        }
    except Exception:
        return None


raw_events = []

with open(GENERIC_LOG_FILE) as f:
    for line in f:
        evt = parse_generic_log(line)
        if evt:
            raw_events.append(evt)

with open(SSH_LOG_FILE) as f:
    for line in f:
        evt = parse_ssh_auth_log(line)
        if evt:
            raw_events.append(evt)


normalized_events = [
    normalize_event(evt) for evt in raw_events if normalize_event(evt)
]

print(f"Loaded {len(normalized_events)} normalized events")


recent_failures_by_ip = defaultdict(lambda: deque())
structured_alerts = []

alerted_suspicious_ips = set()
alerted_bruteforce_ips = set()

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

    if outcome == "FAILURE":
        failures_per_ip[ip] += 1
        recent_failures_by_ip[ip].append((timestamp, user))

        while (
            recent_failures_by_ip[ip]
            and timestamp - recent_failures_by_ip[ip][0][0]
            > timedelta(minutes=WINDOW_MINUTES)
        ):
            recent_failures_by_ip[ip].popleft()

        if len(recent_failures_by_ip[ip]) >= FAIL_THRESHOLD and ip not in alerted_bruteforce_ips:
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
                    description="Successful login after brute-force activity"
                )
            )
            recent_failures_by_ip[ip].clear()


print_alerts(structured_alerts)
save_alerts_to_json(structured_alerts)

print("\n=== SOC SUMMARY REPORT ===")
for ip, count in failures_per_ip.items():
    print(f"{ip}: {count} failures, users: {', '.join(users_per_ip[ip])}")

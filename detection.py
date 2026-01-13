# detection.py
from collections import defaultdict, deque
from datetime import timedelta

# --- Detection Configuration ---
FAILED_LOGIN_THRESHOLD = 3
WINDOW_MINUTES = 5
FAIL_THRESHOLD = 3
SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]


def detect_failed_logins(events):
    """
    Detect users exceeding failed login thresholds per hour
    and suspicious IP activity.
    """
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:
        user = event["user"]
        ip = event["ip"]
        status = event["status"]
        timestamp = event["timestamp"]

        if status.lower() == "failed":
            hour = timestamp.replace(minute=0, second=0)
            failed_logins[(user, hour)].append(event)

            if len(failed_logins[(user, hour)]) > FAILED_LOGIN_THRESHOLD:
                alerts.append(
                    f"[HIGH] {len(failed_logins[(user, hour)])} failed logins for user '{user}' around {hour}"
                )

        if ip in SUSPICIOUS_IPS:
            alerts.append(
                f"[MEDIUM] Suspicious login from IP {ip} by user '{user}' at {timestamp}"
            )

    return alerts, failed_logins


def detect_brute_force_and_escalation(events):
    """
    Detect:
    - Rolling-window brute-force attempts
    - Escalation from failed to successful login
    - Single IP attacking multiple users
    """
    recent_failures = defaultdict(lambda: deque())
    users_per_ip = defaultdict(set)
    alerts = []

    for event in events:
        user = event["user"]
        ip = event["ip"]
        status = event["status"]
        timestamp = event["timestamp"]

        # Track users per IP (spray attack detection)
        users_per_ip[ip].add(user)

        # --- Failed login tracking ---
        if status.lower() == "failed":
            recent_failures[user].append(timestamp)

            # Remove old failures outside rolling window
            while recent_failures[user] and timestamp - recent_failures[user][0] > timedelta(minutes=WINDOW_MINUTES):
                recent_failures[user].popleft()

            if len(recent_failures[user]) >= FAIL_THRESHOLD:
                alerts.append(
                    f"[HIGH] Possible brute-force attempt: {len(recent_failures[user])} failed logins for user '{user}' within {WINDOW_MINUTES} minutes from IP {ip}"
                )

        # --- Escalation: failures followed by success ---
        if status.lower() == "success" and len(recent_failures[user]) >= FAIL_THRESHOLD:
            alerts.append(
                f"[CRITICAL] Possible account compromise: user '{user}' logged in successfully after {len(recent_failures[user])} failed attempts from IP {ip}"
            )
            recent_failures[user].clear()

    # --- Detect IP attacking multiple users ---
    for ip, users in users_per_ip.items():
        if len(users) >= 3:
            alerts.append(
                f"[CRITICAL] Possible password spraying attack: IP {ip} attempted logins on multiple users ({', '.join(users)})"
            )

    return alerts

from collections import defaultdict, deque
from datetime import timedelta

# --- Detection Configuration ---
FAILED_LOGIN_THRESHOLD = 3
SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.50"]
WINDOW_MINUTES = 5
FAIL_THRESHOLD = 3

def detect_failed_logins(events):
    """
    Detect users exceeding failed login thresholds per hour
    and log suspicious IPs.
    Returns a list of alert strings and failed login dictionary for visualization.
    """
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:
        user = event["user"]
        ip = event["ip"]
        status = event["status"]
        timestamp = event["timestamp"]

        # Detect failed logins per hour
        if status.lower() == "failed":
            hour = timestamp.replace(minute=0, second=0)
            failed_logins[(user, hour)].append(event)
            if len(failed_logins[(user, hour)]) > FAILED_LOGIN_THRESHOLD:
                alerts.append(
                    f"[HIGH] {len(failed_logins[(user, hour)])} failed logins for user '{user}' around {hour}"
                )

        # Detect suspicious IPs
        if ip in SUSPICIOUS_IPS:
            alerts.append(
                f"[MEDIUM] Suspicious login from IP {ip} by user '{user}' at {timestamp}"
            )

    return alerts, failed_logins


def detect_brute_force(events):
    """
    Detect rolling-window brute-force login attempts.
    Returns a list of alert strings.
    """
    recent_failures = defaultdict(lambda: deque())
    enhanced_alerts = []

    for event in events:
        user = event["user"]
        ip = event["ip"]
        status = event["status"]
        timestamp = event["timestamp"]

        # Track failed logins in rolling window
        if status.lower() == "failed":
            recent_failures[user].append(timestamp)
            while recent_failures[user] and timestamp - recent_failures[user][0] > timedelta(minutes=WINDOW_MINUTES):
                recent_failures[user].popleft()

            if len(recent_failures[user]) >= FAIL_THRESHOLD:
                enhanced_alerts.append(
                    f"[HIGH] Possible brute-force detected: {len(recent_failures[user])} failed logins for user '{user}' within {WINDOW_MINUTES} minutes from IP {ip}"
                )

        # Optional: flag suspicious IPs again
        if ip in SUSPICIOUS_IPS:
            enhanced_alerts.append(
                f"[MEDIUM] Suspicious IP login attempt: {ip} by user '{user}' at {timestamp}"
            )

    return enhanced_alerts

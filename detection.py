from collections import defaultdict, deque
from datetime import timedelta


# ======================================================
# USER-BASED DETECTION (SOC LOGIC)
# ======================================================

FAILED_LOGIN_THRESHOLD = 3  # per user per hour

def detect_failed_logins(events):
    """
    Detect multiple failed logins per user per hour.
    Returns:
    - alerts: list of alert strings
    - failed_logins: dict {(user, hour): [events]}
    """
    failed_logins = defaultdict(list)
    alerts = []

    for event in events:
        user = event["user"]
        status = event["status"]
        timestamp = event["timestamp"]

        if status.lower() == "failed":
            hour = timestamp.replace(minute=0, second=0)
            failed_logins[(user, hour)].append(event)

            if len(failed_logins[(user, hour)]) == FAILED_LOGIN_THRESHOLD + 1:
                alerts.append(
                    f"[HIGH] Multiple failed logins for user '{user}' around {hour}"
                )

    return alerts, failed_logins


# ======================================================
# USER-BASED BRUTE FORCE & ESCALATION (SOC LOGIC)
# ======================================================

WINDOW_MINUTES_USER = 5
FAIL_THRESHOLD_USER = 3

def detect_brute_force_and_escalation(events):
    """
    Detect brute-force attempts and escalation (failed -> success) per user.
    """
    recent_failures_user = defaultdict(lambda: deque())
    alerts = []

    for event in events:
        user = event["user"]
        ip = event["ip"]
        status = event["status"]
        timestamp = event["timestamp"]

        if status.lower() == "failed":
            recent_failures_user[user].append(timestamp)

            while (
                recent_failures_user[user]
                and timestamp - recent_failures_user[user][0] > timedelta(minutes=WINDOW_MINUTES_USER)
            ):
                recent_failures_user[user].popleft()

            if len(recent_failures_user[user]) == FAIL_THRESHOLD_USER:
                alerts.append(
                    f"[HIGH] Possible brute-force against user '{user}' from IP {ip}"
                )

        if status.lower() == "success" and len(recent_failures_user[user]) >= FAIL_THRESHOLD_USER:
            alerts.append(
                f"[CRITICAL] Login success after multiple failures for user '{user}' from IP {ip}"
            )
            recent_failures_user[user].clear()

    return alerts


# ========================================================================
# IP-BASED SSH-STYLE BRUTE FORCE DETECTION (SSH-style brute-force logic)
# ========================================================================

WINDOW_MINUTES_IP = 5
FAIL_THRESHOLD_IP = 5  # common SSH default

def detect_ip_based_bruteforce(events):
    """
    Detect SSH-style brute-force attacks based on source IP.
    Rules:
    - Multiple failed attempts from same IP in short time window
    - Successful login after many failures from same IP
    """
    recent_failures_ip = defaultdict(lambda: deque())
    alerts = []

    for event in events:
        ip = event["ip"]
        user = event["user"]
        status = event["status"]
        timestamp = event["timestamp"]

        # Track failed attempts per IP
        if status.lower() == "failed":
            recent_failures_ip[ip].append(timestamp)

            # Remove events outside rolling window
            while (
                recent_failures_ip[ip]
                and timestamp - recent_failures_ip[ip][0] > timedelta(minutes=WINDOW_MINUTES_IP)
            ):
                recent_failures_ip[ip].popleft()

            if len(recent_failures_ip[ip]) == FAIL_THRESHOLD_IP:
                alerts.append(
                    f"[HIGH] SSH-style brute-force detected from IP {ip} "
                    f"({FAIL_THRESHOLD_IP} failed attempts within {WINDOW_MINUTES_IP} minutes)"
                )

        # Detect escalation: success after failures
        if status.lower() == "success" and len(recent_failures_ip[ip]) >= FAIL_THRESHOLD_IP:
            start_time = recent_failures_ip[ip][0]
            end_time = timestamp

            alerts.append(
                f"[CRITICAL] Successful login after brute-force from IP {ip} "
                f"(user '{user}', window {start_time} - {end_time})"
            )

            recent_failures_ip[ip].clear()

    return alerts

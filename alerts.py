import json
from datetime import datetime


def create_alert(
    severity,
    attack_type,
    source_ip,
    username,
    attempts,
    start_time,
    end_time,
    description
):
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "attack_type": attack_type,
        "source_ip": source_ip,
        "username": username,
        "attempts": attempts,
        "time_window": {
            "start": start_time.isoformat(),
            "end": end_time.isoformat()
        },
        "description": description
    }


def save_alerts_to_json(alerts, filename="alerts.json"):
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=4)


def print_alerts(alerts):
    print("\n=== STRUCTURED ALERTS ===")
    if not alerts:
        print("No alerts detected.")
        return

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['attack_type']} | "
            f"IP={alert['source_ip']} | "
            f"User={alert['username']} | "
            f"Attempts={alert['attempts']}"
        )

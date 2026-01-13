def normalize_event(raw_event):
    """
    Convert raw parsed events into a normalized SOC event format
    """

    if not raw_event:
        return None

    outcome = "SUCCESS" if raw_event["status"] == "success" else "FAILURE"

    return {
        "timestamp": raw_event["timestamp"],
        "source_ip": raw_event["ip"],
        "username": raw_event["user"],
        "event_type": "AUTH",
        "outcome": outcome,
        "source": "GENERIC_AUTH"
    }

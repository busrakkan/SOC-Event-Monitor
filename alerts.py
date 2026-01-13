import csv

def print_alerts(alerts):
    """
    Print all alerts to the console.
    """
    print("\n=== ALERTS DETECTED ===")
    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No alerts detected.")


def save_alerts_to_csv(alerts, filename="alerts_report.csv"):
    """
    Save alerts to a CSV file.
    """
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Alert"])
        for alert in alerts:
            writer.writerow([alert])

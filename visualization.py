import matplotlib.pyplot as plt
from collections import defaultdict

def plot_failed_logins(failed_logins):
    """
    Bar chart: number of failed logins per user.
    """
    users = [user for (user, _) in failed_logins.keys()]
    failed_counts = [len(events) for events in failed_logins.values()]

    if failed_counts:
        plt.figure(figsize=(8,5))
        plt.bar(users, failed_counts, color='salmon')
        plt.xlabel("Users")
        plt.ylabel("Number of Failed Logins")
        plt.title("Failed Login Attempts per User (SOC-Event-Monitor)")
        plt.xticks(rotation=30)
        plt.tight_layout()
        plt.show()


def plot_failed_logins_over_time(events):
    """
    Line chart: number of failed logins per hour.
    """
    counts_per_hour = defaultdict(int)
    for event in events:
        if event["status"].lower() == "failed":
            hour = event["timestamp"].replace(minute=0, second=0)
            counts_per_hour[hour] += 1

    if counts_per_hour:
        hours = sorted(counts_per_hour.keys())
        counts = [counts_per_hour[h] for h in hours]

        plt.figure(figsize=(10,5))
        plt.plot(hours, counts, marker='o', color='orange')
        plt.xlabel("Hour")
        plt.ylabel("Failed Logins")
        plt.title("Failed Logins Over Time")
        plt.xticks(rotation=30)
        plt.tight_layout()
        plt.show()


def plot_ip_user_heatmap(events):
    """
    Heatmap: IP vs User, counts of login attempts.
    """
    import numpy as np

    ip_user_counts = defaultdict(lambda: defaultdict(int))
    users_set = set()
    ips_set = set()

    for event in events:
        user = event["user"]
        ip = event["ip"]
        ips_set.add(ip)
        users_set.add(user)
        ip_user_counts[ip][user] += 1

    users = sorted(list(users_set))
    ips = sorted(list(ips_set))

    matrix = np.zeros((len(ips), len(users)))

    for i, ip in enumerate(ips):
        for j, user in enumerate(users):
            matrix[i, j] = ip_user_counts[ip][user]

    plt.figure(figsize=(8,6))
    plt.imshow(matrix, cmap="Reds", interpolation="nearest")
    plt.colorbar(label="Login Attempts")
    plt.xticks(range(len(users)), users, rotation=30)
    plt.yticks(range(len(ips)), ips)
    plt.xlabel("Users")
    plt.ylabel("IP Addresses")
    plt.title("Login Attempts Heatmap (IP vs User)")
    plt.tight_layout()
    plt.show()

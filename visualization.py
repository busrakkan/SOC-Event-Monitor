import matplotlib.pyplot as plt

def plot_failed_logins(failed_logins):
    """
    Plot a bar chart of failed login attempts per user.
    failed_logins: dict with keys (user, hour) and values as list of events
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

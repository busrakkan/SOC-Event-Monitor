import re
from datetime import datetime

def parse_log_line(line):
    """
    Parse a log line in the format:
    YYYY-MM-DD HH:MM:SS user=<username> ip=<ip_address> status=<success|failed>
    """
    try:
        timestamp_str = re.search(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line
        ).group()
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        user = re.search(r"user=(\w+)", line).group(1)
        ip = re.search(r"ip=([\d.]+)", line).group(1)
        status = re.search(r"status=(\w+)", line).group(1)

        return {
            "timestamp": timestamp,
            "user": user,
            "ip": ip,
            "status": status,
        }
    except:
        return None

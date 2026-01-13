import re
from datetime import datetime


def parse_ssh_auth_log(line):
    """
    Parses SSH auth.log lines like:
    Jan 13 10:05:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 54321 ssh2
    Jan 13 10:06:12 server sshd[1234]: Accepted password for bob from 192.168.1.10 port 54321 ssh2
    """

    try:
        timestamp_match = re.search(
            r"^(\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})", line
        )
        if not timestamp_match:
            return None

        timestamp = datetime.strptime(
            timestamp_match.group(1), "%b %d %H:%M:%S"
        ).replace(year=datetime.now().year)

        ip_match = re.search(r"from ([\d.]+)", line)
        user_match = re.search(r"for (invalid user )?(\w+)", line)

        if not ip_match or not user_match:
            return None

        ip = ip_match.group(1)
        user = user_match.group(2)

        if "Failed password" in line:
            status = "failed"
        elif "Accepted password" in line:
            status = "success"
        else:
            return None

        return {
            "timestamp": timestamp,
            "user": user,
            "ip": ip,
            "status": status,
            "source": "SSH"
        }

    except Exception:
        return None

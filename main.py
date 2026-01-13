from parser import parse_log_line
from collections import defaultdict, deque
from datetime import timedelta
import csv
import matplotlib.pyplot as plt

LOG_FILE = "sample_logs.txt"

# Store parsed events
events = []

# Read log file and parse events
with open(LOG_FILE, "r") as f:
    for line in f:
        event = parse_log_line(line)
        if event:
            events.append(event)

import sqlite3
import json
import pandas as pd
from datetime import datetime

# Safe process list and odd hour range
WHITELIST_PROCESSES = ['bash', 'python', 'ssh', 'cron']
ODD_HOURS_RANGE = (0, 5)

# Connect to your logs database
conn = sqlite3.connect('alerts.db')  # Change if your DB file has a different name
cursor = conn.cursor()

# Fetch logs
cursor.execute("SELECT client_id, timestamp, running_processes, open_ports, failed_logins FROM client_logs")
rows = cursor.fetchall()

data = []

for client_id, timestamp, running_processes, open_ports, failed_logins in rows:
    try:
        processes = json.loads(running_processes)
        ports = json.loads(open_ports)
        logins = json.loads(failed_logins)
    except json.JSONDecodeError:
        continue

    num_open_ports = len(ports)
    num_failed_logins = len(logins)
    has_unusual_process = any(proc not in WHITELIST_PROCESSES for proc in processes)

    log_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    is_odd_hour = int(ODD_HOURS_RANGE[0] <= log_time.hour <= ODD_HOURS_RANGE[1])

    # 👇 Manually set label = 1 if malicious, 0 if normal (we’ll automate this later)
    label = int(input(f"Label this log as malicious (1) or normal (0)?\nTime: {timestamp}, Ports: {ports}, Logins: {logins}, Unusual Process: {has_unusual_process}\n> "))

    data.append({
        "num_open_ports": num_open_ports,
        "num_failed_logins": num_failed_logins,
        "has_unusual_process": int(has_unusual_process),
        "is_odd_hour": is_odd_hour,
        "label": label
    })

# Save to CSV
df = pd.DataFrame(data)
df.to_csv("labeled_logs.csv", index=False)
print("✅ Labeled logs saved to labeled_logs.csv")

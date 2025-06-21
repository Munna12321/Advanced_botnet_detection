import sqlite3
import json
import pandas as pd

def extract_and_label_data(db_name="alerts.db"):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Fetch all client logs
    cursor.execute("SELECT client_id, timestamp, running_processes, open_ports, failed_logins FROM client_logs")
    client_logs = cursor.fetchall()

    # Fetch all malicious logs for comparison
    cursor.execute("SELECT client_id, timestamp FROM malicious_client_logs")
    malicious_entries = set(cursor.fetchall())  # Set for fast lookup

    data = []

    for client_id, timestamp, processes, ports, logins in client_logs:
        try:
            # Convert stringified JSON to Python lists
            processes = json.loads(processes)
            ports = json.loads(ports)
            logins = json.loads(logins)

            num_processes = len(processes)
            num_ports = len(ports)
            num_logins = len(logins)

            # Additional logic: count how many unusual ports
            unusual_ports = [4444, 1337, 5555, 8080]
            port_values = [p if isinstance(p, int) else p.get("port") for p in ports]
            port_values = [p for p in port_values if isinstance(p, int)]
            num_unusual_ports = sum(1 for p in port_values if p in unusual_ports)

            label = 1 if (client_id, timestamp) in malicious_entries else 0

            data.append({
                "num_processes": num_processes,
                "num_ports": num_ports,
                "num_failed_logins": num_logins,
                "num_unusual_ports": num_unusual_ports,
                "label": label
            })

        except json.JSONDecodeError:
            continue

    df = pd.DataFrame(data)
    conn.close()
    return df

# Save to CSV for inspection or model training
df = extract_and_label_data()
df.to_csv("labeled_dataset.csv", index=False)
print("Dataset created and saved as labeled_dataset.csv")

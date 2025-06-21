import sqlite3
import json
import time
import os
from datetime import datetime
from datetime import datetime, timedelta
from joblib import load

DB_NAME = "alerts.db"
MULTIPLE_PORT_THRESHOLD = 4
FREQUENT_CONNECTION_THRESHOLD = 4
UNUSUAL_PORTS = [4444, 1337, 5555, 8080]  # Common suspicious ports
WHITELIST_PROCESSES = ['bash', 'ssh', 'python', 'systemd']
ODD_HOURS_RANGE = (1, 6)
last_seen_logs = {}

# Load AI model once
MODEL_PATH = "botnet_model.pkl"
model = load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_client_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                timestamp TEXT,
                running_processes TEXT,
                open_ports TEXT,
                failed_logins TEXT,
                reason TEXT,
                UNIQUE(client_id, timestamp, reason)
            )
        """)
        conn.commit()

def fetch_logs():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT client_id, timestamp, running_processes, open_ports, failed_logins 
            FROM client_logs 
            ORDER BY timestamp DESC 
            LIMIT 50
        """)
        return cursor.fetchall()

# Feature extraction for ML model
def extract_features(running_processes, open_ports, failed_logins, log_time):
    unusual_processes = sum(1 for proc in running_processes if proc not in WHITELIST_PROCESSES)
    port_count = len(open_ports)
    failed_login_count = len(failed_logins)
    odd_hour = 1 if ODD_HOURS_RANGE[0] <= log_time.hour <= ODD_HOURS_RANGE[1] else 0
    return [unusual_processes, port_count, failed_login_count, odd_hour]

def analyze_logs():
    logs = fetch_logs()
    malicious_logs = []

    for client_id, timestamp, running_processes, open_ports, failed_logins in logs:
        try:
            running_processes = json.loads(running_processes)
            open_ports = json.loads(open_ports)
            failed_logins = json.loads(failed_logins)
        except (json.JSONDecodeError, ValueError):
            continue

        # AI Prediction Integration
        try:
            log_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

        if model:
            features = extract_features(running_processes, open_ports, failed_logins, log_time)
            prediction = model.predict([features])[0]  # 0 = normal, 1 = malicious

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE client_logs SET prediction = ? WHERE client_id = ? AND timestamp = ?",
                               (int(prediction), client_id, timestamp))
                conn.commit()

        reasons = []
        print(f"[DEBUG] Processing log for {client_id} @ {timestamp}")

        if isinstance(open_ports, list) and len(open_ports) > MULTIPLE_PORT_THRESHOLD:
            print(f"[DEBUG] Too many open ports detected")
            reasons.append("Too many open ports")

        if isinstance(failed_logins, list) and len(failed_logins) > FREQUENT_CONNECTION_THRESHOLD:
            print(f"[DEBUG] Excessive failed logins detected")
            reasons.append("Excessive failed login attempts")

        if any(proc not in WHITELIST_PROCESSES for proc in running_processes):
            print(f"[DEBUG] Unusual processes detected")
            reasons.append("Unusual processes detected")

        try:
            if ODD_HOURS_RANGE[0] <= log_time.hour <= ODD_HOURS_RANGE[1]:
                print(f"[DEBUG] Suspicious time-based behavior detected")
                reasons.append("Suspicious time-based behavior detected (odd hours)")
        except Exception:
            continue

        ip_port_map = {}
        if all(isinstance(p, dict) and "ip" in p and "port" in p for p in open_ports):
            for entry in open_ports:
                ip = entry["ip"]
                port = entry["port"]
                ip_port_map.setdefault(ip, set()).add(port)
            for ip, ports in ip_port_map.items():
                if len(ports) > 3:
                    print(f"[DEBUG] IP {ip} accessing multiple ports: {ports}")
                    reasons.append(f"IP {ip} scanning multiple ports")

        ip_connection_counts = {}
        if all(isinstance(f, dict) and "ip" in f for f in failed_logins):
            for login in failed_logins:
                ip = login["ip"]
                ip_connection_counts[ip] = ip_connection_counts.get(ip, 0) + 1
            for ip, count in ip_connection_counts.items():
                if count > 20:
                    print(f"[DEBUG] IP {ip} overwhelming server with {count} failed connections")
                    reasons.append(f"IP {ip} overwhelming the server with requests")

        if isinstance(open_ports, list):
            suspicious_ports_found = []
            for port_entry in open_ports:
                if isinstance(port_entry, int) and port_entry in UNUSUAL_PORTS:
                    suspicious_ports_found.append(port_entry)
                elif isinstance(port_entry, dict) and "port" in port_entry and port_entry["port"] in UNUSUAL_PORTS:
                    suspicious_ports_found.append(port_entry["port"])
            if suspicious_ports_found:
                print(f"[DEBUG] Unusual ports detected: {suspicious_ports_found}")
                reasons.append(f"Unusual ports accessed: {suspicious_ports_found}")

        # ⬇️ Repeated Suspicious Behavior Check moved here
        try:
            recent_window_start = (datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S") - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
            with sqlite3.connect(DB_NAME) as conn:
              cursor = conn.cursor()
              cursor.execute("""
            SELECT COUNT(*) FROM client_logs 
            WHERE client_id = ? AND timestamp >= ?
        """, (client_id, recent_window_start))
            count = cursor.fetchone()[0]
            print(f"[DEBUG] Found {count} logs for {client_id} since {recent_window_start}")
        
        # Add reason if suspicious pattern was already triggered (>=3)
            if count >= 3:
             reasons.append("Repeated suspicious behavior detected")
        
        # Add separate reason for frequent log submissions even if no anomaly is present
            elif count >= 5 and not reasons:
                reasons.append("Frequent access without anomaly")
        except Exception as e:
          print(f"[ERROR] Repeated behavior detection failed: {e}")


        # ⬇️ Now include it in reasons and process log
        if reasons:
             reason_str = ", ".join(reasons)
             print(f"[DEBUG] Detected Reasons: {reason_str}")
             unique_key = f"{client_id}_{timestamp}_{reason_str}"

             if last_seen_logs.get(client_id) != unique_key and not is_already_stored(client_id, timestamp, reason_str):
               print(f"[DEBUG] Storing malicious log for {client_id} @ {timestamp}")
               malicious_logs.append((client_id, timestamp,
                               json.dumps(running_processes),
                               json.dumps(open_ports),
                               json.dumps(failed_logins),
                               reason_str))
               last_seen_logs[client_id] = unique_key

        # Also flag it in client_logs if model is not used or doesn't catch it
               if not model:
                  with sqlite3.connect(DB_NAME) as conn:
                   cursor = conn.cursor()
                   cursor.execute("UPDATE client_logs SET prediction = 1 WHERE client_id = ? AND timestamp = ?",
                               (client_id, timestamp))
                   conn.commit()


    if malicious_logs:
        store_malicious_logs(malicious_logs)


def is_already_stored(client_id, timestamp, reason):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 1 FROM malicious_client_logs
            WHERE client_id = ? AND timestamp = ? AND reason = ?
        """, (client_id, timestamp, reason))
        return cursor.fetchone() is not None

def store_malicious_logs(logs):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        for log in logs:
            client_id, timestamp, running_processes, open_ports, failed_logins, reason = log
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO malicious_client_logs 
                    (client_id, timestamp, running_processes, open_ports, failed_logins, reason)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (client_id, timestamp, running_processes, open_ports, failed_logins, reason))
            except Exception as e:
                print(f"Insert error: {e}")
        conn.commit()

def update_prediction_from_malicious_logs():
    with sqlite3.connect("alerts.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE client_logs SET prediction = 0")
        cursor.execute("""
            UPDATE client_logs
            SET prediction = 1
            WHERE (client_id) IN (
                SELECT client_id FROM malicious_client_logs
            )
        """)
        conn.commit()

if __name__ == "__main__":
    init_db()
    print("Starting real-time log analysis...")
    while True:
        try:
            analyze_logs()
            print("Analysis done....")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(5)

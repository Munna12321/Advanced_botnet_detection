from flask import Blueprint, request, jsonify
import sqlite3
import json
from prediction_updater import update_prediction_from_malicious_logs
from datetime import datetime
import pytz
import joblib
import os

log_handler = Blueprint('log_handler', __name__)
DB_NAME = "alerts.db"

# Load ML model once at the top
MODEL_PATH = "log_classifier_model.pkl"
model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

# Whitelist and odd hours
WHITELIST_PROCESSES = ['bash', 'python', 'ssh', 'cron']
ODD_HOURS_RANGE = (0, 5)

def get_current_ist_time():
    ist = pytz.timezone("Asia/Kolkata")
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S")

@log_handler.route('/receive_logs', methods=['POST'])
def receive_logs():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data received"}), 400

        client_id = data.get("client_id")
        timestamp = get_current_ist_time()
        processes = data.get("running_processes", [])
        ports = data.get("open_ports", [])
        logins = data.get("failed_logins", [])

        # Extract features for prediction
        num_open_ports = len(ports)
        num_failed_logins = len(logins)
        has_unusual_process = any(proc not in WHITELIST_PROCESSES for proc in processes)
        log_time = datetime.now(pytz.timezone("Asia/Kolkata"))
        is_odd_hour = int(ODD_HOURS_RANGE[0] <= log_time.hour <= ODD_HOURS_RANGE[1])

        features = [[num_open_ports, num_failed_logins, int(has_unusual_process), is_odd_hour]]

        prediction = model.predict(features)[0] if model else "N/A"

        # Insert into DB
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO client_logs (client_id, timestamp, running_processes, open_ports, failed_logins, prediction) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            client_id,
            timestamp,
            json.dumps(processes),
            json.dumps(ports),
            json.dumps(logins),
            str(prediction)
        ))

        # New logic to also insert into malicious_client_logs
        if str(prediction).lower() == "malicious":
            cursor.execute("""
                INSERT INTO malicious_client_logs (client_id, timestamp, running_processes, open_ports, failed_logins, prediction)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                client_id,
                timestamp,
                json.dumps(processes),
                json.dumps(ports),
                json.dumps(logins),
                str(prediction)
            ))

        conn.commit()


        update_prediction_from_malicious_logs()
        conn.close()

        return jsonify({"message": "Log received successfully", "prediction": str(prediction)}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

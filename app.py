from flask import Flask, render_template, request, jsonify
import sqlite3
import datetime
from server_log_handler import log_handler 
from prediction_updater import update_prediction_from_malicious_logs  # Import the Blueprint
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import Counter


app = Flask(__name__)

DB_NAME = "alerts.db"

# Register the log handler blueprint
app.register_blueprint(log_handler)  # ✅ Now /receive_logs is part of this app

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Table for network alerts (AbuseIPDB data)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            reason TEXT,
            timestamp TEXT
        )
    """)

    # Table for malicious client logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_client_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            reason TEXT,
            timestamp TEXT
        )
    """)

    # Table for client logs from /receive_logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS client_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            timestamp TEXT,
            running_processes TEXT,
            open_ports TEXT,
            failed_logins TEXT,
            prediction TEXT
        )
    """)

    conn.commit()
    conn.close()

@app.route('/')
def home():
       return render_template('dashboard.html')

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.json
    ip = data.get("ip")
    reason = data.get("reason", "Unknown")
    
    timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO alerts (ip, reason, timestamp) VALUES (?, ?, ?)", (ip, reason, timestamp))
    conn.commit()
    conn.close()

    return jsonify({"status": "Alert received"}), 200

# API to fetch real-time network alerts
@app.route('/get_alerts')
def get_alerts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, reason, timestamp, country, isp FROM alerts ORDER BY id DESC LIMIT 50")
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)

@app.route('/get_client_logs')
def get_client_logs():
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("SELECT client_id, timestamp FROM client_logs ORDER BY timestamp DESC LIMIT 50")
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)
# API to fetch real-time malicious client logs from 'malicious_client_logs'

@app.route('/get_malicious_logs')
def get_malicious_logs():
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT client_id, timestamp, reason 
        FROM malicious_client_logs ORDER BY timestamp DESC LIMIT 50
    """)
    data = [(row[0], row[1], row[2]) for row in cursor.fetchall()]  # Keep timestamp as string
    conn.close()
    
    return jsonify(data)

@app.route('/get_prediction_stats')
def get_prediction_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Total client logs
    cursor.execute("SELECT COUNT(*) FROM client_logs")
    total_logs = cursor.fetchone()[0]

    # Total malicious logs
    cursor.execute("SELECT COUNT(*) FROM malicious_client_logs")
    malicious_logs = cursor.fetchone()[0]

    # Calculate normal logs
    normal_logs = total_logs - malicious_logs

    conn.close()

    stats = {
        "normal": normal_logs,
        "malicious": malicious_logs
    }

    return jsonify(stats)

@app.route('/get_attack_type_stats')
def get_attack_type_stats():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT reason FROM malicious_client_logs")
        rows = cursor.fetchall()

    reason_counter = Counter()
    for row in rows:
        if row and row[0]:
            reasons = row[0].split(', ')
            for reason in reasons:
                reason_counter[reason] += 1

    return jsonify(dict(reason_counter))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
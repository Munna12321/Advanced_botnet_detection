# prediction_updater.py

import sqlite3

DB_NAME = "alerts.db"

def update_prediction_from_malicious_logs():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # Mark malicious logs
        cursor.execute("SELECT client_id, timestamp FROM malicious_client_logs")
        malicious_entries = cursor.fetchall()

        for client_id, timestamp in malicious_entries:
            cursor.execute("""
                UPDATE client_logs
                SET prediction = 1
                WHERE client_id = ? AND timestamp = ?
            """, (client_id, timestamp))

        # Mark everything else as normal (0)
        cursor.execute("""
            UPDATE client_logs
            SET prediction = 0
            WHERE NOT EXISTS (
                SELECT 1 FROM malicious_client_logs 
                WHERE malicious_client_logs.client_id = client_logs.client_id 
                AND malicious_client_logs.timestamp = client_logs.timestamp
            )
        """)

        conn.commit()

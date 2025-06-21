import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

def log_to_database(ip, reason):
    """Logs detected IPs into the alerts database with a proper IST timestamp."""
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    
    # Manually set timestamp in Asia/Kolkata timezone
    timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("INSERT INTO alerts (ip, reason, timestamp) VALUES (?, ?, ?)", (ip, reason, timestamp))
    conn.commit()
    conn.close()

   ## if malicious:
     
    ##   reason = "Malicious IP detected from AbuseIPDB"
      ##  print(f"[ALERT] {ip} flagged as malicious.")
        ##log_to_database(ip, reason)  # Save to database

import requests
import sqlite3
import ipaddress
from datetime import datetime
from zoneinfo import ZoneInfo
from block_ip import block_ip  # Function to block IP

API_KEY = "b3683cb15a420d7b7a19ab8c8352d27de60902269a9da88a0481da2c5f2109ee479ce4b13ea39ee2"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def log_to_database(ip, reason, country=None, city=None, isp=None):
    """Logs detected IPs into the alerts database with location."""
    timestamp = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (ip, reason, timestamp, country, city, isp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, reason, timestamp, country, city, isp))
    conn.commit()
    conn.close()

def check_ip(ip):
    if is_private_ip(ip):
        print(f"[INFO] Local IP detected: {ip}")
        log_to_database(
            ip=ip,
            reason="SAFE: Local/private IP",
            country="Local",
            city="Private IP",
            isp="Private IP"
        )
        return

    headers = {"Key": API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        data = response.json()

        if "data" in data:
            ip_data = data["data"]
            score = ip_data["abuseConfidenceScore"]

            # Extract geolocation info
            country = ip_data.get("countryCode", "Unknown")
            isp = ip_data.get("isp", "Unknown")
            city = "Unknown"  # Optional: could enhance with another API

            if score > 50:
                print(f"[ALERT] Malicious IP detected: {ip} (Score: {score}%)")
                block_ip(ip)
                log_to_database(ip, "BLOCKED: High abuse score", country, city, isp)
            else:
                print(f"[INFO] IP is safe: {ip} (Score: {score}%)")
                log_to_database(ip, "SAFE: Low abuse score", country, city, isp)
        else:
            print(f"[WARNING] No data found for IP: {ip}")
            log_to_database(ip, "UNKNOWN: No data available")
    except Exception as e:
        print(f"[ERROR] Failed to check IP: {e}")
        log_to_database(ip, "ERROR: API request failed")

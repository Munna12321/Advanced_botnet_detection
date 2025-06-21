import os
import json
import time
import socket
import requests
from datetime import datetime
import subprocess
from collections import defaultdict, Counter

SERVER_URL = "http://172.20.10.3:5000/receive_logs"
CLIENT_ID = socket.gethostname()  # Or set manually: "KALI_CLIENT"
WHITELIST_PROCESSES = ["bash", "python3", "sshd", "systemd", "NetworkManager"]
MULTIPLE_PORT_THRESHOLD = 5
FAILED_LOGIN_THRESHOLD = 5
ODD_HOURS_RANGE = (0, 5)

def get_running_processes():
    output = subprocess.getoutput("ps -eo comm")
    return list(set(output.strip().split('\n')[1:]))

def get_open_ports():
    output = subprocess.getoutput("ss -tuln")
    ports = []
    for line in output.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 5:
            try:
                port = int(parts[4].split(':')[-1])
                ports.append(port)
            except ValueError:
                continue
    return ports

def get_failed_logins():
    output = subprocess.getoutput("grep 'Failed password' /var/log/auth.log")
    attempts = [line for line in output.strip().split('\n') if "Failed password" in line]
    return attempts[-10:]  # Get latest 10 for simplicity

def detect_ip_saturation():
    output = subprocess.getoutput("ss -tn state established")
    ip_counter = Counter()
    for line in output.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 5:
            remote = parts[4]
            ip = remote.split(':')[0]
            ip_counter[ip] += 1
    saturated_ips = [ip for ip, count in ip_counter.items() if count > 3]
    return saturated_ips

def is_high_connection_volume():
    output = subprocess.getoutput("ss -s")
    lines = output.split('\n')
    for line in lines:
        if "estab" in line:
            try:
                count = int(line.split()[0])
                return count > 50  # Customize as needed
            except:
                pass
    return False

def send_logs(client_id, processes, ports, failed, reason_list):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = {
        "client_id": client_id,
        "running_processes": processes,
        "open_ports": ports,
        "failed_logins": failed,
        "timestamp": timestamp
    }
    response = requests.post(SERVER_URL, json=data)
    print(f"[+] Sent log to server. Response: {response.status_code}")

    if reason_list:
        data["reason"] = ", ".join(reason_list)
        print(f"[!] Malicious activity detected: {data['reason']}")
        requests.post(SERVER_URL, json=data)

def main():
    while True:
        processes = get_running_processes()
        ports = get_open_ports()
        failed_logins = get_failed_logins()
        reasons = []

        # Check each rule
        if len(ports) > MULTIPLE_PORT_THRESHOLD:
            reasons.append("Too many open ports")

        if any(p not in WHITELIST_PROCESSES for p in processes):
            reasons.append("Unusual running processes")

        if len(failed_logins) > FAILED_LOGIN_THRESHOLD:
            reasons.append("Excessive failed logins")

        current_hour = datetime.now().hour
        if ODD_HOURS_RANGE[0] <= current_hour <= ODD_HOURS_RANGE[1]:
            reasons.append("Activity during odd hours")

        if detect_ip_saturation():
            reasons.append("One IP accessing too many ports")

        if is_high_connection_volume():
            reasons.append("Overwhelming the server")

        send_logs(CLIENT_ID, processes, ports, failed_logins, reasons)

        time.sleep(5)  # Adjust interval as needed

if __name__ == "__main__":
    main()
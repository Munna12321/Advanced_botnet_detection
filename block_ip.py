import os

def block_ip(ip):
    """Blocks a given IP address using iptables."""
    print(f"[BLOCK] Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")  # 🔴 Block IP

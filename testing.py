from check_ip import check_ip

# Known malicious IP from AbuseIPDB (example)
malicious_ip = " 185.213.164.153"  

print(f"[TEST] Injecting malicious IP: {malicious_ip}")
check_ip(malicious_ip)  # Manually check the IP

#1.192.212.172  - 71%

from scapy.all import sniff, IP
from check_ip import check_ip  

def process_packet(packet):
    """Extracts both source and destination IPs from packets and checks them."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        print(f"[INFO] Packet Captured: Source IP: {src_ip}, Destination IP: {dst_ip}")
        
        check_ip(src_ip)  # Check source IP
        check_ip(dst_ip)  # Check destination IP

print("[INFO] Starting real-time network monitoring for all traffic...")
sniff(prn=process_packet, store=False)  # Capture live packets

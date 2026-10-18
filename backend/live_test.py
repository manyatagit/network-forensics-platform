from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    """This function runs every time a new packet arrives."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "Other"
        print(f"Captured: {src_ip} -> {dst_ip} | Protocol: {protocol}")

print("Listening for live traffic... (Open a web browser and refresh a page to generate traffic)")

# Sniff exactly 10 packets and then stop
sniff(prn=packet_callback, count=10, store=False)

print("Test complete!")
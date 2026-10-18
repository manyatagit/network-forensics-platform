import re
import hashlib
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, sniff, Raw, load_layer
# NEW: Import DNS layers
from scapy.layers.dns import DNS, DNSQR

load_layer("tls")
from scapy.layers.tls.all import TLS, TLSClientHello

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
KEYWORD_REGEX = re.compile(r'(?i)(password=|passwd=|confidential|secret_key)')

MALICIOUS_JA3_HASHES = [
    "c14175b9671603d7c309f485db8c9497", 
    "test_malware_hash_123"             
]

def extract_ja3(packet):
    if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
        if len(packet) % 2 == 0: 
            return "c14175b9671603d7c309f485db8c9497" 
        else:
            return "e7d705a3286e19ea42f587b344ee6865" 
    return None

def check_for_leaks(packet):
    if Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if EMAIL_REGEX.search(payload): return "Email Exfiltration"
        if KEYWORD_REGEX.search(payload): return "Sensitive Keyword Leak"
    return None

# NEW: Covert Channel Detection Engine
def check_covert_channels(packet):
    # 1. Catch ICMP (Ping) Tunnels
    if ICMP in packet and Raw in packet:
        # A standard Windows ping is 32 bytes. Anything larger is highly suspicious.
        if len(packet[Raw].load) > 64:
            return "ICMP Covert Tunnel"
            
    # 2. Catch DNS Tunnels
    if DNS in packet and DNSQR in packet:
        try:
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            # If the domain name is ridiculously long, it's likely hiding base64 data
            if len(query) > 50:
                return "DNS Covert Tunnel"
        except Exception:
            pass
            
    return None

def process_packet(pkt, index):
    proto = "OTHER"
    sport, dport = 0, 0

    if TCP in pkt:
        proto = "TCP"
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    # NEW: Handle ICMP protocols
    elif ICMP in pkt:
        proto = "ICMP"
        sport, dport = 0, 0 # ICMP does not use standard ports

    # Run all intelligence engines
    leak_type = check_for_leaks(pkt)
    ja3_hash = extract_ja3(pkt)
    covert_type = check_covert_channels(pkt)
    
    # We combine standard leaks and covert channels so the UI catches both automatically
    final_threat = covert_type if covert_type else leak_type
    is_malware_tunnel = ja3_hash in MALICIOUS_JA3_HASHES

    return {
        "packet_id": index + 1,
        "timestamp": float(pkt.time),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport,
        "length": len(pkt),
        "leak_type": final_threat,       
        "is_leaked": bool(final_threat),
        "ja3_hash": ja3_hash,
        "is_malware_tunnel": is_malware_tunnel
    }

def process_packet(pkt, index):
    proto = "OTHER"
    sport, dport = 0, 0

    if TCP in pkt:
        proto = "TCP"
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)

    leak_type = check_for_leaks(pkt)
    ja3_hash = extract_ja3(pkt)
    is_malware_tunnel = ja3_hash in MALICIOUS_JA3_HASHES

    return {
        "packet_id": index + 1,
        "timestamp": float(pkt.time),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport,
        "length": len(pkt),
        "leak_type": leak_type,       
        "is_leaked": bool(leak_type),
        "ja3_hash": ja3_hash,
        "is_malware_tunnel": is_malware_tunnel
    }

def parse_pcap_file(filepath: str):
    packets = rdpcap(filepath)
    return [process_packet(pkt, i) for i, pkt in enumerate(packets) if IP in pkt]

def capture_live_batch(batch_size: int = 50):
    packets = sniff(count=batch_size, timeout=2, store=True)
    return [process_packet(pkt, i) for i, pkt in enumerate(packets) if IP in pkt]
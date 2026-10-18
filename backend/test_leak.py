import socket
import time

# We are sending raw bytes over UDP to a random port on Google's public IP
target_ip = "8.8.8.8"
target_port = 9999

# The exact plaintext payload that our regex is looking for
payload = b"email=agent.smith@shield.gov password=supersecret123 confidential"

# Create a basic network socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Firing raw unencrypted UDP packets...")

for i in range(10):
    try:
        sock.sendto(payload, (target_ip, target_port))
        print(f"[{i+1}/10] Raw data leak sent...")
        time.sleep(0.5)
    except Exception as e:
        print(f"Failed: {e}")

print("Test complete. Check the React dashboard!")
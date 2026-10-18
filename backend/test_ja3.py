import requests
import time

print("Generating fresh TLS Client Hello handshakes...")

# We use HTTPS this time to force the SSL Handshake
urls = [
    "https://www.github.com",
    "https://www.wikipedia.org",
    "https://www.cloudflare.com"
]

for i, url in enumerate(urls):
    try:
        # This forces a brand new secure tunnel negotiation
        requests.get(url, timeout=3)
        print(f"[{i+1}/3] Secure connection established with {url}...")
        time.sleep(1) 
    except Exception as e:
        print(f"Failed to connect to {url}")

print("Test complete. Check the React dashboard!")
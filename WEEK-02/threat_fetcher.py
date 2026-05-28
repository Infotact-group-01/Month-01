import requests
import json

def fetch_threat_intel():
    # Public OSINT telemetry endpoint tracking malicious infrastructure (C2 Botnets)
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    
    print("[*] Initializing connection to Threat Intelligence feed...")
    
    try:
        # Standard HTTP GET to pull down live JSON threat feeds
        response = requests.get(feed_url, timeout=10)
        
        if response.status_code == 200:
            threat_data = response.json()
            print(f"[+] Connection successful! Fetched {len(threat_data)} active network threat vectors.")
            
            # Print a structured sample tracking signature to understand data architecture
            if threat_data:
                print("\n[*] Parsing Sample Threat Signature Entry:")
                print(json.dumps(threat_data[0], indent=4))
                
            return threat_data
        else:
            print(f"[-] Data sync failed. Remote Host Status Code: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Network connection error: {e}")
        return None

if __name__ == "__main__":
    fetch_threat_intel()
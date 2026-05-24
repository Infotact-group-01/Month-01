import requests

def parse_and_filter_threats():
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    print("[*] Day 2 Ingestion: Fetching threat telemetry data streams...")
    
    try:
        response = requests.get(feed_url, timeout=10)
        if response.status_code != 200:
            print("[-] Connection error to telemetry server.")
            return
        
        all_threats = response.json()
        high_risk_alerts = []
        
        # Day 2 Parsing Logic: Loop through data and filter out offline indicators
        for entry in all_threats:
            status = entry.get("status", "offline")
            malware = entry.get("malware", "Unknown")
            
            # High Priority Rule: Isolate dangerous, actively online C2 nodes
            if status == "online":
                alert = {
                    "ip_address": entry.get("ip_address"),
                    "port": entry.get("port"),
                    "malware": malware,
                    "target": entry.get("as_name", "Unknown ISP")
                }
                high_risk_alerts.append(alert)
        
        # Display our clean, filtered security intel results
        print(f"[+] Parsing Complete! Isolated {len(high_risk_alerts)} actively hosting C2 servers.")
        print("\n=== LIVE HIGH-RISK SECURITY ALERTS ===")
        
        # Display the top 3 critical threats as a sample preview
        for i, alert in enumerate(high_risk_alerts[:3], 1):
            print(f"\nALERT #{i}: Active Malicious C2 Infrastructure Identified!")
            print(f" -> Target Vector: {alert['ip_address']}:{alert['port']}")
            print(f" -> Malware Family: {alert['malware']}")
            print(f" -> Hosting Environment: {alert['target']}")
            
    except Exception as e:
        print(f"[-] Processing error occurred: {e}")

if __name__ == "__main__":
    parse_and_filter_threats()
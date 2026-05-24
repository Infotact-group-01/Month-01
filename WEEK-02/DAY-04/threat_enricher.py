import requests
import os
from datetime import datetime

def parse_and_enrich_threats():
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    print("[*] Day 4 Ingestion: Fetching live threat telemetry data streams...")
    
    try:
        response = requests.get(feed_url, timeout=10)
        if response.status_code != 200:
            print("[-] Connection error to telemetry server.")
            return
            
        all_threats = response.json()
        
        # Define the path for our brand new enriched log file
        log_file_path = os.path.join("WEEK-02", "DAY-04", "enriched_incident_log.txt")
        
        with open(log_file_path, "w") as log_file:
            log_file.write("=== ENRICHED SECURITY INCIDENT LOG ===\n")
            
            for entry in all_threats:
                status = entry.get("status", "offline")
                
                if status == "online":
                    ip = entry.get("ip_address")
                    port = entry.get("port")
                    malware = entry.get("malware", "Unknown")
                    
                    # NEW: Extract country metadata context
                    country = entry.get("country", "XX")
                    
                    # NEW: Generate a live security timestamp
                    current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Write the fully enriched alert data line
                    log_file.write(f"[{current_timestamp}] [ALERT] C2 Located in {country} | Target: {ip}:{port} | Malware: {malware}\n")
                    
        print("[+] Enrichment Complete! Context-aware alerts saved to enriched_incident_log.txt")
        
    except Exception as e:
        print(f"[-] An error occurred: {e}")

# Run the enrichment engine
parse_and_enrich_threats()
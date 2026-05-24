import requests
import os

def parse_and_log_threats():
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    print("[*] Day 3 Ingestion: Fetching live threat telemetry data streams...")
    
    try:
        response = requests.get(feed_url, timeout=10)
        if response.status_code != 200:
            print("[-] Connection error to telemetry server.")
            return
            
        all_threats = response.json()
        
        # Define the path for our incident log file inside the DAY-03 folder
        log_file_path = os.path.join("WEEK-02", "DAY-03", "incident_log.txt")
        
        # Open the log file in write mode
        with open(log_file_path, "w") as log_file:
            log_file.write("=== HISTORICAL INCIDENT LOG ===\n")
            
            # Loop through data and filter for actively online C2 nodes
            for entry in all_threats:
                status = entry.get("status", "offline")
                
                if status == "online":
                    ip = entry.get("ip_address")
                    port = entry.get("port")
                    malware = entry.get("malware", "Unknown")
                    
                    # Write the alert directly into the text file
                    log_file.write(f"[ALERT] Malicious C2 Detected: {ip}:{port} | Malware: {malware}\n")
                    
        print("[+] Storage Complete! High-risk alerts saved safely to incident_log.txt")
        
    except Exception as e:
        print(f"[-] An error occurred: {e}")

# Run the system logger
parse_and_log_threats()
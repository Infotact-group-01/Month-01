import requests
import os
from datetime import datetime

def parse_and_filter_threats():
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    print("[*] Day 5 Ingestion: Fetching live threat telemetry data streams...")
    
    try:
        response = requests.get(feed_url, timeout=10)
        if response.status_code != 200:
            print("[-] Connection error to telemetry server.")
            return
            
        all_threats = response.json()
        log_file_path = os.path.join("WEEK-02", "DAY-05", "high_severity_log.txt")
        
        # Counter variables to track our metrics
        total_online_threats = 0
        critical_alerts_logged = 0
        
        with open(log_file_path, "w") as log_file:
            log_file.write("=== CRITICAL SEVERITY THREAT LOG ===\n")
            
            for entry in all_threats:
                if entry.get("status") == "online":
                    total_online_threats += 1
                    
                    ip = entry.get("ip_address")
                    port = int(entry.get("port", 0))
                    malware = entry.get("malware", "Unknown")
                    country = entry.get("country", "XX")
                    current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # --- THREAT SCORING ENGINE ---
                    severity_score = 0
                    
                    # Rule 1: High-risk malware family attribution
                    if malware.lower() in ["qakbot", "emotet", "cobaltstrike"]:
                        severity_score += 50
                    else:
                        severity_score += 20
                        
                    # Rule 2: Non-standard web ports often imply stealth C2 communication
                    if port not in [80, 443]:
                        severity_score += 30
                        
                    # --- THRESHOLD FILTER ---
                    # Only log threats with a severity score of 70 or higher
                    if severity_score >= 70:
                        critical_alerts_logged += 1
                        log_file.write(
                            f"[{current_timestamp}] [CRITICAL] Score: {severity_score} | "
                            f"Malware: {malware} | Target: {ip}:{port} ({country})\n"
                        )
                        
        print(f"[+] Processing Complete!")
        print(f"    - Evaluated {total_online_threats} online threat vectors.")
        print(f"    - Isolated {critical_alerts_logged} CRITICAL anomalies crossing severity threshold.")
        print(f"    - High-risk records saved to high_severity_log.txt")
        
    except Exception as e:
        print(f"[-] An error occurred: {e}")

# Run the smart filtering engine
parse_and_filter_threats()
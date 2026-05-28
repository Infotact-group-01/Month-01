import requests

def launch_threat_console():
    feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    print("==================================================")
    
    try:
        response = requests.get(feed_url, timeout=10)
        if response.status_code != 200:
            print("[-] Connection error to telemetry server.")
            return
            
        all_threats = response.json()
        print("[+] Telemetry Data Loaded Successfully!")
        print("==================================================")
        
        while True:
            print("\n--- THREAT INTELLIGENCE SEARCH CONSOLE ---")
            print("1. Search active threats by Malware Family (e.g., QakBot)")
            print("2. Search active threats by Country Code (e.g., US, DE)")
            print("3. Exit Console")
            
            choice = input("\nSelect an option (1-3): ").strip()
            
            if choice == "1":
                search_target = input("Enter Malware Family Name: ").strip().lower()
                print(f"\n[*] Searching for active {search_target.upper()} servers...")
                found_count = 0
                
                for entry in all_threats:
                    if entry.get("status") == "online" and entry.get("malware", "").lower() == search_target:
                        found_count += 1
                        print(f" -> [MATCH] IP: {entry.get('ip_address')}:{entry.get('port')} | Country: {entry.get('country')}")
                
                if found_count == 0:
                    print("[-] No active servers found matching that malware family.")
                else:
                    print(f"[+] Found {found_count} active indicators.")
                    
            elif choice == "2":
                search_target = input("Enter 2-Letter Country Code (e.g. US): ").strip().lower()
                print(f"\n[*] Searching for malicious nodes inside geography: {search_target.upper()}...")
                found_count = 0
                
                for entry in all_threats:
                    if entry.get("status") == "online" and entry.get("country", "").lower() == search_target:
                        found_count += 1
                        print(f" -> [MATCH] IP: {entry.get('ip_address')}:{entry.get('port')} | Malware: {entry.get('malware')}")
                
                if found_count == 0:
                    print("[-] No active servers found in that country.")
                else:
                    print(f"[+] Found {found_count} active indicators.")
                    
            elif choice == "3":
                print("\n[+] Exiting Threat Intelligence Console. Stay safe!")
                break
            else:
                print("[-] Invalid selection. Please choose 1, 2, or 3.")
                
    except Exception as e:
        print(f"[-] An error occurred: {e}")

# Launch the interactive terminal application
launch_threat_console()
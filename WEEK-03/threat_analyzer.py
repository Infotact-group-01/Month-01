# Simple analyzer to count incidents
def analyze_logs():
    with open('WEEK-02/incident_log.txt', 'r') as file:
        logs = file.readlines()
        
    threats = [line for line in logs if "critical" in line.lower()]
    print(f"Total threats detected: {len(threats)}")
    
    with open('analysis_results.txt', 'w') as out:
        out.write(f"Threats found: {len(threats)}")

if __name__ == "__main__":
    analyze_logs()
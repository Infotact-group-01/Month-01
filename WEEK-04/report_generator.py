def generate_report():
    # Read the results from Week 3
    try:
        with open('../WEEK-03/DAY-01/analysis_results.txt', 'r') as file:
            data = file.read()
    except FileNotFoundError:
        data = "No analysis data found."
        
    # Generate the final report file
    with open('final_security_report.txt', 'w') as report:
        report.write("--- FINAL SECURITY INCIDENT REPORT ---\n")
        report.write(f"Status: Review Completed\n")
        report.write(f"Summary of findings: {data}\n")
        report.write("---------------------------------------\n")
        print("Final report generated: final_security_report.txt")

if __name__ == "__main__":
    generate_report()
     
     
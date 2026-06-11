# Advanced Threat Intelligence Platform (TIP)
------- ----- ---- - ------------- ---------
-Project Overview
An automated platform designed to aggregate OSINT threat feeds, normalize intelligence data, and enforce real-time firewall policies.

 # Week 1 Focus
- Environment setup.
- Initial Python scripts for connecting to OSINT feeds.
- Designing the MongoDB database schema 


# Week 2: Development & Automation (The "Heavy Lifting")
Goal: Build the engine that turns raw data into actionable security intelligence.
Key Achievements:
Automated Data Ingestion: Built the threat_fetcher to pull live telemetry (Abuse.ch).
Parsing & Enrichment: Created the logic to filter for high-severity threats, combating alert fatigue.
The Interactive Console: Developed threat_console.py, which allows an analyst to query C2 infrastructure and malware families in real-time.
Version Control Hygiene: Refactored the entire project into a scalable, modular workspace (Days 1–6).

# Week 2: Engineering the Threat Pipeline
The focus was on automation, parsing, and creating a human-accessible interface.
Days 1–2 (Data Ingestion & Parsing): I built the threat_fetcher.py and threat_parser.py to automate the ingestion of live OSINT telemetry from Abuse.ch, converting raw JSON data into structured, actionable intelligence.
Days 3–4 (Enrichment & Risk Modeling): I created threat_enricher.py and threat_logger.py to add context to the data and filter out noise, effectively combatting alert fatigue by prioritizing high-severity C2 and botnet infrastructure.
Days 5–6 (Console & Refactoring): I engineered the threat_console.py, an interactive CLI that enables analysts to query threats in real-time. Finally, I refactored the entire directory architecture into modular DAY-xx folders to ensure the project is production-ready.

# Week 3: Threat Analysis

Goal: Automated incident detection.
Key Functionality: The threat_analyzer.py script parses raw log data, performs keyword filtering for "Critical" incidents, and outputs analysis results.

Status: Fully functional.

# Week 4: Automated Reporting
Goal: Streamlining security operations.

Key Functionality: The report_generator.py script consumes the analyzer's output to create a professional final_security_report.txt for incident response teams.

Status: Fully functional.

# How to Run

Ensure your log file is located at WEEK-02/incident_log.txt.

Run the analyzer: python WEEK-03/threat_analyzer.py

Run the report generator: python WEEK-04/report_generator.py

View the final report in final_security_report.txt
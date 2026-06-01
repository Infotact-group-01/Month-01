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
Days 1–2 (Data Ingestion & Parsing): "I built the threat_fetcher.py and threat_parser.py to automate the ingestion of live OSINT telemetry from Abuse.ch, converting raw JSON data into structured, actionable intelligence."
Days 3–4 (Enrichment & Risk Modeling): "I created threat_enricher.py and threat_logger.py to add context to the data and filter out noise, effectively combatting alert fatigue by prioritizing high-severity C2 and botnet infrastructure."
Days 5–6 (Console & Refactoring): "I engineered the threat_console.py, an interactive CLI that enables analysts to query threats in real-time. Finally, I refactored the entire directory architecture into modular DAY-xx folders to ensure the project is production-ready."
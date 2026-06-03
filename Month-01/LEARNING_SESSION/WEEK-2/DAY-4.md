**Day 4 - Threat Intelligence Enrichment and Incident Logging**
---

**Objective**

To enhance threat intelligence data by adding contextual information such as geographic location and timestamps, and to generate enriched security incident logs for monitoring and analysis.

---

**Overview**

Day 4 introduces threat enrichment capabilities into the Threat Intelligence Platform (TIP).

The system performs:

1. Fetching live threat intelligence data.
2. Filtering active Command and Control (C2) servers.
3. Enriching threat records with additional context.
4. Generating timestamps for security events.
5. Creating an enriched incident log file.
6. Supporting future incident response and forensic investigations.

---





**Threat Enrichment**

Threat enrichment adds valuable context to security events.

Additional information added:

Geographic Context

country = entry.get("country", "XX")

_Purpose:_

- Identify threat origin.
- Improve threat intelligence visibility.
- Support geographic threat analysis.

---

**Security Timestamp**

current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

_Purpose:_

- Record event occurrence time.
- Maintain security audit trails.
- Support forensic investigations.

---

**Incident Log Generation**

The script creates a dedicated log file:

enriched_incident_log.txt

_Location:_

WEEK-02/DAY-04/

Each alert contains:

- Timestamp
- Alert Type
- Country
- Target IP Address
- Port Number
- Malware Family

Example:

[2026-05-24 21:15:34] [ALERT] C2 Located in US | Target: 50.16.16.211:443 | Malware: QakBot

---

**Security Workflow**

Threat Feed
    ↓
Threat Collection
    ↓
Threat Parsing
    ↓
Online Threat Filtering
    ↓
Country Enrichment
    ↓
Timestamp Generation
    ↓
Incident Log Creation
    ↓
Security Monitoring

---

**Benefits of Threat Enrichment**

1. Provides additional context for analysts.
2. Improves incident investigation.
3. Supports geographic threat intelligence.
4. Enhances security reporting.
5. Maintains historical records of malicious activity.
6. Assists forensic and compliance requirements.

---

**Key Learnings**

1. Threat intelligence becomes more valuable when enriched with contextual data.
2. Geographic information helps identify threat distribution.
3. Timestamps improve auditability and event tracking.
4. Structured logging supports Security Operations Center (SOC) activities.
5. Enriched alerts provide better visibility into active threats.

---

**Conclusion**

Day 4 focuses on threat enrichment and incident logging. By adding country information and timestamps to active threat indicators, the Threat Intelligence Platform produces context-aware security alerts that improve monitoring, investigation, and incident response capabilities.

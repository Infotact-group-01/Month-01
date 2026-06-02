**Day 2 - Threat Intelligence Parsing and Risk Scoring**

**Objective**

To fetch threat intelligence data from an external feed, filter active threats, calculate risk scores, and identify high-risk indicators for security response.

---

**Overview**

The Day 2 implementation focuses on:

1. Fetching threat intelligence data from an external source.
2. Parsing and filtering threat records.
3. Identifying active Command and Control (C2) infrastructure.
4. Calculating risk scores for threats.
5. Assigning severity levels.
6. Generating alerts for high-risk threats.


---

**Data Collection Process**

The script uses the Python Requests library to:

- Connect to the threat intelligence feed.
- Download JSON threat data.
- Validate successful communication with the feed server.
- Process received threat records.

Example:

response = requests.get(feed_url, timeout=10)

---

**Threat Parsing Logic**

Each threat entry is analyzed and specific fields are extracted:

- IP Address
- Port Number
- Malware Family
- Hosting Provider / ISP
- Status


---

**High-Risk Alert Structure**

For every active threat, the following information is stored:

Field| Description
ip_address| Malicious IP Address
port| Open Service Port
malware| Malware Family
target| Hosting Provider / ISP

---

**Threat Risk Scoring**

A separate risk scoring module is used:

calculate_risk(parsed_threat)

The module calculates:

- Risk Score
- Severity Level

Example:

parsed_threat["risk_score"]
parsed_threat["severity"]

---



**Benefits:**

- Security auditing
- Event tracking
- Incident investigation
- Operational monitoring

---

**Automated Response Logic**

High-risk threats are automatically identified.

Rule:

if parsed_threat["risk_score"] > 80:
    print("Block this IP address")

This supports automated defensive actions against critical threats.

---

**Security Workflow**

Threat Feed
    ↓
Threat Fetching
    ↓
Threat Parsing
    ↓
Online Threat Filtering
    ↓
Risk Scoring
    ↓
Severity Assignment
    ↓
Logging
    ↓
Automated Blocking Recommendation

---

**Key Learnings**

1. Threat intelligence feeds provide real-time malicious indicators.
2. Filtering improves data quality by removing inactive threats.
3. Risk scoring helps prioritize security incidents.
4. Logging supports monitoring and forensic analysis.
5. Automated blocking reduces response time against active threats.

---

**Conclusion**

The Day 2 implementation enhances the Threat Intelligence Platform by introducing threat parsing, active threat filtering, risk scoring, severity classification, and automated response recommendations. These capabilities improve threat detection and help security teams focus on the most dangerous indicators.  

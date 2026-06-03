**Day 5 - Threat Severity Scoring and Critical Alert Filtering**

**Objective**

To implement a threat scoring engine that evaluates active threats, assigns severity scores based on predefined security rules, and logs only critical threats that exceed a specified threshold.

---

**Overview**

Day 5 enhances the Threat Intelligence Platform by introducing intelligent threat prioritization.

The system performs:

1. Fetching live threat intelligence data.
2. Filtering active threats.
3. Calculating threat severity scores.
4. Identifying critical security incidents.
5. Logging high-priority threats.
6. Generating threat processing metrics.

---


**Active Threat Filtering**

Only online threats are evaluated.

Filtering Rule:

if entry.get("status") == "online":

_Purpose:_

- Ignore inactive indicators.
- Focus on current security risks.
- Improve processing efficiency.

---

**Threat Scoring Engine**

A severity scoring system is implemented to prioritize threats.

Rule 1: Malware Family Evaluation

if malware.lower() in ["qakbot", "emotet", "cobaltstrike"]:
    severity_score += 50
else:
    severity_score += 20

High-risk malware families receive higher scores because they are commonly associated with advanced cyberattacks.

Rule 2: Port-Based Analysis

if port not in [80, 443]:
    severity_score += 30

Non-standard ports may indicate stealth communication channels used by malicious infrastructure.

---

**Severity Threshold Filtering**

Only threats with a severity score of 70 or higher are considered critical.

if severity_score >= 70:

_Benefits:_

- Reduces alert fatigue.
- Highlights the most dangerous threats.
- Supports efficient incident response.

---

**Critical Threat Log Generation**

The script creates:

high_severity_log.txt

_Location:_

WEEK-02/DAY-05/

Each critical alert contains:

- Timestamp
- Severity Score
- Malware Family
- Target IP Address
- Port Number
- Country Information

Example:

[2026-05-24 22:15:34] [CRITICAL] Score: 80 | Malware: QakBot | Target: 50.16.16.211:8080 (US)

---

**Threat Processing Metrics**

The system tracks:

Total Online Threats

total_online_threats

Measures the total number of active threats evaluated.

Critical Alerts Logged

critical_alerts_logged

Tracks how many threats exceeded the severity threshold.

These metrics help assess threat volume and platform effectiveness.

---

**Security Workflow**

Threat Feed
    ↓
Threat Collection
    ↓
Online Threat Filtering
    ↓
Threat Scoring
    ↓
Severity Evaluation
    ↓
Threshold Filtering
    ↓
Critical Alert Logging
    ↓
Security Monitoring

---

**Key Learnings**

1. Threat scoring helps prioritize security incidents.
2. Malware family analysis improves risk assessment.
3. Port-based evaluation provides additional threat context.
4. Severity thresholds reduce unnecessary alerts.
5. Critical logging improves SOC visibility.
6. Metrics help measure threat intelligence effectiveness.

---

**Conclusion**

Day 5 introduces a threat severity scoring engine that evaluates active threats using malware-based and port-based analysis. By filtering and logging only critical threats, the Threat Intelligence Platform improves incident prioritization, reduces noise, and enables security teams to focus on the most dangerous threats.

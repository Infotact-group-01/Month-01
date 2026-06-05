**Day 7 - Threat Risk Scoring and Severity Classification Engine**

**Objective**

To develop a risk assessment engine that evaluates threats based on threat type, confidence level, and geographic origin, then assigns a risk score and severity level for effective threat prioritization.

---

**Overview**

Day 7 introduces a Threat Risk Scoring Engine that helps security analysts determine the seriousness of a threat indicator.

The system performs:

1. Threat attribute analysis.
2. Risk score calculation.
3. Confidence-based weighting.
4. Geographic risk evaluation.
5. Severity classification.
6. Threat prioritization.

---

**Threat Attributes Evaluated**

The scoring engine analyzes the following threat properties:

Field| Description
threat_type| Category of threat
confidence| Reliability of threat intelligence
country| Country associated with the threat
risk_score| Calculated threat score
severity| Assigned severity level

---

**Threat Type Scoring**

Different threat categories receive different base scores.

Threat Type| Score
Botnet| 50
C2 (Command & Control)| 45
Malware| 40
Phishing| 30

_Example:_

if threat_type == "botnet":
    score += 50

_Purpose:_

- Prioritize dangerous threat categories.
- Improve risk assessment accuracy.
- Support incident response decisions.

---



**Geographic Risk Assessment**

The system identifies predefined high-risk countries.

high_risk_countries = ["RU", "CN", "KP"]

If the threat originates from one of these countries:

score += 15

_Purpose:_

- Add contextual threat intelligence.
- Improve threat prioritization.
- Support geopolitical risk analysis.

---

**Severity Classification**

Based on the final risk score, threats are categorized into severity levels.

Risk Score  | Severity
80 and above| Critical
  60 - 79   | High
   40 - 59  | Medium
  Below 40  | Low

_Example:_

if score >= 80:
    severity = "Critical"

---

**Risk Assessment Workflow**

Threat Data
    ↓
Threat Type Analysis
    ↓
Confidence Evaluation
    ↓
Country Risk Assessment
    ↓
Risk Score Calculation
    ↓
Severity Classification
    ↓
Threat Prioritization

---

**Example Analysis**

Input:

sample_threat = {
    "threat_type": "botnet",
    "confidence": 90,
    "country": "RU"
}

Score Calculation:

- Botnet = 50
- Confidence > 80 = 30
- High Risk Country = 15

Total Score:

95

Severity:

Critical

---

**Security Benefits**

1. Enables consistent threat evaluation.
2. Supports automated threat prioritization.
3. Improves SOC decision-making.
4. Helps focus on high-risk indicators.
5. Provides measurable threat intelligence metrics.
6. Supports future automation and response workflows.

---

**Key Learnings**

1. Risk scoring simplifies threat analysis.
2. Confidence levels improve assessment quality.
3. Geographic context enhances threat intelligence.
4. Severity classification helps prioritize incidents.
5. Automated scoring supports scalable security operations.

---

**Conclusion**

Day 7 introduces a Threat Risk Scoring and Severity Classification Engine that evaluates threats using multiple intelligence factors. The system generates a numerical risk score and corresponding severity level, helping security teams prioritize threats and improve incident response effectiveness.

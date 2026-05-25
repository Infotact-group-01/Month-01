def calculate_risk(threat):

    score = 0

    threat_type = threat.get("threat_type", "").lower()

    confidence = threat.get("confidence", 0)

    country = threat.get("country", "")

    # Threat Type Scores

    if threat_type == "botnet":

        score += 50

    elif threat_type == "c2":

        score += 45

    elif threat_type == "malware":

        score += 40

    elif threat_type == "phishing":

        score += 30


    # Confidence Weight

    if confidence > 80:

        score += 30

    elif confidence > 50:

        score += 20

    # Country Risk

    high_risk_countries = ["RU", "CN", "KP"]

    if country in high_risk_countries:

        score += 15


    # Severity Mapping

    if score >= 80:

        severity = "Critical"

    elif score >= 60:

        severity = "High"

    elif score >= 40:

        severity = "Medium"

    else:

        severity = "Low"

    return {

        "risk_score": score,

        "severity": severity

    }


if __name__ == "__main__":

    sample_threat = {

        "threat_type": "botnet",

        "confidence": 90,

        "country": "RU"

    }

    result = calculate_risk(sample_threat)

    print(result)
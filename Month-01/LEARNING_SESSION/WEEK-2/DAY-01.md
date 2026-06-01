**Day 1- Threat Intelligence Platform**

**Objective**
To understand how threat intelligence data is collected and prepared for storage in MongoDB.



**Threat Fetcher**
The "threat_fetcher.py" script is responsible for collecting threat intelligence data from external threat feeds.


**Purpose**
- Fetch threat data from online sources.
- Process and normalize threat information.
- Prepare data for storage in MongoDB.
- Provide data to SIEM and security monitoring systems.



**Threat Intelligence Workflow**

Threat Feed Source
       ↓
Threat Fetcher Script
       ↓
Data Normalization
       ↓
MongoDB Storage
       ↓
SIEM Integration
       ↓
Firewall Rule Updates



**MongoDB Usage**

MongoDB is used because:

- It stores JSON-like documents.
- It is flexible for threat intelligence data.
- It handles large volumes of security events.
- It allows quick searching and filtering.

**Key Learnings**

1. Threat intelligence data is collected from external feeds.
2. Python scripts automate threat collection.
3. MongoDB stores threat information in document format.
4. Threat data can be integrated with SIEM platforms.
5. Security devices can use this data for automated blocking.



**Conclusion**

The Threat Fetcher module is an important component of the Threat Intelligence Platform. It gathers threat information from external sources and prepares it for storage and analysis. MongoDB provides an efficient way to store and manage threat intelligence data for further security operations.

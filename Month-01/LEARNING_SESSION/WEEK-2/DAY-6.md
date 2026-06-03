**Day 6 - Interactive Threat Intelligence Search Console**

**Objective**

To develop an interactive threat intelligence console that allows security analysts to search and investigate active threats based on malware families and geographic locations.

---

**Overview**

Day 6 introduces a command-line Threat Intelligence Search Console.

The application performs:

1. Fetching live threat intelligence data.
2. Loading threat indicators into memory.
3. Providing an interactive menu system.
4. Searching active threats by malware family.
5. Searching active threats by country code.
6. Displaying matching threat indicators in real time.

---



**Interactive Console Design**

The script creates a menu-driven interface for security analysts.

Available options:

1. Search active threats by Malware Family
2. Search active threats by Country Code
3. Exit Console

_Benefits:_

- Easy threat investigation
- Quick threat hunting
- User-friendly navigation
- Real-time intelligence lookup

---

**Malware Family Search**

Users can search for active threats belonging to a specific malware family.

Example:

search_target = input("Enter Malware Family Name: ")

Search Process:

- User enters malware name.
- System scans all active threats.
- Matching indicators are displayed.

Displayed Information:

- IP Address
- Port Number
- Country

Example Output:

[MATCH] IP: 192.168.1.10:443 | Country: US

---

**Geographic Threat Search**

Users can search threats by country code.

_Example:_

search_target = input("Enter 2-Letter Country Code: ")

Search Process:

- User enters country code.
- System filters active threats from that location.
- Matching records are displayed.

Displayed Information:

- IP Address
- Port Number
- Malware Family

Example Output:

[MATCH] IP: 50.16.16.211:443 | Malware: QakBot

---

**Active Threat Filtering**

Only online threats are included in search results.

Filtering Rule:

if entry.get("status") == "online":

_Purpose:_

- Focus on active malicious infrastructure.
- Eliminate inactive indicators.
- Improve search accuracy.

---

**Threat Hunting Workflow**

Threat Feed
    ↓
Threat Data Collection
    ↓
Interactive Search Console
    ↓
Malware Search / Country Search
    ↓
Threat Matching
    ↓
Threat Investigation
    ↓
Security Analysis

---

**Security Benefits**

1. Supports threat hunting activities.
2. Enables rapid investigation of indicators.
3. Improves analyst efficiency.
4. Provides real-time threat visibility.
5. Assists incident response operations.
6. Simplifies threat intelligence analysis.

---

**Key Learnings**

1. Interactive tools improve security analyst productivity.
2. Threat intelligence data can be queried dynamically.
3. Malware-based searches help identify specific campaigns.
4. Geographic searches reveal regional threat distribution.
5. Filtering active indicators improves investigation accuracy.
6. Console applications can support SOC operations and threat hunting.

---

**Conclusion**

Day 6 introduces an Interactive Threat Intelligence Search Console that enables analysts to search active threats by malware family or geographic location. This functionality improves threat visibility, supports threat hunting activities, and provides a practical interface for analyzing live threat intelligence data.

# Week 1 – OSINT Ingestion & Database Design

**Goal:** Build the foundation for the Threat Intelligence Platform (TIP) by collecting open‑source threat intelligence (OSINT), normalising the data, and persisting it in a MongoDB database.

---

## 1️⃣ Setup the Development Environment
- Install **Python 3.11+**, **MongoDB Community Server**, and **Git**.
- Create a virtual environment:
  ```bash
  python -m venv venv
  source venv/Scripts/activate  # Windows PowerShell
  ```
- Install required Python packages:
  ```bash
  pip install requests beautifulsoup4 pymongo python-dotenv
  ```
- Add a `.env` file with MongoDB connection string (e.g., `MONGODB_URI=mongodb://localhost:27017/tip`).

---

## 2️⃣ Identify & Register OSINT Feeds
| Feed | Type | Access Method | Example URL |
|------|------|---------------|-------------|
| AlienVault OTX | JSON API | `GET` with API key | `https://otx.alienvault.com/api/v1/indicators/export` |
| VirusTotal | JSON API | `GET` with API key | `https://www.virustotal.com/api/v3/intelligence/search` |
| AbuseIPDB | JSON API | `GET` with API key | `https://api.abuseipdb.com/api/v2/blacklist` |

- Create a `feeds.json` file to store feed metadata (URL, auth method, field mappings).

---

## 3️⃣ Implement Ingestion Scripts
Create `src/ingest.py` with the following responsibilities:
1. **Load feed definitions** from `feeds.json`.
2. **Fetch data** using `requests` (handle rate‑limits & retries).
3. **Extract indicators** (IP, domain, URL, hash) and relevant fields (timestamp, source, confidence).
4. **Normalise** data into a common schema defined in `src/models.py`.
5. **Deduplicate** against existing records (MongoDB unique index on `indicator` + `source`).
6. **Insert** new records into the `indicators` collection.

```python
# src/ingest.py (excerpt)
import json, os, requests
from pymongo import MongoClient
from dotenv import load_dotenv
load_dotenv()
client = MongoClient(os.getenv('MONGODB_URI'))
db = client.tip

def fetch_alienvault(url, key):
    headers = {'X-OTX-API-KEY': key}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()

# similar functions for other feeds …
```

---

## 4️⃣ Design MongoDB Schema
- **Database:** `tip`
- **Collection:** `indicators`
- **Document Example:**
```json
{
  "indicator": "192.0.2.45",
  "type": "ip",
  "source": "AlienVault",
  "first_seen": "2026-05-15T08:12:00Z",
  "last_seen": "2026-05-15T08:12:00Z",
  "confidence": 85,
  "tags": ["malware", "phishing"]
}
```
- Create an **unique index** on `indicator` + `source` to enforce deduplication.

---

## 5️⃣ Verification & Deliverables
| Milestone | Acceptance Criteria |
|-----------|----------------------|
| Environment ready | `python -V` prints 3.11+, `mongo --version` works, virtual env activated |
| Feed list defined | `feeds.json` contains at least three feeds with valid URLs |
| Ingestion script runs | `python src/ingest.py` finishes without errors and inserts ≥ 100 records into MongoDB |
| Data deduplication | Running the script a second time does **not** increase document count |
| Schema documented | `README.md` (or `docs/schema.md`) contains the JSON example and index definition |

---

## 6️⃣ Quick Run Checklist (copy‑paste into PowerShell)
```powershell
# 1. Activate venv
.\venv\Scripts\Activate.ps1
# 2. Install deps (if not already)
pip install -r requirements.txt
# 3. Start MongoDB (if not running)
mongod --dbpath C:\data\db
# 4. Execute ingestion
python src/ingest.py
# 5. Verify count
python -c "from pymongo import MongoClient; import os; client = MongoClient(os.getenv('MONGODB_URI')); print('Docs:', client.tip.indicators.count_documents({}))"
```

---

**Note:** No web front‑end or website is required for this week. All work is performed via command‑line scripts and a local MongoDB instance.

---

*Prepared for **Project 1 – Finance & Banking – Advanced Threat Intelligence Platform** – Week 1*

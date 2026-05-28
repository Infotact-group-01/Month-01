# Threat Intelligence Platform (TIP) — Project 01

> Automated cybersecurity threat intelligence aggregation, risk scoring, and SIEM visualisation for financial institutions.

---

## ✅ Project Status

| Phase | Description | Status |
|---|---|---|
| **Week 1** | OSINT Ingestion & Database Design | ✅ Done |
| **Week 2** | Normalization, Risk Scoring & SIEM Integration | ✅ Done |
<<<<<<< HEAD
| **Week 3** | Policy Enforcer Daemon (auto-blocking via Windows Firewall) | ✅ Done |
| **Week 4** | Rollback API + Kibana Dashboard + Final Docs | ✅ Done |
=======
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441

---

## 📋 What This Project Does

This platform automatically:
1. **Collects** real threat data from 6 sources (3 free public feeds + 3 live APIs)
2. **Cleans and validates** every indicator into a standard format
3. **Calculates a risk score** (0–100) for each threat based on source, tags, and confidence
4. **Stores** everything in MongoDB (deduplicated — no repeated entries)
5. **Pushes** all data into Elasticsearch so you can search and visualise it in Kibana
<<<<<<< HEAD
6. **Auto-blocks** high-risk IPs (risk ≥ 90) using Windows Firewall rules — zero human intervention needed
7. **Provides a REST API** for SOC analysts to review and undo any auto-block with a full audit trail

**Result:** A fully automated, end-to-end threat intelligence and enforcement platform — from OSINT collection to firewall blocking.
=======

**Result:** A live, searchable threat intelligence dashboard you can open in your browser.
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441

---

## 🗂️ Project Structure

```
PROJECT-01/
│
├── .env                     ← Secret settings (API keys, database URLs)
├── feeds.json               ← List of free text-based threat feed URLs
├── requirements.txt         ← All Python packages needed
├── docker-compose.yml       ← Starts Elasticsearch + Kibana with one command
├── load_demo_data.py        ← Loads realistic demo data into Elasticsearch
│
├── src/                     ← All Python source code
│   ├── config.py            ← Loads settings, connects to MongoDB
│   ├── models.py            ← Defines threat indicator shape + risk scoring
│   ├── fetch_feeds.py       ← Downloads & parses all threat feeds + live APIs
│   ├── db.py                ← Saves data into MongoDB
│   ├── es_client.py         ← Pushes data into Elasticsearch
<<<<<<< HEAD
│   ├── ingest.py            ← MASTER script — runs the full pipeline
│   ├── enforcer.py          ← Week 3: Policy Enforcer Daemon (auto-blocking)
│   └── rollback_api.py      ← Week 4: Flask REST API for SOC rollback control
=======
│   └── ingest.py            ← MASTER script — runs the full pipeline
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441
│
├── data/
│   └── demo_dataset.json    ← 54 hand-crafted realistic demo indicators
│
<<<<<<< HEAD
├── kibana/
│   └── dashboard_export.ndjson  ← Pre-built Kibana dashboard (import once)
│
├── logs/                    ← Auto-created: enforcer.log + rollback.log
│
├── tests/                   ← Automated test suite (96 tests)
=======
├── tests/                   ← Automated test suite (42 tests)
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441
│
├── SCHEMA.md                ← Full database schema documentation
├── PROJECT_GUIDE.md         ← Complete client-facing explanation of the project
└── README.md                ← This file
```

---

## ⚙️ Prerequisites (What You Need Before Starting)

Make sure you have these installed on your PC before doing anything:

| Tool | Version | Check if installed |
|---|---|---|
| Python | 3.11 or higher | `python --version` |
| pip | (comes with Python) | `pip --version` |
| Docker Desktop | Latest | Open the Docker Desktop app |
| Git | Any | `git --version` (optional) |

---

## 🚀 How to Set This Up on Your PC (Step by Step)

Follow these steps **in order**. Do not skip any.

---

### Step 1 — Get the Project Folder

> ℹ️ **Only the `PROJECT-01` folder is needed.** The GitHub repository contains other folders for separate projects — you do not need them. Everything required to run this platform is inside `PROJECT-01`.

You have two options:

---

**Option A — Download as ZIP (recommended, easiest)**

1. Go to: **https://github.com/Infotact-group-01/Month-01**
2. Click the green **`<> Code`** button → **Download ZIP**
3. Right-click the downloaded ZIP → **Extract All**
4. Open the extracted folder — navigate into `Month-01 → Month-01 → PROJECT-01`
5. That `PROJECT-01` folder is your working directory — copy it anywhere you like, for example `C:\Projects\TIP`

---

**Option B — Clone with Git**

```powershell
git clone https://github.com/Infotact-group-01/Month-01.git
```

This downloads the full repository. Once done, navigate into the project:

```powershell
cd Month-01\Month-01\PROJECT-01
```

---

After either option, open **PowerShell** and make sure you are inside the `PROJECT-01` folder.  
Run `dir` to confirm — you should see these files:

```
requirements.txt
docker-compose.yml
feeds.json
.env
src\
tests\
data\
```

> 💡 **All commands from this point forward must be run from inside the `PROJECT-01` folder.**


---

### Step 2 — Install Python Dependencies

This installs all required Python packages:

```powershell
pip install -r requirements.txt
```

Wait for it to finish. You should see:
```
Successfully installed elasticsearch-8.x.x pymongo pydantic requests ...
```

---

### Step 3 — Set Up Your API Keys (in `.env`)

Open the `.env` file in the project root. It looks like this:

```env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=tip
MONGODB_COLLECTION=indicators
ELASTICSEARCH_URI=http://localhost:9200
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

**Replace `your_key_here`** with your actual API keys. Get them free from:

| Key | Where to get it (free) |
|---|---|
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/register → API → Create Key |
| `OTX_API_KEY` | https://otx.alienvault.com → Profile → Settings → OTX Key |

> ⚠️ Never share your `.env` file — it contains private API keys. It is already listed in `.gitignore` so it will never be uploaded to GitHub.

---

### Step 4 — Start Elasticsearch and Kibana (via Docker)

Make sure **Docker Desktop is open and running** first. Then run:

```powershell
docker-compose up -d
```

You should see:
```
✔ Container tip-elasticsearch  Started
✔ Container tip-kibana         Started
```

> ⏳ Wait about **60 seconds** after this. Kibana takes time to fully start up.

You can verify Elasticsearch is running:

```powershell
python -c "import urllib.request, json; r=urllib.request.urlopen('http://localhost:9200'); print(json.loads(r.read())['version']['number'])"
```

Expected output: `8.16.0`

---

### Step 5 — Run the Ingestion Pipeline

This is the main command. It does everything:
- Fetches data from all 6 sources
- Validates and risk-scores every indicator
- Inserts into MongoDB
- Syncs everything to Elasticsearch

```powershell
python -m src.ingest
```

Expected output:
```
Starting TIP ingestion process...
Database setup complete.
Elasticsearch index 'indicators' already exists.
Fetching TestFeed
Fetching EmergingThreats_IPs
Fetching FeodoTracker_IPs
Fetching URLhaus_URLs
Fetching AbuseIPDB blacklist (limit=500) ...
AbuseIPDB: fetched 500 live malicious IPs.
Fetching AlienVault OTX subscribed pulses (max=20) ...
AlienVault OTX: fetched 796 indicators from 20 pulses.
Fetched total 13312 indicators
Successfully validated 13312 out of 13312 indicators.
Ingestion complete. Inserted 13299 new indicators into the database.
Elasticsearch sync: 13312 indexed, 0 failed.
```

---

### Step 6 — Open Kibana and Explore Your Data

Open your browser and go to:

**👉 http://localhost:5601**

**First-time setup (do this once):**
1. Click the **☰ menu** (top-left)
2. Go to **Stack Management** → **Data Views** (or Index Patterns)
3. Click **Create data view**
4. Name: `indicators`
5. Time field: `observed_at`
6. Click **Save data view to Kibana**

**Now explore:**
- Go to **☰ menu → Discover**
- All 13,000+ threat indicators are now visible
- Use the search bar to filter:
  - `source: AbuseIPDB` → Live malicious IPs
  - `source: AlienVault` → Real campaign threat data
  - `risk_score > 90` → Critical threats only
  - `type: hash` → Malware file hashes

---

## 🔁 How to Use It Day-to-Day

### Refresh threat data (run any time)
```powershell
python -m src.ingest
```
Run this whenever you want fresh data. It only adds **new** indicators — duplicates are automatically skipped.

---

### Load the demo dataset (for presentations)
```powershell
python load_demo_data.py
```
Loads 54 hand-crafted, realistic indicators covering 6 attack campaigns (LockBit, APT29, Emotet, QakBot, etc.) — perfect for showing to the company.

---

### Start / Stop the ELK Stack
```powershell
# Start (after PC restart)
docker-compose up -d

# Stop (keeps all data)
docker-compose stop

# Stop and delete all data (full reset)
docker-compose down -v
```

---

<<<<<<< HEAD
### Run the Policy Enforcer (Week 3)
```powershell
# Simulate only — safe, no real firewall changes (good for demos)
.\run_enforcer.ps1 -DryRun

# Run one cycle and exit (requires PowerShell as Administrator)
.\run_enforcer.ps1 -Once

# Run as daemon every 60 seconds (requires PowerShell as Administrator)
.\run_enforcer.ps1

# Remove all TIP firewall rules
.\run_enforcer.ps1 -UnblockAll
```

> ⚠️ **Real blocking requires PowerShell run as Administrator.** Right-click PowerShell → "Run as Administrator".

---

### Start the Rollback API (Week 4)
```powershell
# Start on http://localhost:5050 (dry-run — safe for demos)
.\run_api.ps1 -DryRun

# Start in live mode (actually removes firewall rules when analyst requests rollback)
.\run_api.ps1
```

Once running, SOC analysts can:
```powershell
# View all blocked IPs
curl http://localhost:5050/api/blocked

# Unblock a specific IP
curl -X POST http://localhost:5050/api/rollback/1.2.3.4 -H "Content-Type: application/json" -d '{"reason":"false positive","analyst":"john"}'

# View audit trail
curl http://localhost:5050/api/audit
```

---

### Import the pre-built Kibana Dashboard (Week 4)
1. Open **http://localhost:5601** → log in
2. Go to **☰ menu → Stack Management → Saved Objects**
3. Click **Import** → select `kibana/dashboard_export.ndjson`
4. Go to **☰ menu → Dashboard** → open **"TIP — Threat Intelligence Dashboard"**

---

### Run automated tests
```powershell
pytest tests/ -v
```
Expected: `96 passed`

---

## 📡 Data Sources

| Source | Type | What It Provides |
|---|---|---|
| EmergingThreats | Free text feed | Compromised IP addresses |
| FeodoTracker | Free text feed | Botnet (Emotet, QakBot) C2 IPs |
| URLhaus | Free text feed | Active malicious URLs |
| **AbuseIPDB** | **Live API** | 500 high-confidence malicious IPs with country + category tags |
| **AlienVault OTX** | **Live API** | Real threat pulses — IPs, domains, URLs, file hashes with campaign names |
| TestFeed | Local file | Sample indicators for testing |

---

## 📊 Risk Scoring

Every indicator gets a score from **0 to 100**:

```
risk_score = confidence + (number of tags × 5) + source weight
             ─────────────────────────────────────────────────
             Maximum capped at 100
```

| Source | Weight |
|---|---|
| AbuseIPDB | +20 |
| VirusTotal | +15 |
| AlienVault | +10 |
| Others | +5 |

| Score | Severity | Meaning |
|---|---|---|
| 90–100 | 🔴 Critical | Block immediately |
| 75–89 | 🟠 High | Investigate urgently |
| 50–74 | 🟡 Medium | Monitor closely |
| 0–49 | 🟢 Low | Log and observe |

---

=======
### Run automated tests
```powershell
pytest tests/ -v
```
Expected: `42 passed`

---

## 📡 Data Sources

| Source | Type | What It Provides |
|---|---|---|
| EmergingThreats | Free text feed | Compromised IP addresses |
| FeodoTracker | Free text feed | Botnet (Emotet, QakBot) C2 IPs |
| URLhaus | Free text feed | Active malicious URLs |
| **AbuseIPDB** | **Live API** | 500 high-confidence malicious IPs with country + category tags |
| **AlienVault OTX** | **Live API** | Real threat pulses — IPs, domains, URLs, file hashes with campaign names |
| TestFeed | Local file | Sample indicators for testing |

---

## 📊 Risk Scoring

Every indicator gets a score from **0 to 100**:

```
risk_score = confidence + (number of tags × 5) + source weight
             ─────────────────────────────────────────────────
             Maximum capped at 100
```

| Source | Weight |
|---|---|
| AbuseIPDB | +20 |
| VirusTotal | +15 |
| AlienVault | +10 |
| Others | +5 |

| Score | Severity | Meaning |
|---|---|---|
| 90–100 | 🔴 Critical | Block immediately |
| 75–89 | 🟠 High | Investigate urgently |
| 50–74 | 🟡 Medium | Monitor closely |
| 0–49 | 🟢 Low | Log and observe |

---

>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441
## 🗃️ Data Schema

Every indicator stored in the system looks like this:

```json
{
  "indicator":   "185.220.101.47",
  "type":        "ip",
  "source":      "AbuseIPDB",
  "observed_at": "2026-05-25T09:47:23+00:00",
  "confidence":  100,
  "tags":        ["ssh-brute-force", "brute-force"],
  "risk_score":  100,
  "country":     "NL"
}
```

| Field | Description |
|---|---|
| `indicator` | The actual threat value (IP / domain / URL / file hash) |
| `type` | Category: `ip`, `domain`, `url`, or `hash` |
| `source` | Which feed it came from |
| `observed_at` | Timestamp when it was collected |
| `confidence` | How reliable the source is (0–100) |
| `tags` | Labels like `malware`, `phishing`, `botnet` |
| `risk_score` | Calculated danger level (0–100) |

See [SCHEMA.md](SCHEMA.md) for full schema documentation.

---

## 🛠️ Troubleshooting

### "Real MongoDB not running! Falling back to mongomock"
This is **normal and expected**. The system works without MongoDB installed — it uses an in-memory database automatically. Data won't persist between runs, but everything else works fine.

---

### Kibana shows no data after running the pipeline
1. Make sure Docker is running: `docker-compose up -d`
2. Make sure the pipeline ran: `python -m src.ingest`
3. In Kibana → change the time range to **Last 30 days** or **Last 1 year**
4. Make sure your Data View is set up (Stack Management → Data Views → `indicators`)

---

### Elasticsearch connection error
Make sure Docker Desktop is running and wait 60 seconds after starting it:
```powershell
docker-compose up -d
# Wait 60 seconds, then:
python -m src.ingest
```

---

### API key errors (AbuseIPDB / OTX)
- Check your `.env` file has the correct keys with no spaces
- Test AbuseIPDB: `curl -H "Key: YOUR_KEY" https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8`
- If keys expire, get new ones from abuseipdb.com and otx.alienvault.com

---

### Missing Python packages
```powershell
pip install -r requirements.txt --upgrade
```

---

## ✅ Week 1 — Completed Deliverables

| Task | Result |
|---|---|
| Python environment set up | Python 3.12 + pip + Docker Desktop |
| Connected to 3+ OSINT feeds | EmergingThreats, FeodoTracker, URLhaus + TestFeed |
| Data cleaned and normalized | Pydantic model with type classification |
| MongoDB deduplication | Unique index on `(indicator, source)` |
| 100+ records inserted | **13,312 indicators** ingested ✅ |
| Schema documented | `SCHEMA.md` complete |

---

## ✅ Week 2 — Completed Deliverables

| Task | Result |
|---|---|
| Risk scoring schema designed | `risk_score` field (0–100) on every indicator |
| Risk calculation implemented | `calculate_risk()` — confidence + tags + source weight |
| Live API feeds added | AbuseIPDB (500 IPs/run) + AlienVault OTX (796+ IOCs/run) |
| Elasticsearch set up | Docker container running on port 9200, v8.16.0 |
| Kibana SIEM running | Visual dashboard on port 5601 |
| Dual-write pipeline | Every indicator → MongoDB **and** Elasticsearch |
| ES sync result | **13,312 indexed, 0 failed** ✅ |
| Demo dataset created | 54 indicators across 6 real attack campaigns |
| Automated tests passing | **42 tests, all passing** ✅ |

---

<<<<<<< HEAD
## ✅ Week 3 — Completed Deliverables

| Task | Result |
|---|---|
| Policy Enforcer Daemon | `src/enforcer.py` — queries ES, applies Windows Firewall rules |
| Windows Firewall integration | `netsh advfirewall` — blocks IPs automatically |
| Risk threshold configurable | Default `risk_score ≥ 90`; override via `--threshold` flag |
| Dry-run mode | `--dry-run` flag — simulates blocking safely for demos |
| State persistence | `enforcer_state.json` — tracks all blocked IPs across restarts |
| Append-only audit log | `logs/enforcer.log` — every block action timestamped |
| PowerShell launcher | `run_enforcer.ps1` with `-DryRun`, `-Once`, `-UnblockAll` flags |
| Admin rights check | Warns and exits if not run as Administrator (in real mode) |
| 23 new unit tests | All mocked — no real firewall calls, no network needed |

---

## ✅ Week 4 — Completed Deliverables

| Task | Result |
|---|---|
| Rollback REST API | `src/rollback_api.py` — Flask API on `localhost:5050` |
| View blocked IPs | `GET /api/blocked` — sorted list with metadata |
| Individual rollback | `POST /api/rollback/<ip>` — removes firewall rule + logs |
| Bulk rollback | `POST /api/rollback-all` — safety confirm field required |
| Audit trail API | `GET /api/audit` — full history of blocks and rollbacks |
| Rollback audit log | `logs/rollback.log` — every analyst action recorded |
| PowerShell launcher | `run_api.ps1` with `-DryRun` and `-Port` flags |
| Kibana dashboard | `kibana/dashboard_export.ndjson` — 7 charts, import once |
| 31 new unit tests | Flask test client — no real network or firewall needed |
| **Total test suite** | **96 tests, all passing ✅** |

---

=======
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441
## 📚 Documentation

| File | Description |
|---|---|
| `README.md` | This file — setup and usage guide |
| `SCHEMA.md` | Full database schema with field definitions |
| `PROJECT_GUIDE.md` | Complete client-facing project explanation |
| `data/demo_dataset.json` | Realistic demo indicators for presentations |
<<<<<<< HEAD
| `kibana/dashboard_export.ndjson` | Pre-built Kibana dashboard — import once |
=======
>>>>>>> 229f71947df386995f1a8233a0fd88e723de7441

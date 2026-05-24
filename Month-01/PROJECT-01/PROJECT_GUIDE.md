# Threat Intelligence Platform (TIP) — Complete Project Guide

> **This document is a full, end-to-end guide for the Threat Intelligence Platform project.**
> It covers what the project is, why it was built, how every component works, how to set it up
> from scratch, and how to use it — written so that anyone, even without technical background,
> can understand it.

---

## 📌 Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Why Do We Need It?](#2-why-do-we-need-it)
3. [How Does It Work? (The Big Picture)](#3-how-does-it-work-the-big-picture)
4. [Project Structure (Every File Explained)](#4-project-structure-every-file-explained)
5. [Week 1 — OSINT Ingestion & Database Design](#5-week-1--osint-ingestion--database-design)
6. [Week 2 — Normalization, Risk Scoring & SIEM Integration](#6-week-2--normalization-risk-scoring--siem-integration)
7. [Step-by-Step Setup Guide (From Zero to Running)](#7-step-by-step-setup-guide-from-zero-to-running)
8. [How to Run the System](#8-how-to-run-the-system)
9. [How to Use Kibana (The Visual Dashboard)](#9-how-to-use-kibana-the-visual-dashboard)
10. [Risk Scoring — How It Works](#10-risk-scoring--how-it-works)
11. [Data Schema — What Each Record Looks Like](#11-data-schema--what-each-record-looks-like)
12. [Testing](#12-testing)
13. [Troubleshooting](#13-troubleshooting)
14. [Summary of Achievements](#14-summary-of-achievements)

---

## 1. What Is This Project?

The **Threat Intelligence Platform (TIP)** is an automated cybersecurity system built for **financial institutions**.

In simple terms:

> **It automatically collects data about cyber threats from the internet, cleans and scores them by risk level, stores them in a database, and displays them visually on a dashboard — so security teams can see what threats exist and act on them fast.**

Think of it like a **live news feed**, but instead of news, it collects threat data — malicious IP addresses, dangerous websites, suspicious URLs — from trusted sources around the world, every time you run it.

---

## 2. Why Do We Need It?

Every day, thousands of new cyber threats emerge — malicious IPs, phishing URLs, malware domains. Manually tracking all of them is:
- ❌ Too slow
- ❌ Too expensive
- ❌ Impossible to scale

This platform:
- ✅ **Automatically collects** threat data from multiple trusted public sources
- ✅ **Cleans and normalizes** the data into one standard format
- ✅ **Assigns a risk score** to each threat (0–100)
- ✅ **Stores everything** in a database with zero duplicates
- ✅ **Pushes everything** to a searchable visual dashboard (Kibana)

---

## 3. How Does It Work? (The Big Picture)

Here is the complete flow of the system, from start to finish:

```
┌─────────────────────────────────────────────────────────┐
│              THREAT INTELLIGENCE PIPELINE                │
│                                                          │
│  🌐 OSINT Feeds (Internet)                              │
│  ├── EmergingThreats (compromised IPs)                  │
│  ├── FeodoTracker (botnet IPs)                          │
│  ├── URLhaus (malicious URLs)                           │
│  └── TestFeed (local test data)                         │
│            │                                             │
│            ▼                                             │
│  📥 fetch_feeds.py  ← Fetches & classifies indicators   │
│            │                                             │
│            ▼                                             │
│  🧹 models.py  ← Validates, normalizes, scores risk     │
│            │                                             │
│            ▼ (two parallel paths)                        │
│                                                          │
│  🗃️ MongoDB           🔍 Elasticsearch                  │
│  (stores records)     (makes records searchable)         │
│            │                      │                      │
│            └──────────────────────┘                      │
│                       │                                  │
│                       ▼                                  │
│           📊 Kibana Dashboard                            │
│    (visual charts, search, filters — in your browser)    │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Project Structure (Every File Explained)

```
PROJECT-01/
│
├── 📄 .env                    ← Secret settings (database URLs etc.)
├── 📄 feeds.json              ← List of threat feed sources
├── 📄 requirements.txt        ← Python packages this project needs
├── 📄 docker-compose.yml      ← Starts Elasticsearch + Kibana via Docker
│
├── 📁 src/                    ← All Python source code
│   ├── __init__.py            ← Marks this folder as a Python package
│   ├── config.py              ← Loads settings, connects to MongoDB
│   ├── models.py              ← Defines what a "threat indicator" looks like
│   ├── fetch_feeds.py         ← Downloads and parses threat feeds
│   ├── db.py                  ← Saves data into MongoDB
│   ├── es_client.py           ← Saves data into Elasticsearch
│   └── ingest.py              ← The MASTER script — runs the full pipeline
│
├── 📁 tests/                  ← Automated tests to verify everything works
│   ├── conftest.py            ← Shared test setup
│   ├── test_models.py         ← Tests the data model and risk scoring
│   ├── test_fetch_feeds.py    ← Tests the feed fetching logic
│   └── test_db.py             ← Tests the database layer
│
├── 📄 SCHEMA.md               ← Detailed database schema documentation
├── 📄 README.md               ← Short quick-start guide
└── 📄 Week1_Plan.md           ← Week 1 objectives and milestones
```

---

## 5. Week 1 — OSINT Ingestion & Database Design

### 🎯 Goal
Set up the environment, connect to public threat feeds, and store clean data in MongoDB.

### What Was Built

#### `feeds.json` — The Feed Registry
This file tells the system **where to get threat data from**. It lists the name and URL of each source:

```json
{
  "TestFeed":          "file://test_indicators.txt",
  "EmergingThreats_IPs": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
  "FeodoTracker_IPs":  "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
  "URLhaus_URLs":      "https://urlhaus.abuse.ch/downloads/text_online/"
}
```

These are all **public, free, trusted** cybersecurity threat intelligence sources.

---

#### `src/fetch_feeds.py` — The Data Collector
This script reads `feeds.json`, visits each URL, downloads the data, and classifies every line.

For each line it finds, it automatically figures out what type of threat it is:

| What it looks like | Classified as |
|---|---|
| `1.2.3.4` | IP address |
| `evil.example.com` | Domain |
| `http://bad-site.io/payload` | URL |
| `a1b2c3d4e5f6...` (hex string) | Hash |

---

#### `src/models.py` — The Data Blueprint
This defines the **standard shape** of every threat indicator stored in the system:

| Field | Type | Description |
|---|---|---|
| `indicator` | string | The actual threat value (e.g. `1.2.3.4`) |
| `type` | string | `ip`, `domain`, `url`, or `hash` |
| `source` | string | Where it came from (e.g. `EmergingThreats_IPs`) |
| `observed_at` | datetime | When it was collected |
| `confidence` | integer | How confident we are (0–100), default: 85 |
| `tags` | list | Labels like `malware`, `phishing` |
| `risk_score` | integer | Calculated danger level (0–100) |

---

#### `src/db.py` + `src/config.py` — The Database Layer
- Connects to **MongoDB** (or falls back to an in-memory mock if MongoDB is offline)
- Creates a **unique index** on `(indicator, source)` — this is how duplicates are prevented
- If the same IP is found in two different runs, it will only be stored **once**

---

#### `src/ingest.py` — The Master Orchestrator
This is the single script that runs the **entire pipeline**:

```
1. Setup database and Elasticsearch index
2. Fetch all feeds → 12,357+ indicators
3. Validate and normalize each indicator
4. Calculate risk score for each
5. Insert into MongoDB (deduplicated)
6. Sync to Elasticsearch (for searching)
```

---

### Week 1 Deliverables ✅

| Milestone | Result |
|---|---|
| Environment ready | Python 3.12 + Docker running |
| Feed list defined | 4 feeds in `feeds.json` |
| Ingestion script runs | `python -m src.ingest` works |
| 100+ records inserted | **12,357** records inserted |
| Deduplication working | Unique index on `(indicator, source)` |
| Schema documented | `SCHEMA.md` + `README.md` |

---

## 6. Week 2 — Normalization, Risk Scoring & SIEM Integration

### 🎯 Goal
Add a risk scoring system to the data, and set up a lightweight SIEM using the ELK Stack (Elasticsearch + Kibana) so the data becomes searchable and visually explorable.

### What Was Built

#### Risk Scoring Engine (`src/models.py`)
A `calculate_risk()` method was added to every indicator. It produces a score from **0 to 100** based on three factors:

```
risk_score = base_confidence + tag_weight + source_weight  (capped at 100)
```

| Factor | How it contributes |
|---|---|
| `confidence` | Base score — default is 85 |
| Tags | Each tag adds +5 (e.g., `malware` + `phishing` = +10) |
| Source reputation | AbuseIPDB +20, VirusTotal +15, AlienVault +10, others +5 |

**Example calculations:**
```
1.2.3.4        (TestFeed, no tags)       → 85 + 0  + 5  = 90
evil.example   (TestFeed, malware tag)   → 85 + 5  + 5  = 95
http://bad.io  (AbuseIPDB, 2 tags)       → 90 + 10 + 20 = 100 (capped)
```

---

#### Elasticsearch Client (`src/es_client.py`)
This module handles all communication with Elasticsearch:

- **`setup_elasticsearch()`** — Creates the `indicators` index with the right field types if it doesn't already exist
- **`index_indicators()`** — Bulk-uploads a list of indicators to Elasticsearch efficiently, using composite `indicator::source` IDs to prevent Elasticsearch duplicates

The index uses the following field mappings:

```json
{
  "indicator":   "keyword",
  "type":        "keyword",
  "source":      "keyword",
  "observed_at": "date",
  "confidence":  "integer",
  "tags":        "keyword",
  "risk_score":  "integer"
}
```

---

#### ELK Stack via Docker (`docker-compose.yml`)
The SIEM runs entirely inside Docker — no manual installation needed. Just one command starts both services:

```
┌─────────────────────┐    ┌────────────────────┐
│   Elasticsearch      │    │       Kibana        │
│   Port: 9200        │◄───│   Port: 5601        │
│   (data store)      │    │   (visual UI)       │
└─────────────────────┘    └────────────────────┘
```

Both are version **8.16.0** — the same version as the images already on your Docker Desktop.

---

#### Updated Ingestion Pipeline (`src/ingest.py`)
The pipeline was extended to:
1. Call `setup_elasticsearch()` at startup
2. Call `calculate_risk()` on every validated indicator
3. After MongoDB insert → immediately bulk-sync to Elasticsearch

**Final confirmed run:**
```
Fetched:           12,357 indicators (from 4 feeds)
Validated:         12,357 / 12,357  (100%)
MongoDB inserted:  12,357 records
Elasticsearch:     12,357 indexed, 0 failed ✅
```

---

### Week 2 Deliverables ✅

| Milestone | Result |
|---|---|
| Risk score schema added | `risk_score` field on every indicator |
| Risk calculation logic | `calculate_risk()` method implemented |
| Elasticsearch running | Docker container `tip-elasticsearch:9200` ✅ |
| Kibana running | Docker container `tip-kibana:5601` ✅ |
| Indicators indexed in ES | 12,357 records fully indexed ✅ |
| Zero sync failures | `0 failed` in bulk indexing ✅ |

---

## 7. Step-by-Step Setup Guide (From Zero to Running)

> **Prerequisites before you start:**
> - Python 3.11 or higher installed
> - Docker Desktop installed and running
> - Git (optional, if cloning from a repo)

---

### Step 1 — Navigate to the Project Folder

Open **PowerShell** and go to the project directory:

```powershell
cd H:\Infotact_files\antigravity\Month-01\Month-01\PROJECT-01
```

---

### Step 2 — Install Python Dependencies

This installs all required Python packages (requests, pymongo, pydantic, elasticsearch, etc.):

```powershell
pip install -r requirements.txt
```

Expected output (abridged):
```
Successfully installed elasticsearch-8.19.3 ...
```

---

### Step 3 — Configure Environment Variables

The `.env` file at the root of the project already contains the correct defaults:

```env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=tip
MONGODB_COLLECTION=indicators
ELASTICSEARCH_URI=http://localhost:9200
```

> ⚠️ If you have a real MongoDB server running, make sure `MONGODB_URI` points to it.
> If not, the system automatically uses an **in-memory fallback** — no action needed.

---

### Step 4 — Start the ELK Stack (Elasticsearch + Kibana)

This single command downloads (or reuses) the Docker images and starts both services in the background:

```powershell
docker-compose up -d
```

Expected output:
```
✔ Container tip-elasticsearch  Started
✔ Container tip-kibana         Started
```

> 💡 Wait about **60 seconds** after this before running the pipeline — Kibana needs time to initialize.

---

### Step 5 — Verify Elasticsearch is Running

```powershell
python -c "import urllib.request, json; r=urllib.request.urlopen('http://localhost:9200'); print(json.loads(r.read())['version']['number'])"
```

Expected output:
```
8.16.0
```

---

### Step 6 — Run the Ingestion Pipeline

This is the main command. It fetches all threats, scores them, and loads them into both databases:

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
Fetched total 12357 indicators
Successfully validated 12357 out of 12357 indicators.
Ingestion complete. Inserted 12357 new indicators into the database.
Elasticsearch sync: 12357 indexed, 0 failed.
```

---

## 8. How to Run the System

### Run the Full Pipeline (standard operation)
```powershell
python -m src.ingest
```
Run this **every time** you want to refresh the threat data.

### Fetch Only (no database insert)
```powershell
python -m src.fetch_feeds
```
Useful for previewing what's in the feeds without storing anything.

### Start/Stop the ELK Stack
```powershell
# Start
docker-compose up -d

# Stop (data is preserved)
docker-compose stop

# Stop and delete all data
docker-compose down -v
```

### Run All Tests
```powershell
pytest tests/
```

Expected result:
```
42 passed in 2.37s
```

---

## 9. How to Use Kibana (The Visual Dashboard)

### Open Kibana
Open your web browser and go to:

**👉 [http://localhost:5601](http://localhost:5601)**

---

### First-Time Setup — Create an Index Pattern

1. Click the **☰ menu** (top-left) → **Stack Management**
2. Under **Kibana** → click **Index Patterns** (or **Data Views**)
3. Click **Create index pattern**
4. Enter: `indicators`
5. For **Time field**, select: `observed_at`
6. Click **Create index pattern**

---

### Explore Your Threat Data

1. Click **☰ menu** → **Discover**
2. Select the `indicators` index pattern
3. You will see all **12,357+ threat indicators** listed
4. Use the search bar to filter, for example:
   - `type: ip` — show only IP threats
   - `risk_score: >90` — show only high-risk threats
   - `source: URLhaus_URLs` — show threats from URLhaus

---

### Create Visualizations (Optional)

Go to **☰ menu → Dashboard → Create dashboard**, then:

| Visualization Idea | Type | Field |
|---|---|---|
| Threats by source | Pie chart | `source` |
| Risk score distribution | Bar chart | `risk_score` |
| Indicator types breakdown | Donut chart | `type` |
| Timeline of collected threats | Line chart | `observed_at` |

---

## 10. Risk Scoring — How It Works

Every indicator gets a **risk score from 0 to 100** calculated automatically. Here's the formula:

```
risk_score = confidence + (tags × 5) + source_weight
             ────────────────────────────────────────
             Maximum capped at 100
```

### Source Reputation Weights

| Feed Source | Weight Added |
|---|---|
| AbuseIPDB | +20 |
| VirusTotal | +15 |
| AlienVault OTX | +10 |
| Any other source | +5 |

### Real Examples from Our Data

| Indicator | Source | Confidence | Tags | Risk Score |
|---|---|---|---|---|
| `1.2.3.4` | TestFeed | 85 | none | **90** |
| `evil.example.com` | TestFeed | 85 | malware | **95** |
| `http://bad.io/x` | AbuseIPDB | 90 | phishing, malware | **100** |

### Risk Severity Guide

| Score Range | Severity | Action |
|---|---|---|
| 90 – 100 | 🔴 Critical | Block immediately |
| 75 – 89 | 🟠 High | Investigate urgently |
| 50 – 74 | 🟡 Medium | Monitor closely |
| 0 – 49 | 🟢 Low | Log and observe |

---

## 11. Data Schema — What Each Record Looks Like

Every single threat indicator stored in the system follows this exact structure:

```json
{
  "indicator":   "185.220.101.45",
  "type":        "ip",
  "source":      "FeodoTracker_IPs",
  "observed_at": "2026-05-24T09:15:37+00:00",
  "confidence":  85,
  "tags":        [],
  "risk_score":  90
}
```

### Field Definitions

| Field | Example Value | Meaning |
|---|---|---|
| `indicator` | `185.220.101.45` | The actual threat — IP, domain, URL, or hash |
| `type` | `ip` | Category: `ip`, `domain`, `url`, or `hash` |
| `source` | `FeodoTracker_IPs` | Which feed it came from |
| `observed_at` | `2026-05-24T09:15:37Z` | Timestamp when collected |
| `confidence` | `85` | How reliable the source is (0–100) |
| `tags` | `["malware"]` | Labels describing the threat type |
| `risk_score` | `90` | **Calculated danger level (0–100)** |

---

## 12. Testing

The project includes **42 automated tests** that verify every layer works correctly:

```powershell
pytest tests/ -v
```

| Test File | What It Tests | Tests |
|---|---|---|
| `test_models.py` | Data validation, risk scoring, field defaults | 13 |
| `test_fetch_feeds.py` | Feed fetching, IOC classification, parsing | 24 |
| `test_db.py` | MongoDB setup, insert, deduplication | 5 |
| **Total** | | **42 ✅** |

### What The Tests Verify

- ✅ An IP address is correctly classified as `ip`
- ✅ A URL starting with `http://` is classified as `url`
- ✅ The default confidence score is 85
- ✅ Inserting the same indicator twice does **not** create a duplicate
- ✅ Invalid indicators (wrong format) are rejected
- ✅ Risk score is always between 0 and 100

---

## 13. Troubleshooting

### ❓ "Real MongoDB not running! Falling back to mongomock"
**This is normal.** If you don't have MongoDB installed locally, the system uses an in-memory database automatically. Data will not be persisted between restarts. To use real MongoDB, install it and ensure it runs on port `27017`.

---

### ❓ Kibana shows "No results" or the index doesn't appear
**Solution:**
1. Make sure you ran `python -m src.ingest` successfully
2. Go to **Stack Management → Index Patterns** and create the `indicators` pattern
3. Check that the time range in Kibana is set wide enough (e.g., "Last 7 days")

---

### ❓ `docker-compose up -d` fails
**Solution:**
1. Ensure Docker Desktop is running (check the taskbar)
2. Try `docker-compose down` then `docker-compose up -d` again
3. Ensure ports `9200` and `5601` are not used by another application

---

### ❓ Elasticsearch connection fails in Python
**Solution:** Check the version match. The Python client **must** match the server version:
- Server: Elasticsearch **8.16.0** (Docker image)
- Python client: `elasticsearch>=8.0.0,<9.0.0` ✅ (pinned in requirements.txt)

```powershell
pip install "elasticsearch>=8.0.0,<9.0.0"
```

---

### ❓ Tests fail after changes
**Solution:**
```powershell
pytest tests/ -v --tb=short
```
Review the failed test output — most failures will show the exact line and assertion that broke.

---

## 14. Summary of Achievements

### Week 1
| ✅ Task | Detail |
|---|---|
| Development environment | Python 3.12, pip, Docker Desktop |
| OSINT feed integration | 4 feeds: EmergingThreats, FeodoTracker, URLhaus, TestFeed |
| Ingestion script | `src/ingest.py` — full pipeline orchestrator |
| Data normalization | Pydantic models with automatic type classification |
| MongoDB storage | Deduplicated via unique index on `(indicator, source)` |
| 100+ records target | **12,357 records** inserted ✅ |
| Schema documentation | `SCHEMA.md`, `README.md` |

### Week 2
| ✅ Task | Detail |
|---|---|
| Risk scoring schema | `risk_score` field (0–100) on every indicator |
| Risk calculation | Heuristic based on confidence + tags + source weight |
| Elasticsearch setup | Docker container, port 9200, v8.16.0 |
| Kibana SIEM | Docker container, port 5601, visual dashboard |
| Dual-write pipeline | Every indicator → MongoDB **and** Elasticsearch |
| ES sync result | **12,357 indexed, 0 failed** ✅ |
| Automated tests | **42 tests, all passing** ✅ |

---

> 📝 **Document Version:** Week 2 Final
> 📅 **Last Updated:** May 2026
> 👤 **Project:** Threat Intelligence Platform — Finance & Banking Security Initiative

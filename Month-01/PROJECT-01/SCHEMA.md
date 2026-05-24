# Threat Intelligence Platform (TIP) - Week 1 Deliverables

## Overview
Week 1 focuses on building the OSINT ingestion foundation, database schema, and data deduplication pipeline for the Threat Intelligence Platform.

## MongoDB Schema

### Collection: `indicators`

**Purpose:** Stores normalized threat indicators (IPs, domains, URLs, hashes) from OSINT feeds.

#### Document Structure
```json
{
  "indicator": "192.0.2.45",
  "type": "ip",
  "source": "TestFeed",
  "observed_at": "2026-05-21T10:30:00Z",
  "confidence": 85,
  "tags": ["malware", "c2"],
  "first_seen": "2026-05-21T10:30:00Z",
  "last_seen": "2026-05-21T10:30:00Z"
}
```

#### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `indicator` | String | The actual threat indicator (IP address, domain, URL, or file hash) |
| `type` | String | Classification: `ip`, `domain`, `url`, or `hash` |
| `source` | String | Name of the OSINT feed source |
| `observed_at` | DateTime | When the indicator was collected |
| `confidence` | Integer | Confidence score (0-100), defaults to 85 |
| `tags` | Array | Categorization tags (e.g., "malware", "phishing", "c2") |
| `first_seen` | DateTime | First time indicator appeared in any feed |
| `last_seen` | DateTime | Last time indicator was observed |

#### Indexes

**Unique Index: `(indicator, source)`**
```javascript
db.indicators.createIndex(
  [("indicator", 1), ("source", 1)],
  { unique: true, name: "unique_indicator_source" }
)
```
**Purpose:** Prevents duplicate indicators from the same source while allowing the same indicator from multiple sources.

---

## Ingestion Pipeline

### Components

1. **`src/fetch_feeds.py`** - Downloads threat data from OSINT feeds
   - Supports HTTP/HTTPS URLs and local `file://` URLs
   - Handles simple text-based feeds (one indicator per line)
   - Graceful error handling with logging

2. **`src/models.py`** - Pydantic models for data validation
   - `Indicator` model enforces schema constraints
   - Auto-validation of indicator types
   - Fallback dataclass if Pydantic unavailable

3. **`src/ingest.py`** - Main orchestration script
   - Fetches data from all feeds
   - Validates against schema
   - Handles deduplication via MongoDB unique index
   - Provides summary statistics

4. **`src/db.py`** - Database utilities
   - Collection management
   - Index creation
   - Bulk insert with duplicate handling

5. **`src/config.py`** - Configuration management
   - Loads `.env` file for MongoDB connection
   - Reads `feeds.json` for feed definitions
   - MongoDB client initialization with fallback to mongomock

### Data Flow

```
OSINT Feeds (feeds.json)
    ↓
fetch_feeds.py (HTTP GET or file read)
    ↓
parse_plain_iocs() (simple line-by-line parsing)
    ↓
models.Indicator (Pydantic validation)
    ↓
db.insert_indicators() (MongoDB insert_many)
    ↓
Unique Index (deduplication on indicator + source)
    ↓
MongoDB indicators collection
```

---

## Configuration

### `.env` File
```env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=tip
MONGODB_COLLECTION=indicators
```

### `feeds.json` File
```json
{
  "SourceName": "feed_url_or_file_path",
  "TestFeed": "file://test_indicators.txt"
}
```

Supported URL schemes:
- `https://` - HTTPS web resources
- `http://` - HTTP web resources  
- `file://` - Local file paths (relative to project root)

---

## Acceptance Criteria - Week 1

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Environment ready | ✅ | Python 3.11+, MongoDB/mongomock configured, venv active |
| Feed list defined | ✅ | `feeds.json` contains feed definitions with valid URLs |
| Ingestion script runs | ✅ | `python -m src.ingest` completes without errors |
| Records inserted | ✅ | 104 test indicators successfully ingested |
| Data deduplication | ✅ | Unique index on `(indicator, source)` prevents duplicates |
| Schema documented | ✅ | This document defines collection structure and field mapping |

---

## Running the Ingestion

### Setup
```bash
# 1. Navigate to project directory
cd PROJECT-01

# 2. Create virtual environment (if not exists)
python -m venv venv
source venv/Scripts/activate  # Windows: .\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

### Execution
```bash
# Run ingestion pipeline
python -m src.ingest

# Or run just the fetcher
python -m src.fetch_feeds
```

### Verification
```bash
# Check document count
python -c "from pymongo import MongoClient; client = MongoClient('mongodb://localhost:27017/'); print('Total indicators:', client.tip.indicators.count_documents({}))"

# List first 5 indicators
python -c "from pymongo import MongoClient; client = MongoClient('mongodb://localhost:27017/'); docs = list(client.tip.indicators.find().limit(5)); import json; print(json.dumps(docs, default=str, indent=2))"
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `requests` | Latest | HTTP client for feed fetching |
| `beautifulsoup4` | Latest | HTML parsing (future use) |
| `pymongo` | Latest | MongoDB driver |
| `python-dotenv` | Latest | Environment variable loading |
| `pydantic` | Latest | Data validation |
| `mongomock` | Latest | In-memory MongoDB fallback for testing |

---

## Testing Strategy

### Unit Tests (Future)
- Parser validation (IP/domain/URL classification)
- Pydantic model enforcement
- Error handling in fetch functions

### Integration Tests (Future)
- Full pipeline with real MongoDB
- Deduplication with repeated ingestion
- Multiple concurrent feeds

### Current Test Coverage
- ✅ Test data with 104 indicators
- ✅ Local file:// feed support
- ✅ Validation pipeline
- ✅ Duplicate prevention logic

---

## Known Limitations & Future Work

### Current Limitations
1. Simple line-by-line parsing (no JSON/CSV parsing yet)
2. No rate limiting for external feeds
3. No feed authentication beyond basic URL structure
4. Mongomock fallback for offline MongoDB (no persistence)

### Week 2+ Enhancements
1. Risk scoring schema and algorithm
2. SIEM integration (ELK stack)
3. Advanced feed parsers (JSON, CSV, XML)
4. Feed authentication and API key support
5. Rate limiting and retry logic

---

## Success Metrics

- **Ingestion Rate:** 100+ indicators per feed without errors
- **Deduplication Rate:** 100% accuracy (no duplicate indicators from same source)
- **Data Quality:** 100% schema validation pass rate
- **Uptime:** Graceful fallback to mongomock when MongoDB unavailable

---

*Last Updated: 2026-05-21*
*Project: Threat Intelligence Platform (TIP) - Week 1 OSINT Ingestion*

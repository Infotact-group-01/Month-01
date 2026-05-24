# Threat Intelligence Platform (TIP) - Project 1

Advanced threat intelligence aggregation and automated security policy enforcement for financial institutions.

## Quick Start

```bash
# 1. Activate virtual environment
source venv/Scripts/activate  # Windows: .\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run OSINT ingestion
python -m src.ingest

# 4. Check results
python -m src.fetch_feeds
```

## Project Structure

```
PROJECT-01/
├── src/
│   ├── __init__.py
│   ├── fetch_feeds.py       # OSINT feed fetcher
│   ├── ingest.py            # Main ingestion orchestrator
│   ├── models.py            # Pydantic data models
│   ├── db.py                # MongoDB utilities
│   └── config.py            # Configuration & environment
├── feeds.json               # Feed source definitions
├── .env                     # Environment variables (MongoDB connection)
├── requirements.txt         # Python dependencies
├── test_indicators.txt      # Test data (104 sample indicators)
├── SCHEMA.md                # Database schema documentation
└── Week1_Plan.md            # Week 1 deliverables and roadmap
```

## Features

### OSINT Ingestion
- Fetches threat data from multiple OSINT feeds
- Supports HTTP/HTTPS URLs and local files
- Simple line-by-line indicator parsing
- Automatic indicator type classification (IP/domain/URL)

### Data Normalization
- Pydantic-based schema validation
- Automatic confidence scoring
- Timestamp normalization
- Tag categorization

### MongoDB Integration
- Automatic deduplication via unique indexes
- Bulk insert with duplicate handling
- Schema-enforced document structure
- In-memory fallback (mongomock) when MongoDB offline

## Configuration

### Environment Variables (`.env`)
```env
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DB=tip
MONGODB_COLLECTION=indicators
```

### Feed Sources (`feeds.json`)
```json
{
  "SourceName": "https://example.com/feed"
}
```

Supported protocols:
- `https://` - HTTPS feeds
- `http://` - HTTP feeds
- `file://` - Local files (relative to project root)

## Data Schema

**Collection:** `indicators`

**Sample Document:**
```json
{
  "indicator": "192.0.2.45",
  "type": "ip",
  "source": "TestFeed",
  "observed_at": "2026-05-21T10:30:00Z",
  "confidence": 85,
  "tags": []
}
```

**Unique Index:** `(indicator, source)` - prevents duplicates from same source

See [SCHEMA.md](SCHEMA.md) for complete documentation.

## Usage Examples

### Run Full Ingestion Pipeline
```bash
python -m src.ingest
```
Output:
```
Starting TIP ingestion process...
Database setup complete. Unique index on (indicator, source) is ready.
Fetching TestFeed
Fetched total 104 indicators
Successfully validated 104 out of 104 indicators.
Ingestion complete. Inserted 104 new indicators into the database.
```

### Fetch Only (No Database Insert)
```bash
python -m src.fetch_feeds
```
Output: JSON array of all fetched indicators

### Query MongoDB
```bash
python -c "from pymongo import MongoClient; 
client = MongoClient('mongodb://localhost:27017/'); 
print('Total indicators:', client.tip.indicators.count_documents({}))"
```

## Week 1 Acceptance Criteria

✅ **Environment ready** - Python 3.11+, MongoDB/mongomock configured  
✅ **Feed list defined** - feeds.json contains valid source URLs  
✅ **Ingestion script runs** - `python -m src.ingest` completes without errors  
✅ **Records inserted** - 104+ indicators successfully ingested  
✅ **Data deduplication** - Unique index prevents duplicate indicators  
✅ **Schema documented** - See SCHEMA.md  

## Dependencies

- **requests** - HTTP client for feed fetching
- **beautifulsoup4** - HTML parsing (for future feed parsers)
- **pymongo** - MongoDB driver
- **python-dotenv** - Environment variable loading
- **pydantic** - Data validation and models
- **mongomock** - In-memory MongoDB fallback for testing

## Architecture Overview

```
Feeds (JSON/TXT)
    ↓
fetch_feeds.py (HTTP GET or file read)
    ↓
parse_plain_iocs() (line-by-line parsing)
    ↓
Indicator (Pydantic validation)
    ↓
insert_indicators() (MongoDB bulk insert)
    ↓
Unique Index (deduplication)
    ↓
indicators collection
```

## Future Work (Week 2+)

- Risk scoring schema
- SIEM integration (ELK Stack)
- Advanced feed parsers (JSON, CSV, XML)
- API key authentication
- Rate limiting
- Dynamic Policy Enforcer daemon
- Kibana dashboards
- Rollback mechanism

## Testing

### Run Ingestion with Test Data
```bash
python -m src.ingest
```

### Check Data Quality
```bash
# Count total indicators
python -m src.ingest | grep "Inserted"

# View first 5 records
python -c "from src.config import get_db_collection; 
import json; 
docs = list(get_db_collection().find().limit(5)); 
print(json.dumps(docs, default=str, indent=2))"
```

## Troubleshooting

### MongoDB Connection Fails
```
WARNING: Real MongoDB not running! Falling back to 'mongomock' (in-memory database) for testing.
```
→ This is normal. mongomock provides an in-memory fallback. For production, ensure MongoDB is running.

### Duplicate Indicators
→ Check the unique index on `(indicator, source)`. Duplicates from the same source will be skipped.

### Missing Dependencies
```bash
pip install -r requirements.txt --upgrade
```

## Documentation

- [SCHEMA.md](SCHEMA.md) - Complete database schema documentation
- [Week1_Plan.md](Week1_Plan.md) - Week 1 deliverables and roadmap
- [../Project_01_TIP_Overview.md](../Project_01_TIP_Overview.md) - Full project overview

## License

Proprietary - Finance & Banking Security Initiative

## Contact

Security Team - security@organization.local

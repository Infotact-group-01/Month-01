import argparse
import json
import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

from src.models import Indicator
from src.db import insert_indicators
from src.es_client import index_indicators

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    print(f"🔍 Querying AbuseIPDB API for {ip}...")
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return data
    except Exception as e:
        print(f"⚠️ Failed to reach AbuseIPDB: {e}")
        return {}

def main():
    parser = argparse.ArgumentParser(description="Manually add a single IP to the Threat Intelligence Platform")
    parser.add_argument("ip", help="The IP address to add")
    parser.add_argument("--source", default="Manual Analyst Entry", help="Source of the indicator")
    parser.add_argument("--tags", nargs="*", default=["manual_entry"], help="Tags for the IP")
    args = parser.parse_args()

    confidence = 90
    source = args.source
    tags = args.tags.copy()

    # Query AbuseIPDB for live threat intel
    intel = check_abuseipdb(args.ip)
    if intel:
        api_score = intel.get("abuseConfidenceScore", 0)
        print(f"✅ AbuseIPDB returned confidence score: {api_score}/100")
        confidence = api_score
        source = "AbuseIPDB (Live API)"
        if api_score >= 50:
            tags.append("malicious")
        if intel.get("usageType"):
            tags.append(intel.get("usageType").split("/")[0].lower())

    # 1. Create the Indicator and calculate risk
    ind = Indicator(
        indicator=args.ip,
        type="ip",
        source=source,
        observed_at=datetime.now(timezone.utc),
        tags=tags,
        confidence=confidence
    )
    ind.calculate_risk()

    # Convert to dict for DB insertion
    record = json.loads(ind.model_dump_json()) if hasattr(ind, "model_dump_json") else ind.__dict__

    # 2. Insert into MongoDB
    inserted = insert_indicators([record])
    if inserted:
        print(f"✅ Successfully added IP {args.ip} to MongoDB with risk score {ind.risk_score}")
    else:
        print(f"ℹ️ IP {args.ip} already exists, updated record in MongoDB.")

    # 3. Sync to Elasticsearch so Kibana sees it
    print("🔄 Syncing to Elasticsearch...")
    index_indicators([record])
    print("✅ Done! IP is now fully registered in the platform.")

if __name__ == "__main__":
    main()

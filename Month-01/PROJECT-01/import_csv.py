import argparse
import csv
import json
import os
from datetime import datetime, timezone

from src.models import Indicator
from src.db import insert_indicators
from src.es_client import index_indicators

def main():
    parser = argparse.ArgumentParser(description="Bulk import indicators (IPs, URLs, Domains, Hashes) from a CSV file")
    parser.add_argument("csv_file", help="Path to the CSV file")
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"❌ Error: File '{args.csv_file}' not found.")
        return

    records = []
    valid_types = ["ip", "domain", "url", "hash"]
    
    print(f"📂 Reading from {args.csv_file}...")
    with open(args.csv_file, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            indicator_value = row.get("indicator", "").strip()
            ind_type = row.get("type", "ip").strip().lower()
            source = row.get("source", "Manual CSV Import").strip()
            tags_str = row.get("tags", "")
            tags = [t.strip() for t in tags_str.split("|") if t.strip()]

            if not indicator_value:
                continue

            if ind_type not in valid_types:
                print(f"⚠️ Skipping '{indicator_value}': Invalid type '{ind_type}'. Must be one of {valid_types}.")
                continue

            try:
                ind = Indicator(
                    indicator=indicator_value,
                    type=ind_type,
                    source=source,
                    observed_at=datetime.now(timezone.utc),
                    tags=tags,
                    confidence=90
                )
                ind.calculate_risk()
                
                record = json.loads(ind.model_dump_json()) if hasattr(ind, "model_dump_json") else ind.__dict__
                records.append(record)
            except Exception as e:
                print(f"⚠️ Error processing '{indicator_value}': {e}")

    if not records:
        print("ℹ️ No valid indicators found to import.")
        return

    print(f"💾 Inserting {len(records)} indicators into MongoDB...")
    newly_inserted = insert_indicators(records)
    print(f"✅ Inserted {newly_inserted} new records (existing ones were updated).")

    print(f"🔄 Syncing {len(records)} records to Elasticsearch...")
    success = index_indicators(records)
    print(f"✅ Successfully synced {success} records to Elasticsearch.")

if __name__ == "__main__":
    main()

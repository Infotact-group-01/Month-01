import csv
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intelligence"]
collection = db["threats"]

inserted = 0

with open("ipblocklist.csv", "r", encoding="utf-8") as file:

    reader = csv.reader(file)

    for row in reader:

        if not row:
            continue

        if row[0].startswith("#"):
            continue

        # IMPORTANT: We need to know which column contains the IP
        print(row)

        document = {
            "data": row,
            "source": "FeodoTracker",
            "risk_score": 90,
            "status": "active"
        }

        collection.insert_one(document)
        inserted += 1

print(f"Imported {inserted} records")

import csv
from pymongo import MongoClient

client = MongoClient("mongodb://pensive_turing:27017")

db = client["threat_intelligence"]
collection = db["threats"]

with open("ipblocklist.csv","r",encoding="utf-8") as file:

    reader = csv.reader(file)

    for row in reader:

        if len(row)==0:
            continue

        if row[0].startswith("#"):
            continue

        document = {
            "ip": row[1],
            "source": "FeodoTracker",
            "risk_score": 90,
            "status": "active"
        }

        collection.insert_one(document)

print("Import Completed")

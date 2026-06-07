from pymongo import MongoClient
from elasticsearch import Elasticsearch

mongo = MongoClient("mongodb://localhost:27017")

es = Elasticsearch("http://localhost:9200")

collection = mongo["threat_intelligence"]["threats"]

for doc in collection.find():

    doc.pop("_id", None)

    es.index(
        index="threats",
        document=doc
    )

print("Migration Complete")

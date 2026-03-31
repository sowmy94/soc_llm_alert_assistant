from pymongo import MongoClient
from typing import Dict, Any
from bson import ObjectId

# MongoDB connection
uri = "mongodb://localhost:27017/"

client = MongoClient(uri)

db = client["Security_alerts"]

collection = db["alerts"]

# Verify connection
try:
    client.admin.command("ping")
    print("MongoDB connected successfully!")
except Exception as e:
    print(f"MongoDB connection failed: {e}")


def insert_alert(alert_data: Dict[str, Any]) -> str:
    """
    Insert alert document into MongoDB
    """
    result = collection.insert_one(alert_data)
    return str(result.inserted_id)


def get_alert(alert_id: str):
    """
    Retrieve stored alert by ID
    """
    try:
        alert = collection.find_one({"_id": ObjectId(alert_id)})

        if alert:
            alert["_id"] = str(alert["_id"])
            return alert

        return None

    except Exception:
        return None
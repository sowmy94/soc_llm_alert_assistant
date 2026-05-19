# database.py

from pymongo import MongoClient
from typing import Dict, Any
from bson import ObjectId


MONGO_URI = "mongodb://localhost:27017/"

# Module-level client — MongoClient is thread-safe and reuses the connection pool
client = MongoClient(MONGO_URI)
db = client["Security_alerts"]
collection = db["alerts"]

# Eagerly verify the connection so misconfiguration is caught at startup
try:
    client.admin.command("ping")
    print("MongoDB connected successfully!")
except Exception as e:
    print(f"MongoDB connection failed: {e}")


def insert_alert(alert_data: Dict[str, Any]) -> str:
    """
    Insert an alert document into the MongoDB alerts collection.

    Returns the inserted document's ObjectId as a string.
    """
    result = collection.insert_one(alert_data)
    return str(result.inserted_id)


def get_alert(alert_id: str) -> Dict[str, Any] | None:
    """
    Retrieve a stored alert by its MongoDB ObjectId string.

    Returns the alert document with '_id' serialized to a string,
    or None if the ID is invalid or the document does not exist.
    """
    try:
        alert = collection.find_one({"_id": ObjectId(alert_id)})

        if alert:
            # Convert ObjectId to string so the document is JSON-serializable
            alert["_id"] = str(alert["_id"])
            return alert

        return None

    except Exception:
        # Catches bson.errors.InvalidId for malformed IDs
        return None

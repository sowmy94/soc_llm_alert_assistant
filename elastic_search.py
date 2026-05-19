# elastic_search.py

import os
from typing import Dict, Any

from elasticsearch import Elasticsearch


ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "soc-alerts")


def get_es_client() -> Elasticsearch:
    """Return an Elasticsearch client using the configured URL."""
    return Elasticsearch(ELASTIC_URL)


def ensure_index() -> None:
    """
    Create the SOC alerts index in Elasticsearch if it does not already exist.

    Called once at application startup. If Elasticsearch is unavailable,
    the error is logged and swallowed so the app can still serve non-ES
    endpoints (e.g. MongoDB-only paths).
    """
    try:
        client = get_es_client()

        if client.indices.exists(index=ELASTIC_INDEX):
            return

        client.indices.create(
            index=ELASTIC_INDEX,
            mappings={
                "properties": {
                    "timestamp": {"type": "date"},
                    "alert_source": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "process_name": {"type": "keyword"},
                    "command_line": {"type": "text"},
                    "parent_process": {"type": "keyword"},
                    "matched": {"type": "boolean"},
                    "rule_name": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "reason": {"type": "text"},
                    "technique_id": {"type": "keyword"},
                    "technique_name": {"type": "keyword"},
                    "tactic": {"type": "keyword"},
                    "llm_summary": {"type": "text"},
                    "analyst_note": {"type": "text"},
                    "recommended_actions": {"type": "text"}
                }
            }
        )
        print(f"Elasticsearch index '{ELASTIC_INDEX}' created.")
    except Exception as e:
        # Non-fatal: the app can still operate without Elasticsearch
        print(f"Elasticsearch index setup failed (is ES running?): {e}")


def index_alert(alert_doc: Dict[str, Any]) -> str:
    """
    Index an enriched alert document into Elasticsearch.

    Returns the Elasticsearch-assigned document ID.
    Raises an exception if indexing fails (callers should handle this).
    """
    client = get_es_client()
    response = client.index(index=ELASTIC_INDEX, document=alert_doc)
    return response["_id"]

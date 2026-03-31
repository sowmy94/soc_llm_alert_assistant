# elastic_service.py

import os
from typing import Dict, Any
from elasticsearch import Elasticsearch


ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "soc-alerts")


def get_es_client() -> Elasticsearch:
    return Elasticsearch(ELASTIC_URL)


def ensure_index():
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


def index_alert(alert_doc: Dict[str, Any]) -> str:
    client = get_es_client()
    response = client.index(index=ELASTIC_INDEX, document=alert_doc)
    return response["_id"]
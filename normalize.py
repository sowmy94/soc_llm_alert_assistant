# normalize.py

from typing import Dict, Any


def normalize_log(raw_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw log entry into a consistent normalized structure.

    Renames 'source' to 'alert_source' to avoid conflicts with Python
    builtins and to align with the Elasticsearch index mapping.
    All fields default to None if absent in the raw log.
    """
    return {
        "timestamp": raw_log.get("timestamp"),
        # Renamed from "source" to "alert_source" for clarity
        "alert_source": raw_log.get("source"),
        "event_type": raw_log.get("event_type"),
        "user": raw_log.get("user"),
        "host": raw_log.get("host"),
        "process_name": raw_log.get("process_name"),
        "command_line": raw_log.get("command_line"),
        "parent_process": raw_log.get("parent_process"),
    }

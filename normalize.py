# normalizer.py

from typing import Dict, Any


def normalize_log(raw_log: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": raw_log.get("timestamp"),
        "alert_source": raw_log.get("source"),
        "event_type": raw_log.get("event_type"),
        "user": raw_log.get("user"),
        "host": raw_log.get("host"),
        "process_name": raw_log.get("process_name"),
        "command_line": raw_log.get("command_line"),
        "parent_process": raw_log.get("parent_process"),
    }
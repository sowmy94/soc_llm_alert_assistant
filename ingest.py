# ingest.py

import json
from typing import List, Dict, Any


def load_logs(file_path: str = "sample_logs.json") -> List[Dict[str, Any]]:
    """
    Load log entries from a JSON file.

    The file must contain a JSON array of log objects.
    Raises FileNotFoundError if the path does not exist, or ValueError
    if the file content is not valid JSON.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse log file {file_path}: {e}")

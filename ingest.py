# ingest.py

import json
from typing import List, Dict, Any


def load_logs(file_path: str = "sample_logs.json") -> List[Dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)
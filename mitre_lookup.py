# mitre_lookup.py
# Utilities for loading and indexing the full MITRE ATT&CK enterprise dataset.

import json
from typing import Dict


def load_mitre_mappings(file_path: str) -> dict:
    """
    Load the MITRE ATT&CK enterprise-attack.json STIX bundle from disk.

    Raises FileNotFoundError if the path does not exist, or ValueError
    if the file is not valid JSON.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"MITRE data file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse MITRE JSON at {file_path}: {e}")


def build_mitre_lookup(data: dict) -> Dict[str, str]:
    """
    Build a flat technique_id → technique_name lookup from the STIX bundle.

    Iterates over all STIX objects, extracts attack-pattern entries, and
    maps their MITRE external ID (e.g. 'T1059') to their human-readable name.
    """
    lookup: Dict[str, str] = {}

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name")

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                if technique_id and name:
                    lookup[technique_id] = name

    return lookup

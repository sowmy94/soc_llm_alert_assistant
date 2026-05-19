# mitre.py
# Static MITRE ATT&CK technique mappings used by the rule-based detection engine.
# For broader coverage, use mitre_lookup.py to load the full MITRE enterprise-attack.json.

MITRE_MAPPINGS = {
    "powershell_encoded": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution"
    },
    "suspicious_cmd": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "Execution"
    }
}

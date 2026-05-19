# detect.py

from typing import Dict, Any, Optional

from mitre import MITRE_MAPPINGS


def detect_threat(normalized_log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply rule-based detection to a normalized log entry.

    Checks process name and command-line arguments against known suspicious
    patterns and returns a detection result with MITRE ATT&CK metadata.
    Returns a low-severity no-match result if no rules fire.
    """
    process_name = (normalized_log.get("process_name") or "").lower()
    command_line = (normalized_log.get("command_line") or "").lower()

    if process_name == "powershell.exe" and "-enc" in command_line:
        mitre = MITRE_MAPPINGS["powershell_encoded"]
        return {
            "matched": True,
            "rule_name": "encoded_powershell_execution",
            "severity": "high",
            "reason": "Encoded PowerShell execution detected",
            "technique_id": mitre["technique_id"],
            "technique_name": mitre["technique_name"],
            "tactic": mitre["tactic"]
        }

    if process_name == "cmd.exe" and "/c" in command_line:
        mitre = MITRE_MAPPINGS["suspicious_cmd"]
        return {
            "matched": True,
            "rule_name": "suspicious_cmd_execution",
            "severity": "medium",
            "reason": "Suspicious cmd.exe execution detected",
            "technique_id": mitre["technique_id"],
            "technique_name": mitre["technique_name"],
            "tactic": mitre["tactic"]
        }

    return {
        "matched": False,
        "rule_name": None,
        "severity": "low",
        "reason": "No suspicious activity detected",
        "technique_id": None,
        "technique_name": None,
        "tactic": None
    }


def detect_mitre_from_alert(alert_text: str, mitre_lookup: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Keyword-scan free-form alert text and return a MITRE technique match.

    Looks for known keywords in the alert text and maps them to MITRE
    technique IDs using the provided lookup dictionary.
    Returns None if no keyword matches.
    """
    alert_text = alert_text.lower()

    # Map commonly observed alert keywords to their MITRE technique IDs
    keyword_map = {
        "powershell": "T1059",
        "wmi": "T1047",
        "scheduled task": "T1053",
        "process injection": "T1055",
        "screen capture": "T1113",
        "vnc": "T1021"
    }

    for keyword, technique_id in keyword_map.items():
        if keyword in alert_text:
            technique_name = mitre_lookup.get(technique_id)
            return {
                "technique_id": technique_id,
                "technique_name": technique_name
            }

    return None

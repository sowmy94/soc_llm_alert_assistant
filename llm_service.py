# llm_service.py

from typing import Dict, Any


def explain_and_remediate(log: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    if not detection.get("matched"):
        return {
            "summary": "No suspicious activity was identified for this log.",
            "explanation": (
                "The event did not match the current suspicious behavior rules, "
                "so it is treated as low priority at this stage."
            ),
            "remedy": (
                "No immediate action is required. Continue monitoring and correlate "
                "with other events if needed."
            )
        }

    host = log.get("host", "unknown host")
    user = log.get("user", "unknown user")
    process_name = log.get("process_name", "unknown process")
    reason = detection.get("reason", "Suspicious behavior detected")
    technique_id = detection.get("technique_id", "Unknown")
    technique_name = detection.get("technique_name", "Unknown")
    tactic = detection.get("tactic", "Unknown")
    severity = detection.get("severity", "medium")

    return {
        "summary": (
            f"Suspicious activity was detected on host {host}. "
            f"User {user} executed {process_name}."
        ),
        "explanation": (
            f"The alert was triggered because {reason}. "
            f"This behavior maps to MITRE ATT&CK {technique_id} ({technique_name}) "
            f"under the {tactic} tactic. "
            f"The assigned severity is {severity}."
        ),
        "remedy": (
            "Review the command line and parent process, verify whether the activity "
            "was authorized, check for related child processes or network connections, "
            "and isolate the endpoint if malicious behavior is confirmed."
        )
    }
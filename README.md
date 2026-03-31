# SOC LLM Alert Assistant

## Overview

SOC LLM Alert Assistant is a proof-of-concept security automation system that analyzes security logs, detects suspicious activity using rule-based logic mapped to MITRE ATT&CK techniques, enriches alerts with Large Language Model (LLM) explanations, and stores results for search and investigation.

The system demonstrates how modern Security Operations Centers (SOC) can combine **Python automation, MITRE ATT&CK mapping, LLM analysis, and Elasticsearch-based threat hunting** to accelerate incident investigation.

---

## Architecture

```
Log Input
   ↓
Log Ingestion (FastAPI API)
   ↓
Log Normalization
   ↓
Detection Engine (MITRE technique mapping)
   ↓
LLM Enrichment (Explanation & remediation)
   ↓
Alert Storage
   ├ MongoDB (persistent storage)
   └ Elasticsearch (threat hunting & search)
```

---

## Features

* Log ingestion through FastAPI REST API
* Log normalization for consistent data structure
* Rule-based detection engine
* MITRE ATT&CK technique mapping
* LLM-powered alert explanation and remediation guidance
* Alert storage in MongoDB
* Alert indexing in Elasticsearch for threat hunting
* Simple SOC automation pipeline

---

## Technology Stack

| Component          | Technology                 |
| ------------------ | -------------------------- |
| API Framework      | FastAPI                    |
| Language           | Python                     |
| Database           | MongoDB                    |
| Search Engine      | Elasticsearch              |
| Security Framework | MITRE ATT&CK               |
| AI Integration     | Large Language Model (LLM) |
| Data Validation    | Pydantic                   |

---

## Project Structure

```
soc_llm_alert_assistant/

main.py
ingest.py
normalize.py
detect.py
mitre_lookup.py
llm_service.py
elastic_search.py
database.py
Data/
   enterprise-attack.json
README.md
```

---

## Detection Example

Example suspicious activity detected by the system:

```
Process: powershell.exe
Command: powershell.exe -enc SQBFAFgA
Parent: winword.exe
```

Detection Output:

```
Technique ID: T1059
Technique Name: Command and Scripting Interpreter
Severity: High
Reason: Encoded PowerShell execution detected
```

---

## MITRE ATT&CK Mapping

Example mappings used in the detection engine:

| Technique ID | Technique Name                     |
| ------------ | ---------------------------------- |
| T1059        | Command and Scripting Interpreter  |
| T1047        | Windows Management Instrumentation |
| T1053        | Scheduled Task                     |
| T1055        | Process Injection                  |
| T1021        | Remote Services                    |
| T1113        | Screen Capture                     |

---

## Installation

### 1. Clone the repository

```
git clone https://github.com/yourusername/soc-llm-alert-assistant.git
cd soc-llm-alert-assistant
```

### 2. Create virtual environment

```
python -m venv .venv
```

Activate:

Windows

```
.venv\Scripts\activate
```

Linux / Mac

```
source .venv/bin/activate
```

### 3. Install dependencies

```
pip install fastapi uvicorn pymongo elasticsearch pydantic
```

---

## Start Required Services

### MongoDB

Ensure MongoDB is running locally

```
mongod
```

---

### Elasticsearch

Ensure Elasticsearch is running

```
http://localhost:9200
```

---

## Run the Application

```
uvicorn main:app --reload
```

API documentation:

```
http://127.0.0.1:8000/docs
```

---

## API Endpoints

### Analyze Single Log

```
POST /analyze-one-log
```

Example request:

```json
{
  "timestamp": "2026-03-30T20:10:11Z",
  "source": "sysmon",
  "event_type": "process_create",
  "user": "corp\\analyst",
  "host": "wkstn-01",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc SQBFAFgA",
  "parent_process": "winword.exe"
}
```

Response:

```
Detection result
MITRE technique mapping
LLM explanation
Alert stored in MongoDB
Alert indexed in Elasticsearch
```

---

### Analyze Sample Logs

```
GET /analyze-logs
```

Processes sample log dataset.

---

### Retrieve Stored Alert

```
GET /stored-alerts/{alert_id}
```

Fetch stored alert from MongoDB.

---

## Example Alert Pipeline

```
Input Log
    ↓
Normalization
    ↓
Detection Rule
    ↓
MITRE Technique Mapping
    ↓
LLM Explanation
    ↓
Alert Storage
```

---

## Use Cases

* SOC alert triage automation
* Threat detection experimentation
* MITRE ATT&CK based detection engineering
* LLM-assisted security analysis
* Security automation proof of concept

---

## Future Improvements

* Integration with SIEM log sources
* Real-time log streaming
* Automated response actions
* Advanced threat hunting queries
* Kibana dashboards
* RAG-based threat intelligence enrichment

---

## Author

Sowmya Srinivasan


---

## License

This project is for educational and demonstration purposes.

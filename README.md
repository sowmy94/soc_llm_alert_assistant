# SOC LLM Alert Assistant

## Overview

SOC LLM Alert Assistant is a proof-of-concept security automation system that analyzes security logs, detects suspicious activity using rule-based logic mapped to MITRE ATT&CK techniques, enriches alerts with LLM-style explanations, and stores results for search and investigation.

The system demonstrates how modern Security Operations Centers (SOC) can combine **Python automation, MITRE ATT&CK mapping, LLM analysis, and Elasticsearch-based threat hunting** to accelerate incident investigation.

> **Note:** The LLM enrichment module (`llm_service.py`) is currently a rule-based stub that generates structured analyst notes. Replace the return values with real LLM API calls (e.g. Anthropic Claude, OpenAI) to add dynamic, context-aware analysis.

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
   ├── MongoDB (persistent storage)
   └── Elasticsearch (threat hunting & search)
```

---

## Features

* Log ingestion through FastAPI REST API
* Log normalization for consistent data structure
* Rule-based detection engine with MITRE ATT&CK technique mapping
* LLM-ready enrichment layer for analyst notes and remediation guidance
* Alert persistence in MongoDB
* Alert indexing in Elasticsearch for threat hunting
* Graceful Elasticsearch failure handling — MongoDB path is unaffected if ES is down

---

## Technology Stack

| Component          | Technology                 |
| ------------------ | -------------------------- |
| API Framework      | FastAPI                    |
| Language           | Python 3.10+               |
| Database           | MongoDB                    |
| Search Engine      | Elasticsearch              |
| Security Framework | MITRE ATT&CK               |
| AI Integration     | LLM stub (pluggable)       |
| Data Validation    | Pydantic                   |

---

## Project Structure

```
soc_llm_alert_assistant/
├── main.py           # FastAPI app, pipeline orchestration, API endpoints
├── ingest.py         # Log file loading
├── normalize.py      # Raw log → normalized schema
├── detect.py         # Rule-based threat detection + MITRE keyword scanner
├── mitre.py          # Static MITRE ATT&CK technique mappings
├── mitre_lookup.py   # Full MITRE enterprise-attack.json loader & index builder
├── llm_service.py    # Alert enrichment (analyst note + remediation guidance)
├── elastic_search.py # Elasticsearch index management and document indexing
├── database.py       # MongoDB connection and CRUD helpers
├── requirement.txt   # Python dependencies
├── sample_logs.json  # Sample log entries for testing
└── Data/
    └── enterprise-attack.json  # MITRE ATT&CK STIX bundle
```

---

## Alert Pipeline Data Flow

Each log entry passes through these pipeline stages:

| Stage        | Module            | Output key(s) added                                      |
| ------------ | ----------------- | -------------------------------------------------------- |
| Ingest       | `ingest.py`       | Raw log dict                                             |
| Normalize    | `normalize.py`    | `alert_source`, `event_type`, `user`, `host`, etc.       |
| Detect       | `detect.py`       | `matched`, `rule_name`, `severity`, `technique_id`, etc. |
| LLM Enrich   | `llm_service.py`  | `summary`, `analyst_note`, `recommended_actions`         |
| Store        | `database.py`     | MongoDB `_id`                                            |
| Index        | `elastic_search.py` | Elasticsearch `_id`                                    |

---

## Detection Example

Suspicious activity detected by the system:

```
Process:  powershell.exe
Command:  powershell.exe -enc SQBFAFgA
Parent:   winword.exe
```

Detection output:

```json
{
  "matched": true,
  "rule_name": "encoded_powershell_execution",
  "severity": "high",
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "tactic": "Execution",
  "reason": "Encoded PowerShell execution detected"
}
```

---

## MITRE ATT&CK Mapping

Static mappings used by the detection engine (`mitre.py`):

| Rule Key              | Technique ID | Technique Name       | Tactic    |
| --------------------- | ------------ | -------------------- | --------- |
| `powershell_encoded`  | T1059.001    | PowerShell           | Execution |
| `suspicious_cmd`      | T1059.003    | Windows Command Shell| Execution |

Keyword-based mappings used by `detect_mitre_from_alert`:

| Keyword          | Technique ID | Technique Name                     |
| ---------------- | ------------ | ---------------------------------- |
| powershell       | T1059        | Command and Scripting Interpreter  |
| wmi              | T1047        | Windows Management Instrumentation |
| scheduled task   | T1053        | Scheduled Task                     |
| process injection| T1055        | Process Injection                  |
| screen capture   | T1113        | Screen Capture                     |
| vnc              | T1021        | Remote Services                    |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/soc-llm-alert-assistant.git
cd soc-llm-alert-assistant
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows:
```bash
.venv\Scripts\activate
```

Linux / Mac:
```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirement.txt
```

---

## Start Required Services

### MongoDB

```bash
mongod
```

Default connection: `mongodb://localhost:27017/`

### Elasticsearch

Start Elasticsearch and verify it is reachable:

```
http://localhost:9200
```

The application will attempt to create the `soc-alerts` index at startup. If Elasticsearch is unavailable, startup continues and only the ES-indexing path will fail.

---

## Environment Variables

| Variable        | Default                  | Description                          |
| --------------- | ------------------------ | ------------------------------------ |
| `ELASTIC_URL`   | `http://localhost:9200`  | Elasticsearch base URL               |
| `ELASTIC_INDEX` | `soc-alerts`             | Name of the Elasticsearch index      |

---

## Run the Application

```bash
uvicorn main:app --reload
```

Interactive API docs:

```
http://127.0.0.1:8000/docs
```

---

## API Endpoints

### `POST /analyze-one-log` — Analyze a single log

Submit a log entry for analysis. The enriched alert is stored in MongoDB and indexed in Elasticsearch.

Request body:

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

Response fields:

| Field                | Description                                 |
| -------------------- | ------------------------------------------- |
| `db_id`              | MongoDB ObjectId of the stored alert        |
| `elasticsearch_id`   | Elasticsearch document ID (null if ES down) |
| `elasticsearch_error`| Error message if ES indexing failed         |
| `result`             | Full enriched alert document                |

---

### `GET /analyze-logs` — Analyze the sample dataset

Processes all entries in `sample_logs.json` through the full pipeline and indexes each into Elasticsearch. A single ES failure does not abort the batch.

---

### `GET /stored-alerts/{alert_id}` — Retrieve a stored alert

Fetch a previously stored alert from MongoDB by its ObjectId string.

---

## Example Full Alert Document

```json
{
  "timestamp": "2026-03-29T10:30:00Z",
  "alert_source": "sysmon",
  "event_type": "process_create",
  "user": "admin",
  "host": "server01",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc ZQBjAGgAbwAgAGgAZQBsAGwAbwA=",
  "parent_process": "cmd.exe",
  "matched": true,
  "rule_name": "encoded_powershell_execution",
  "severity": "high",
  "reason": "Encoded PowerShell execution detected",
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "tactic": "Execution",
  "llm_summary": "Suspicious activity was detected on host server01. User admin executed powershell.exe.",
  "analyst_note": "The alert was triggered because Encoded PowerShell execution detected. This behavior maps to MITRE ATT&CK T1059.001 (PowerShell) under the Execution tactic. The assigned severity is high.",
  "recommended_actions": "Review the command line and parent process, verify whether the activity was authorized, check for related child processes or network connections, and isolate the endpoint if malicious behavior is confirmed."
}
```

---

## Use Cases

* SOC alert triage automation
* Threat detection experimentation
* MITRE ATT&CK based detection engineering
* LLM-assisted security analysis proof of concept
* Security automation pipeline reference implementation

---

## Future Improvements

* Plug in a real LLM API (Anthropic Claude, OpenAI) in `llm_service.py`
* Integration with live SIEM log sources
* Real-time log streaming via Kafka or similar
* Automated response actions (endpoint isolation, user suspension)
* Advanced Elasticsearch threat hunting queries
* Kibana dashboards for alert visualization
* RAG-based threat intelligence enrichment

---

## Author

Sowmya Srinivasan

---

## License

This project is for educational and demonstration purposes.

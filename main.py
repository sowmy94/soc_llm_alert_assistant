from contextlib import asynccontextmanager
from typing import Dict, Any, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ingest import load_logs
from normalize import normalize_log
from detect import detect_threat
from llm_service import explain_and_remediate
from database import insert_alert, get_alert
from elastic_search import ensure_index, index_alert


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create the Elasticsearch index on startup if it doesn't exist
    ensure_index()
    yield


app = FastAPI(title="SOC LLM Alert Assistant", version="1.0", lifespan=lifespan)


class LogRequest(BaseModel):
    timestamp: str | None = None
    source: str | None = None
    event_type: str | None = None
    user: str | None = None
    host: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None


def build_final_alert(
    raw_log: Dict[str, Any],
    normalized_log: Dict[str, Any],
    detection: Dict[str, Any],
    llm_output: Dict[str, Any]
) -> Dict[str, Any]:
    """Assemble the enriched alert document from pipeline stage outputs."""
    return {
        "timestamp": normalized_log.get("timestamp"),
        # Bug fix: normalized_log uses "alert_source" (renamed from raw "source")
        "alert_source": normalized_log.get("alert_source"),
        "event_type": normalized_log.get("event_type"),
        "user": normalized_log.get("user"),
        "host": normalized_log.get("host"),
        "process_name": normalized_log.get("process_name"),
        "command_line": normalized_log.get("command_line"),
        "parent_process": normalized_log.get("parent_process"),
        "matched": detection.get("matched"),
        "rule_name": detection.get("rule_name"),
        "severity": detection.get("severity"),
        "reason": detection.get("reason"),
        "technique_id": detection.get("technique_id"),
        "technique_name": detection.get("technique_name"),
        "tactic": detection.get("tactic"),
        "llm_summary": llm_output.get("summary"),
        # Bug fix: llm_service returns "analyst_note" and "recommended_actions"
        "analyst_note": llm_output.get("analyst_note"),
        "recommended_actions": llm_output.get("recommended_actions"),
        "raw_log": raw_log
    }


@app.get("/")
def root():
    return {"message": "SOC LLM Alert Assistant API is running"}


@app.get("/analyze-logs")
def analyze_logs():
    """
    Process all logs in the sample dataset through the full alert pipeline.
    Each log is normalized, checked for threats, enriched by the LLM, and
    indexed into Elasticsearch. Returns all enriched alerts.
    """
    raw_logs = load_logs()
    results: List[Dict[str, Any]] = []

    for raw_log in raw_logs:
        normalized_log = normalize_log(raw_log)
        detection = detect_threat(normalized_log)
        llm_output = explain_and_remediate(normalized_log, detection)

        final_alert = build_final_alert(raw_log, normalized_log, detection, llm_output)

        # Wrap ES indexing per-log so one failure doesn't abort the whole batch
        es_id = None
        es_error = None
        try:
            es_id = index_alert(final_alert)
        except Exception as e:
            es_error = str(e)

        results.append({
            "elasticsearch_id": es_id,
            "elasticsearch_error": es_error,
            "result": final_alert
        })

    return {
        "total_logs": len(results),
        "results": results
    }


@app.post("/analyze-one-log")
def analyze_one_log(log: LogRequest):
    """
    Analyze a single log entry submitted via the request body.
    The alert is persisted to MongoDB and indexed in Elasticsearch.
    Elasticsearch failures are non-fatal and reported in the response.
    """
    raw_log = log.model_dump()
    normalized_log = normalize_log(raw_log)
    detection = detect_threat(normalized_log)
    llm_output = explain_and_remediate(normalized_log, detection)

    final_alert = build_final_alert(raw_log, normalized_log, detection, llm_output)

    # Strip any MongoDB _id field that might exist before inserting
    alert_to_store = final_alert.copy()
    alert_to_store.pop("_id", None)

    try:
        alert_id = insert_alert(alert_to_store)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MongoDB insert failed: {str(e)}")

    es_id = None
    es_error = None

    try:
        es_id = index_alert(final_alert)
    except Exception as e:
        es_error = str(e)

    return {
        "db_id": alert_id,
        "elasticsearch_id": es_id,
        "elasticsearch_error": es_error,
        "result": final_alert
    }


@app.get("/stored-alerts/{alert_id}")
def get_stored_alerts(alert_id: str):
    """Fetch a previously stored alert from MongoDB by its ObjectId string."""
    alert = get_alert(alert_id)
    if alert:
        return {"alert": alert}
    return {"message": "Alert not found"}

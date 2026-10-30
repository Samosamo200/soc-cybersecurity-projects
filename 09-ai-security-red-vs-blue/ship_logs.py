"""
Forward the assistant's logs to Microsoft Sentinel (Log Analytics table AIAssistant_CL).

Works like a small log forwarder: it sends only the lines that are new since the last run,
using the Logs Ingestion API and Entra ID (no keys). Run setup\\setup_logging.ps1 first.

Usage:
    python ship_logs.py
"""

import json
import os

from azure.core.exceptions import HttpResponseError
from azure.monitor.ingestion import LogsIngestionClient
from dotenv import load_dotenv

from app.assistant import LOG_FILE
from app.client import get_credential

STREAM = "Custom-AIAssistant"
STATE_FILE = LOG_FILE.with_name(".shipped")  # how many lines have already been sent


def to_row(record):
    return {
        "TimeGenerated": record["timestamp"],
        "Mode": record.get("mode", "baseline"),
        "UserName": record.get("user"),
        "Question": record.get("question"),
        "RetrievedDocs": record.get("retrieved_docs", []),
        "Answer": record.get("answer") or "",
        "Blocked": bool(record.get("blocked")),
        "BlockedBy": record.get("blocked_by") or "",
        "DefensesTriggered": record.get("defenses_triggered", []),
        "Leaks": record.get("leaks", []),
    }


def main():
    load_dotenv()
    endpoint = os.environ.get("LOGS_INGESTION_ENDPOINT")
    rule_id = os.environ.get("LOGS_DCR_IMMUTABLE_ID")
    if not endpoint or not rule_id:
        raise SystemExit("LOGS_INGESTION_ENDPOINT or LOGS_DCR_IMMUTABLE_ID is missing in .env. "
                         "Run setup\\setup_logging.ps1 first.")

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines() if LOG_FILE.exists() else []
    already_shipped = int(STATE_FILE.read_text()) if STATE_FILE.exists() else 0
    new_records = [json.loads(line) for line in lines[already_shipped:] if line.strip()]
    if not new_records:
        print("Nothing new to ship.")
        return

    client = LogsIngestionClient(endpoint=endpoint, credential=get_credential())
    try:
        client.upload(rule_id=rule_id, stream_name=STREAM, logs=[to_row(r) for r in new_records])
    except HttpResponseError as e:
        if e.status_code == 403:
            raise SystemExit("Access denied (403). The 'Monitoring Metrics Publisher' role can take up to "
                             "30 minutes to become active. Wait and try again.")
        raise
    STATE_FILE.write_text(str(len(lines)))
    print(f"Shipped {len(new_records)} events to AIAssistant_CL. They show up in Log Analytics after 5-10 minutes.")


if __name__ == "__main__":
    main()

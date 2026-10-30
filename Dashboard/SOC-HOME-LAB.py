#!/usr/bin/env python3
"""Score Wazuh FIM alerts locally and expose analyses to Grafana."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from waitress import serve

LOCAL_API_KEY = os.environ["LOCAL_API_KEY"]
LOCAL_API_HEADER = os.getenv("LOCAL_API_HEADER", "X-API-Key")
WAZUH_ALERTS_FILE = Path(os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
ANALYSES_FILE = Path(os.getenv("ANALYSES_FILE", "/var/lib/wazuh-airia-forwarder/analyses.jsonl"))
STATE_FILE = Path(os.getenv("STATE_FILE", "/var/lib/wazuh-airia-forwarder/state.json"))
BIND_HOST = os.getenv("BIND_HOST", "192.168.1.109")
BIND_PORT = int(os.getenv("BIND_PORT", "8010"))
FORWARD_EXISTING_ON_FIRST_START = os.getenv("FORWARD_EXISTING_ON_FIRST_START", "false").lower() == "true"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
LOG = logging.getLogger("wazuh-local-scorer")
FILE_LOCK = threading.RLock()
STOP_EVENT = threading.Event()
app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def file_event(alert: dict[str, Any]) -> tuple[str, str] | None:
    rule = alert.get("rule") or {}
    groups = rule.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    syscheck = alert.get("syscheck") or {}
    event = str(syscheck.get("event") or "").lower()
    path = str(syscheck.get("path") or "").strip()
    if "syscheck" not in groups or event not in {"added", "modified", "deleted"} or not path:
        return None
    return event, path


def make_event_id(alert: dict[str, Any], event: str, path: str) -> str:
    source = "|".join([
        str(alert.get("id") or ""),
        str(alert.get("timestamp") or ""),
        str((alert.get("agent") or {}).get("id") or ""),
        event,
        path,
    ])
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:24]


SENSITIVE_PATHS = [
    ("\\start menu\\programs\\startup", 35, "file is in a Startup folder (persistence location)"),
    ("\\system32\\drivers\\etc\\hosts", 35, "hosts file was touched"),
    ("\\windows\\system32", 30, "path is inside Windows system32"),
    ("\\windows\\syswow64", 30, "path is inside Windows syswow64"),
    ("\\windows\\tasks", 30, "path is in the scheduled tasks folder"),
    ("\\program files", 15, "path is inside Program Files"),
    ("\\programdata", 10, "path is inside ProgramData"),
]
EXEC_EXT = {
    ".exe": 25, ".dll": 25, ".sys": 25, ".scr": 25, ".ps1": 25, ".vbs": 25,
    ".bat": 20, ".cmd": 20, ".msi": 20, ".js": 15, ".lnk": 15, ".jar": 15,
}
BASE = {"added": 10, "modified": 15, "deleted": 15}


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    if score >= 30:
        return "Guarded"
    return "Low"


def local_analysis(alert: dict[str, Any], event: str, path: str) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    lowered = path.lower()
    score = BASE.get(event, 10) + min(15, safe_int(rule.get("level")))
    evidence = [f"File {event}: {path}", f"Wazuh rule level {rule.get('level')}: {rule.get('description')}"]
    flagged = False
    for needle, points, reason in SENSITIVE_PATHS:
        if needle in lowered:
            score += points
            evidence.append(reason.capitalize())
            flagged = True
            break
    ext = os.path.splitext(lowered)[1]
    if ext in EXEC_EXT:
        score += EXEC_EXT[ext]
        evidence.append(f"Executable or script type ({ext})")
        flagged = True
    if event == "deleted" and flagged:
        score += 10
    score = max(0, min(100, score))
    severity = severity_from_score(score)
    name = f"File {event}: {os.path.basename(path.replace(chr(92), '/')) or path}"
    summary = (
        f"A file was {event} on {agent.get('name') or 'an endpoint'}: {path}. "
        + ("; ".join(e for e in evidence[2:]) + ". " if len(evidence) > 2 else "No sensitive path or executable type was found. ")
        + "This score is rule-based (event type, path, extension, Wazuh level); confirm with a human review."
    )
    actions = [
        "Confirm whether the change was expected by the file owner.",
        "Open the event in Wazuh and review the hashes and changed attributes.",
    ]
    if flagged:
        actions += ["Check the file against a malware scanner or VirusTotal hash lookup.",
                    "Review recent logons and process activity on the endpoint."]
    else:
        actions += ["If routine, no further action is needed."]
    return {
        "alert_name": name,
        "risk_score": score,
        "severity": severity,
        "confidence": "Medium" if flagged else "Low",
        "summary": summary[:4000],
        "evidence": evidence,
        "recommended_actions": actions,
    }


def build_record(alert: dict[str, Any], event: str, path: str) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    a = local_analysis(alert, event, path)
    return {
        "analysis_timestamp": utc_now(),
        "alert_timestamp": alert.get("timestamp"),
        "event_id": make_event_id(alert, event, path),
        **a,
        "evidence_text": " | ".join(a["evidence"]),
        "recommended_actions_text": " | ".join(a["recommended_actions"]),
        "file_event": event,
        "file_path": path,
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
    }


def append_analysis(record: dict[str, Any]) -> None:
    ANALYSES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with FILE_LOCK, ANALYSES_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_state() -> dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_state(inode: int, offset: int) -> None:
    temp = STATE_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps({"inode": inode, "offset": offset, "updated_at": utc_now()}), encoding="utf-8")
    os.replace(temp, STATE_FILE)


def process_alert(alert: dict[str, Any]) -> None:
    matched = file_event(alert)
    if not matched:
        return
    event, path = matched
    record = build_record(alert, event, path)
    append_analysis(record)
    LOG.info("Stored analysis event=%s path=%s score=%s", event, path, record["risk_score"])


def tail_alerts() -> None:
    state = read_state()
    first_open = True
    while not STOP_EVENT.is_set():
        try:
            stat = WAZUH_ALERTS_FILE.stat()
            inode = int(stat.st_ino)
            if first_open:
                if state.get("inode") == inode:
                    offset = min(safe_int(state.get("offset")), stat.st_size)
                elif FORWARD_EXISTING_ON_FIRST_START:
                    offset = 0
                else:
                    offset = stat.st_size
                write_state(inode, offset)
                state = {"inode": inode, "offset": offset}
                first_open = False
            elif state.get("inode") != inode or safe_int(state.get("offset")) > stat.st_size:
                offset = 0
            else:
                offset = safe_int(state.get("offset"))

            with WAZUH_ALERTS_FILE.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while not STOP_EVENT.is_set():
                    line = handle.readline()
                    if not line or not line.endswith("\n"):
                        break
                    try:
                        process_alert(json.loads(line))
                    except json.JSONDecodeError:
                        LOG.warning("Skipped malformed JSON line")
                    offset = handle.tell()
                    write_state(inode, offset)
                    state = {"inode": inode, "offset": offset}
        except FileNotFoundError:
            LOG.error("Wazuh alerts file not found: %s", WAZUH_ALERTS_FILE)
        except PermissionError:
            LOG.exception("Permission denied reading or writing a service file")
        except Exception:
            LOG.exception("Unexpected error")
        STOP_EVENT.wait(1)


def load_analyses(limit: int) -> list[dict[str, Any]]:
    if not ANALYSES_FILE.exists():
        return []
    records: deque[dict[str, Any]] = deque(maxlen=max(1, min(limit, 1000)))
    with FILE_LOCK, ANALYSES_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(records)


@app.before_request
def protect_api():
    if not request.path.startswith("/api/"):
        return None
    supplied = request.headers.get(LOCAL_API_HEADER, "")
    if not hmac.compare_digest(supplied.encode(), LOCAL_API_KEY.encode()):
        return jsonify({"error": "unauthorized"}), 401
    return None


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "bind_host": BIND_HOST,
        "alerts_readable": os.access(WAZUH_ALERTS_FILE, os.R_OK),
        "analyses_writable": os.access(ANALYSES_FILE.parent, os.W_OK),
    })


@app.get("/api/latest")
def latest_analysis():
    records = load_analyses(1)
    if records:
        return jsonify(records[-1])
    return jsonify({
        "analysis_timestamp": None, "alert_timestamp": None,
        "alert_name": "No analysis received yet", "risk_score": 0,
        "severity": "None", "confidence": "None",
        "summary": "Generate a Wazuh file-integrity event to populate this panel.",
        "recommended_actions_text": "", "file_event": "none", "file_path": "",
        "agent_name": "", "rule_id": "", "rule_level": 0,
    })


@app.get("/api/analyses")
def analysis_history():
    return jsonify({"analyses": load_analyses(safe_int(request.args.get("limit"), 100))})


def main() -> None:
    threading.Thread(target=tail_alerts, name="wazuh-alert-tailer", daemon=True).start()
    LOG.info("Serving Grafana API on http://%s:%s", BIND_HOST, BIND_PORT)
    serve(app, host=BIND_HOST, port=BIND_PORT, threads=4)


if __name__ == "__main__":
    main()




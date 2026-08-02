from typing import Optional, Dict, Any
import os
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Re-read ES config from environment (or import from config if extracted later)
ES_HOST   = os.environ.get("ES_HOST", "https://elasticsearch:9200")
ES_USER   = os.environ.get("ES_USER", "logstash_internal")
ES_PASS   = os.environ.get("ES_PASS", "")
ES_CA     = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

def _get_auth():
    return (ES_USER, ES_PASS) if ES_USER else None

def generate_dedup_key(tenant_id: str, target_ip: str, target_mac: str, severity: str) -> str:
    """Generates a Semantic Deduplication Key using 5m time buckets."""
    bucket = int(time.time()) // 300
    raw = f"{tenant_id}|{target_ip}|{target_mac}|{severity}|{bucket}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def write_checkpoint(tenant_id: str, alert_id: str, phase: str, context: Optional[Dict[str, Any]] = None):
    """Upserts a phase transition to the agent-checkpoints-<tenant> index."""
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_doc/{alert_id}"
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant": {"id": tenant_id},
        "alert_id": alert_id,
        "phase": phase
    }
    if context is not None:
        doc["context"] = context

    res = requests.put(url, json=doc, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    res.raise_for_status()
    logger.info(f"Checkpoint written: {alert_id} -> {phase}")

def read_checkpoint(tenant_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
    """Loads the latest checkpoint from ES for crash resume/idempotency."""
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_doc/{alert_id}"
    res = requests.get(url, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if res.status_code == 404:
        return None
    res.raise_for_status()
    return res.json().get("_source")

def is_duplicate(tenant_id: str, alert_id: str) -> bool:
    """Checks if the alert has already been processed (idempotency gate)."""
    ckpt = read_checkpoint(tenant_id, alert_id)
    if not ckpt:
        return False
    # If a checkpoint exists, it's either in progress (PENDING_APPROVAL) or terminal.
    return True

def is_awaiting_approval(tenant_id: str, alert_id: str) -> bool:
    """Validates if the alert is in PENDING_APPROVAL state."""
    ckpt = read_checkpoint(tenant_id, alert_id)
    if not ckpt:
        return False
    return ckpt.get("phase") == "PENDING_APPROVAL"

def claim_approval(tenant_id: str, alert_id: str, approver: str) -> bool:
    """Atomically claims an approval so at most one /approve execution wins (#214).

    Uses ES op_type=create as the atomicity primitive rather than a
    threading.Lock: a lock only protects a single process, and the agent's
    gunicorn --workers 1 pin is itself a fragile constraint this claim
    shouldn't depend on staying true. First writer gets 201 and wins; every
    other writer for the same alert_id gets 409 and loses. Any other error
    (ES unreachable, 5xx) propagates — callers must fail closed on a lost or
    unconfirmed claim, since duplicate isolation is worse than a delayed one.
    """
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_create/{alert_id}.claim"
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant": {"id": tenant_id},
        "alert_id": alert_id,
        "approver": approver,
        "phase": "CLAIMED",
    }
    res = requests.put(url, json=doc, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if res.status_code == 409:
        return False
    res.raise_for_status()
    return True

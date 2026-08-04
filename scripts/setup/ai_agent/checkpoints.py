from typing import Optional, Dict, Any
import os
import time
import hashlib
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Re-read ES config from environment (or import from config if extracted later).
# #245: a dedicated credential, not the shared ES_USER/ES_PASS agent.py's other
# writes (soar-actions/soc-audit/soc-agent-health) and the real Logstash pipeline
# all use (logstash_internal) - granting agent-checkpoints-* access to that shared
# identity would hand it to Logstash too, which has no business touching this index.
ES_HOST   = os.environ.get("ES_HOST", "https://elasticsearch:9200")
ES_USER   = os.environ.get("AGENT_CHECKPOINTS_ES_USER", "agent_checkpoints")
ES_PASS   = os.environ.get("AGENT_CHECKPOINTS_ES_PASS", "")
ES_CA     = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

def _get_auth():
    return (ES_USER, ES_PASS) if ES_USER else None

def generate_dedup_key(tenant_id: str, target_ip: str, target_mac: str, severity: str) -> str:
    """Generates a Semantic Deduplication Key using 5m time buckets."""
    bucket = int(time.time()) // 300
    raw = f"{tenant_id}|{target_ip}|{target_mac}|{severity}|{bucket}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def should_suppress_technique(tenant_id: str, host: str, technique: str, severity: str = "",
                               window_seconds: int = 900, max_duration_seconds: int = 3600) -> bool:
    """Bounded sliding host+technique suppression window (#220).

    Deliberately parallel to, and independent of, generate_dedup_key's 5-min
    tumbling window over tenant|ip|mac|severity - that key is the agent's
    alert_id, the load-bearing primary key for the whole
    PERCEIVING -> PENDING_APPROVAL -> CLAIMED -> EXECUTED checkpoint/
    approval-claim lifecycle (#214), and must not change shape. This
    suppresses a DIFFERENT class of duplicate: the same technique repeatedly
    firing against the same host, independent of exact IP/MAC/severity and
    not bounded by a 5-minute tumbling edge.

    Not a security gate (unlike claim_approval's atomic op_type=create) - a
    race between two concurrent firings both reading "not suppressed" and
    both writing is tolerated (worst case: one extra actionable alert
    instead of the intended one), so this is a plain read-then-write, not an
    atomic create. Callers should fail OPEN (treat as "not suppressed") on
    an ES error here, matching this module's intake-leniency posture
    elsewhere (unlike the /approve execution gate, under-suppressing is the
    safe failure direction, not over-suppressing).

    security-auditor review of the first version of this function (which had
    neither of the two caps below) found it was a keep-alive evasion
    primitive: refreshing last_seen on every firing with NO ceiling meant a
    sustained attack - anything firing faster than once per window_seconds -
    suppressed itself permanently after the very first alert, forever. Worse
    than no suppression at all. Two independent caps close this:
      - max_duration_seconds: even mid-window, force a fresh alert once this
        many seconds have elapsed since the window opened (first_seen), so
        an ongoing attack still re-alerts periodically instead of going
        silent for good.
      - severity escalation: a "critical" firing always breaks through a
        window that hasn't seen "critical" yet, matching the only severity
        distinction this codebase otherwise makes (agent.py checks
        `severity == "critical"` exactly, never a graded ranking) - so e.g.
        a medium T1110 doesn't suppress a subsequent critical T1110 against
        the same host.
    suppressed_count is tracked (and reset whenever suppression breaks) so a
    caller can record how many firings a given alert actually represents.
    """
    if not host or not technique:
        # Nothing to key on - never suppress. A missing host/technique on
        # this path should surface as its own alert, not silently vanish.
        return False

    index = f"agent-checkpoints-{tenant_id}"
    doc_id = "suppress:" + hashlib.sha256(f"{host}|{technique}".encode('utf-8')).hexdigest()
    url = f"{ES_HOST}/{index}/_doc/{doc_id}"
    now = time.time()

    res = requests.get(url, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    suppress = False
    first_seen = now
    suppressed_count = 0
    max_severity = severity
    if res.status_code == 200:
        src = res.json().get("_source", {})
        last_seen = src.get("last_seen", 0)
        first_seen = src.get("first_seen", now)
        prior_max_severity = src.get("max_severity", "")
        escalated = severity == "critical" and prior_max_severity != "critical"
        suppress = ((now - last_seen) < window_seconds
                    and (now - first_seen) < max_duration_seconds
                    and not escalated)
        if suppress:
            suppressed_count = src.get("suppressed_count", 0) + 1
            max_severity = prior_max_severity
        else:
            first_seen = now  # window resets: fresh burst starts here
    elif res.status_code != 404:
        res.raise_for_status()

    put_res = requests.put(url, json={
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant": {"id": tenant_id},
        "host": host,
        "technique": technique,
        "last_seen": now,
        "first_seen": first_seen,
        "suppressed_count": suppressed_count,
        "max_severity": max_severity,
    }, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    put_res.raise_for_status()

    return suppress

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

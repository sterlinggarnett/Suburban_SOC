"""
app.py — Hive-Mind broker: authenticated router-block dispatcher (#109).

The AI agent's slim container has no ssh/sudo, so it routes containment here
over an HMAC-signed webhook (/webhook/dispatch); Kibana can also hit
/webhook/alert directly to draft a block for human approval (/pending,
/approve). The broker owns the per-tenant router inventory (WS0.3 — a block
never reaches another tenant's routers) and the §12.4 permanent exclusion
list (never dispatched, signed or not), and applies the nftables block over
SSH via dispatcher.py.
"""

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
import uvicorn
import hmac
import hashlib
import json
import time
import uuid
import os
import re
import threading
import fcntl
import logging
import httpx
from datetime import datetime, timezone

from inventory import Inventory
from dispatcher import dispatch_block_to_all, is_excluded_ip, validate_ip

# Module-level so it runs at import time regardless of launch method (the
# Dockerfile CMD is `uvicorn app:app`, which never executes `__main__`).
# Uvicorn's own dictConfig only touches the uvicorn.*/uvicorn.error/access
# loggers and leaves root alone, so this doesn't get clobbered (#171, AU-2/3).
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Hive-Mind Broker")

# Load the router inventory on startup
inv = Inventory("inventory.yaml")

# The secret used for HMAC validation. Loaded from the environment with NO
# insecure default (WS0.4) — if unset, the endpoint fails closed (503).
HMAC_SECRET = os.getenv("HIVE_MIND_SECRET", "").encode("utf-8")
# audit P1-1: replay protection. Signed requests carry x-elastic-timestamp; the
# timestamp must be within +/- HMAC_REPLAY_WINDOW of now, and a signature seen once
# within that window is refused (nonce cache), so a captured block request cannot
# be replayed.
HMAC_REPLAY_WINDOW = int(os.getenv("HMAC_REPLAY_WINDOW", "300"))  # seconds
_seen_sigs: dict[str, float] = {}    # signature -> expiry epoch
_seen_sigs_lock = threading.Lock()

# #171 (AU-2/3/12): persisted record of denied/replayed/invalid-signature
# requests, mirroring agent_app.py's write_audit() — a dedicated least-
# privilege ES account (role: soc_audit_appender, create-only on
# soc-audit-*), same as the agent's. Optional: an unset ES_PASS degrades
# write_denial() to a logged no-op rather than blocking auth responses.
ES_HOST   = os.getenv("ES_HOST", "https://elasticsearch:9200")
ES_USER   = os.getenv("ES_USER", "hive_mind_broker")
ES_PASS   = os.getenv("ES_PASS", "")
ES_CA     = os.getenv("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True  # fail closed: never silently disable TLS verification

# CDP §12.3: autonomous containment is Deferred Scope. By default the broker
# DRAFTS a block and queues it for a human-of-record; it does not push it.
# Set AUTONOMOUS_BLOCK_ENABLED=true to restore legacy auto-dispatch.
AUTONOMOUS_BLOCK_ENABLED = os.getenv("AUTONOMOUS_BLOCK_ENABLED", "false").lower() == "true"

APPROVAL_QUEUE = os.getenv("APPROVAL_QUEUE", "approval_queue.jsonl")
# audit #176: a stable cross-process lock path — see _append_action().
_QUEUE_LOCK_PATH = APPROVAL_QUEUE + ".lock"
_queue_lock = threading.Lock()

# Tenant slug (WS0.3) — same grammar as agent_app/logstash/provision_tenant.sh.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}$")


def safe_tenant(value):
    """Return a validated lowercase tenant slug, or 'unassigned' if invalid."""
    v = str(value or "").strip().lower()
    return v if _TENANT_RE.match(v) else "unassigned"


async def write_denial(reason: str, request: Request, detail: str = "") -> None:
    """Persist a denied/replayed/invalid-signature request (#171, AU-2/3/12).

    Append-only doc to soc-audit-unassigned, same schema as agent_app.py's
    write_audit() (op_type=create via the soc_audit_appender role — no
    update/delete). _verify() fires before any request body is trusted, so
    there is no real tenant to attribute this to yet; 'unassigned' is the
    established convention for audit events with no resolved tenant.
    Failures are logged, never raised — auditing must not break the 401/503
    it's recording.
    """
    doc = {
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
        "event.action":  reason,
        "actor":         request.client.host if request.client else "unknown",
        "tenant.id":     "unassigned",
        "event.outcome": "denied",
        "target":        request.url.path,
        "detail":        detail,
    }
    ndjson = '{"create":{}}\n' + json.dumps(doc) + "\n"
    try:
        async with httpx.AsyncClient(verify=ES_VERIFY, timeout=3) as client:
            response = await client.post(f"{ES_HOST}/soc-audit-unassigned/_bulk", content=ndjson,
                                          headers={"Content-Type": "application/x-ndjson"},
                                          auth=(ES_USER, ES_PASS))
            response.raise_for_status()  # a non-2xx (bad creds, missing role) must not look like success
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to write denial record: %s", e)


def _append_action(action: dict) -> None:
    """Append a resolved/drafted action to the approval queue (audit log).

    audit #176: flocks _QUEUE_LOCK_PATH — a path that is never itself
    replaced/truncated — rather than APPROVAL_QUEUE directly. A separate OS
    process (compact_broker_approval_queue.py, run via cron) can't see
    _queue_lock at all, so cross-process safety has to come from flock; but
    flocking the *data* file doesn't compose safely with that script's atomic
    replace: a fresh open(APPROVAL_QUEUE, "a") that resolves the path right
    before a concurrent os.replace(), then blocks in flock() until after it,
    would end up writing to the now-orphaned pre-replace inode and silently
    lose the append. Locking a path that's never replaced avoids that.
    """
    with _queue_lock:
        with open(_QUEUE_LOCK_PATH, "a") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                with open(APPROVAL_QUEUE, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(action) + "\n")
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _read_queue():
    try:
        with open(APPROVAL_QUEUE, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
    except OSError:
        return []


async def _verify(request: Request) -> bytes:
    """Fail-closed HMAC + timestamp-freshness + replay gate. Verifies
    sha256=HMAC(secret, '<x-elastic-timestamp>.' + raw_body) (same scheme as the AI
    agent), requires the timestamp within +/- HMAC_REPLAY_WINDOW of now, and refuses
    a previously-seen signature — so a captured signed block request cannot be
    replayed (audit P1-1). Returns the raw body, or raises HTTPException.

    Used directly by endpoints that take no JSON body (e.g. GET /pending, which
    signs the empty body) and via _verify_and_parse by the JSON endpoints. Every
    block-producing OR queue-disclosing endpoint must pass through here — an open
    /approve or /pending defeats the signing on /webhook/* entirely.
    """
    # Fail closed if no secret is configured — never accept unauthenticated calls.
    if not HMAC_SECRET:
        await write_denial("no_secret_configured", request)
        raise HTTPException(status_code=503, detail="Broker secret not configured")

    signature_header = request.headers.get("x-elastic-signature")
    timestamp_header = request.headers.get("x-elastic-timestamp")
    if not signature_header or not timestamp_header:
        await write_denial("missing_signature_or_timestamp", request)
        raise HTTPException(status_code=401, detail="Missing signature or timestamp header")
    try:
        ts = int(timestamp_header)
    except ValueError:
        await write_denial("invalid_timestamp", request)
        raise HTTPException(status_code=401, detail="Invalid timestamp")
    now = int(time.time())
    if abs(now - ts) > HMAC_REPLAY_WINDOW:
        await write_denial("timestamp_outside_replay_window", request)
        raise HTTPException(status_code=401, detail="Timestamp outside replay window")

    # The raw body is what was signed (prefixed by the timestamp) — verify before parsing.
    body = await request.body()
    signed = f"{timestamp_header}.".encode("utf-8") + body
    expected_mac = hmac.new(HMAC_SECRET, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f"sha256={expected_mac}", signature_header):
        await write_denial("invalid_signature", request)
        raise HTTPException(status_code=401, detail="Invalid signature")
    # Replay check only AFTER the signature is proven valid (so forged signatures
    # cannot poison the cache). Kept synchronous (no `await` while held) — a
    # threading.Lock does not yield to the event loop, so awaiting write_denial()
    # inside it would stall every other request until this one resumes.
    with _seen_sigs_lock:
        for s, exp in list(_seen_sigs.items()):
            if exp <= now:
                del _seen_sigs[s]
        replayed = signature_header in _seen_sigs
        if not replayed:
            _seen_sigs[signature_header] = now + HMAC_REPLAY_WINDOW
    if replayed:
        await write_denial("replayed_signature", request)
        raise HTTPException(status_code=401, detail="Replayed signature")
    return body


async def _verify_and_parse(request: Request) -> dict:
    """HMAC-verify (via _verify) then return the parsed JSON body."""
    body = await _verify(request)
    try:
        return json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")


@app.post("/webhook/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    """
    Receives webhook payloads from Kibana when a critical alert fires.
    """
    payload = await _verify_and_parse(request)

    # Extract the attacker IP from the Kibana alert payload
    # Payload structure depends on the specific Kibana Watcher/Alert action
    # For this MVP, we assume {"attacker_ip": "x.x.x.x"} is sent by the webhook
    attacker_ip = payload.get("attacker_ip")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="Payload missing attacker_ip")
    try:
        validate_ip(attacker_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="attacker_ip is not a valid IP address")

    # §12.4: refuse to act against protected infrastructure, signed or not.
    if is_excluded_ip(attacker_ip):
        logger.warning("REFUSED: %s is on the permanent exclusion list.", attacker_ip)
        return {"status": "success",
                "message": f"IP {attacker_ip} is on the exclusion list — no block drafted."}

    # WS0.3: scope the block to the alert's tenant — only that tenant's routers
    # are ever touched; the broker never broadcasts across tenants. An unknown
    # tenant (or one with no routers) is a no-op, not a fall-back-to-all.
    tenant = safe_tenant(payload.get("tenant_id"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        logger.warning("No routers for tenant '%s' — refusing to act on %s.", tenant, attacker_ip)
        return {"status": "success",
                "message": f"No routers configured for tenant '{tenant}' — nothing to block."}

    if AUTONOMOUS_BLOCK_ENABLED:
        # Legacy, out-of-scope behaviour, retained only behind an explicit flag.
        background_tasks.add_task(dispatch_block_to_all, routers, attacker_ip)
        logger.info("Auto-block dispatched for %s on tenant '%s' (flag enabled).", attacker_ip, tenant)
        return {"status": "success",
                "message": f"IP {attacker_ip} dispatched for block across {len(routers)} "
                           f"router(s) for tenant '{tenant}'."}

    # Default: §12.3 — draft the block and queue it for human approval.
    action = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "status": "pending",
        "tenant": tenant,
        "attacker_ip": attacker_ip,
        "router_count": len(routers),
    }
    _append_action(action)
    logger.info("Drafted block for %s (action %s) — awaiting approval.", attacker_ip, action['id'])
    return {"status": "success",
            "message": f"IP {attacker_ip} drafted for human approval (action {action['id']})."}


@app.post("/webhook/dispatch")
async def dispatch_block(request: Request):
    """Authenticated IMMEDIATE dispatch for an already-approved block (#109).

    The AI agent can't run isolate.sh from its slim container (no ssh/sudo), so it
    routes containment here. The agent performs the CDP §12.3 human-of-record gate
    upstream (autonomous opt-in OR a human /approve), so — unlike /webhook/alert —
    this endpoint does NOT re-queue for approval; it dispatches now.

    Still defence-in-depth: §12.4 exclusion and WS0.3 tenant scoping are re-checked
    here, and the dispatch is recorded to the approval queue as an audit line.
    Authentication is the same HMAC scheme; only a holder of HIVE_MIND_SECRET (the
    agent) can reach it.
    """
    payload = await _verify_and_parse(request)

    attacker_ip = payload.get("attacker_ip")
    if not attacker_ip:
        raise HTTPException(status_code=400, detail="Payload missing attacker_ip")
    try:
        validate_ip(attacker_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="attacker_ip is not a valid IP address")
    approver = str(payload.get("approver", "soc-ai-agent"))

    # §12.4: refuse protected infrastructure, signed or not.
    if is_excluded_ip(attacker_ip):
        logger.warning("REFUSED dispatch: %s is on the exclusion list.", attacker_ip)
        return {"status": "refused", "executed": False,
                "message": f"IP {attacker_ip} is on the exclusion list — no block dispatched."}

    # WS0.3: only this tenant's routers are ever touched; unknown tenant => no-op.
    tenant = safe_tenant(payload.get("tenant_id"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        logger.warning("No routers for tenant '%s' — refusing to dispatch %s.", tenant, attacker_ip)
        return {"status": "no_routers", "executed": False,
                "message": f"No routers configured for tenant '{tenant}' — nothing to block."}

    count, unknown_count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action({
        "id": uuid.uuid4().hex[:12], "ts": time.time(), "status": "executed",
        "approver": approver, "tenant": tenant, "attacker_ip": attacker_ip,
        "result": f"{count}/{len(routers)} routers ({unknown_count} unknown)",
    })
    logger.info("Dispatched block for %s on tenant '%s' (%d/%d routers, %d unknown) — approver=%s.",
                attacker_ip, tenant, count, len(routers), unknown_count, approver)
    # #247 security-auditor review: unknown_count is surfaced separately from
    # success_count, never folded into it — a caller (agent.py's
    # dispatch_block_via_broker) that treated an unconfirmed router the same as
    # a confirmed failure would risk a real double-dispatch on retry.
    return {"status": "executed", "executed": True, "tenant": tenant,
            "router_count": len(routers), "success_count": count,
            "unknown_count": unknown_count,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                       f"router(s) for tenant '{tenant}' ({unknown_count} unknown)."}


@app.get("/pending")
async def list_pending(request: Request):
    """List drafted blocks awaiting a human-of-record. Authenticated (HMAC)."""
    await _verify(request)  # sign the empty body; raises 401/503 on failure
    resolved = {a["id"] for a in _read_queue() if a.get("status") in ("approved", "denied")}
    pending = [a for a in _read_queue()
               if a.get("status") == "pending" and a["id"] not in resolved]
    return {"pending": pending, "count": len(pending)}


@app.post("/approve")
async def approve(request: Request):
    """Human-of-record approves a drafted block, which then dispatches.

    Authenticated (HMAC) — this endpoint EXECUTES a router block, so it must be
    gated to the same bar as /webhook/dispatch; an open /approve would let any
    caller execute a drafted block.
    """
    body = await _verify_and_parse(request)
    action_id = body.get("id")
    approver = body.get("approver", "unknown")
    if not action_id:
        raise HTTPException(status_code=400, detail="missing 'id'")

    resolved = {a["id"] for a in _read_queue() if a.get("status") in ("approved", "denied")}
    pending = {a["id"]: a for a in _read_queue()
               if a.get("status") == "pending" and a["id"] not in resolved}
    action = pending.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"no pending action {action_id}")

    attacker_ip = action["attacker_ip"]
    try:
        excluded = is_excluded_ip(attacker_ip)  # re-check at execution time
    except ValueError:
        _append_action({"id": action_id, "ts": time.time(), "status": "denied",
                        "approver": approver, "result": "invalid attacker_ip"})
        raise HTTPException(status_code=422,
                            detail=f"invalid attacker_ip in drafted action {action_id}")
    if excluded:
        _append_action({"id": action_id, "ts": time.time(), "status": "denied",
                        "approver": approver, "result": "exclusion list"})
        raise HTTPException(status_code=422, detail=f"{attacker_ip} is excluded")

    # WS0.3: dispatch only to the drafted action's tenant routers — never all.
    tenant = safe_tenant(action.get("tenant"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        _append_action({"id": action_id, "ts": time.time(), "status": "denied",
                        "approver": approver, "result": f"no routers for tenant {tenant}"})
        raise HTTPException(status_code=422, detail=f"no routers for tenant '{tenant}'")

    count, unknown_count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action({"id": action_id, "ts": time.time(), "status": "approved",
                    "approver": approver, "tenant": tenant,
                    "result": f"{count}/{len(routers)} routers ({unknown_count} unknown)"})
    return {"status": "executed", "approver": approver, "unknown_count": unknown_count,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                       f"router(s) for tenant '{tenant}'."}


if __name__ == "__main__":
    # #177: dead in production (the container CMD runs `uvicorn app:app` directly,
    # never this block) — but a checked-in dev-mode default (all-interfaces bind +
    # autoreload) is still a footgun if anyone runs this file directly. Loopback +
    # no reload.
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)

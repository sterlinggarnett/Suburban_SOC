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
from fastapi.responses import JSONResponse
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
import unicodedata
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

# #273: the approver of record must be bound to the credential that authenticated
# the request, never to the request body. The broker authenticates every mutating
# endpoint with the single shared HIVE_MIND_SECRET, so it can prove that *a holder
# of that secret* called it — it cannot prove which human, and it certainly cannot
# vouch for a name the caller typed into the payload. Recording that name as
# "approver" made the audit trail forgeable by anyone holding the secret (the
# ai-agent container, and anything reaching 127.0.0.1:8000), with no way for review
# to tell a real analyst action from an attacker-chosen string.
#
# The two mutating endpoints have distinct callers, so each gets its own
# operator-configured label. Both are configuration, not input.
#   /approve          — a human-of-record approving a drafted block at the broker
#   /webhook/dispatch — the AI agent relaying a block it already gated upstream
#
# Both are gated by the SAME secret, so these labels record which endpoint was
# used, not which caller proved who they were — see approve()'s docstring for
# the limit of that guarantee.
def _resolve_identity(env_key: str, default: str) -> str:
    """Return the operator-configured identity label for `env_key`, or `default`.

    A var that is SET but empty must still fall back: os.getenv(key, default)
    applies the default only when the key is ABSENT, so a `FOO=` line in an .env
    file would otherwise yield "" and blank the approver of record. This is the
    exact defect #246's security review caught in the agent's
    SOC_APPROVER_IDENTITY. Kept as a pure function (not an inline `or`) so the
    behaviour is unit-testable without reimporting this module — a test that
    re-implements the expression inline proves nothing about this code.
    """
    return os.getenv(env_key) or default


APPROVER_IDENTITY = _resolve_identity("BROKER_APPROVER_IDENTITY", "broker-operator")
DISPATCH_IDENTITY = _resolve_identity("BROKER_DISPATCH_IDENTITY", "soc-ai-agent")

# /webhook/dispatch callers may still send an "approver" field — today the agent
# sends the fixed literal "soc-ai-agent" (agent.py's dispatch_block_via_broker).
# It is recorded, bounded and under a name that marks it as unverified, for one
# reason: a value that is anything OTHER than the expected literal means someone
# holding HIVE_MIND_SECRET is calling this endpoint with a hand-crafted payload,
# which is worth seeing in the audit trail. It is never the approver of record.
#
# Realising that value today means manually reading approval_queue.jsonl: the
# broker's queue is not shipped to Elasticsearch by any config under configs/,
# so nothing alerts on a mismatch (#273 review, MEDIUM). Wiring that up is
# tracked separately — do not read this field as actively monitored.
#
# 64 chars: comfortably longer than any real analyst name or handle, short
# enough to bound a hostile payload in the queue and the audit index.
_CLAIMED_APPROVER_MAX = 64


def _claimed_approver(payload: dict) -> str | None:
    """Return the caller's asserted approver string, sanitised and bounded — or
    None if absent.

    Security review (#273, LOW): strip Unicode Cc/Cf (control characters, and
    format characters such as the U+202E bidi override) before truncating.
    json.dumps' ensure_ascii=True already stops this string from breaking the
    JSONL queue's one-record-per-line framing, so this is latent rather than
    live — but the field exists to be *read by a human during an audit*, and a
    bidi override or ANSI escape that renders as a different name than it
    stores defeats exactly that purpose. Close it before a renderer exists,
    not after.
    """
    raw = payload.get("approver")
    if raw is None:
        return None
    # A non-string JSON value (dict, list, number, bool) is itself the anomaly
    # worth recording. str() on a dict renders Python syntax, not JSON, which
    # reads as corruption to whoever audits the queue — record the type instead
    # (#273 review, Should-Fix 4).
    if not isinstance(raw, str):
        return f"<non-string:{type(raw).__name__}>"
    cleaned = "".join(c for c in raw if unicodedata.category(c) not in ("Cc", "Cf"))
    return cleaned[:_CLAIMED_APPROVER_MAX]


# #309: dispatch_block() previously read request_id with no type check, length
# bound, or sanitization at all — unlike the adjacent _claimed_approver() above.
# It's echoed into the SIGNED /webhook/dispatch response body (agent.py's
# dispatch_block_via_broker() binds its replay check to this value, #277
# round-3), into this process's own logs (_signed_json_response()), and now
# into the approval queue (see dispatch_block()'s _append_action call below) —
# every one of those is read by a human or a downstream parser at some point.
_REQUEST_ID_MAX = 64


def _safe_request_id(payload: dict) -> str | None:
    """Return the caller's request_id, sanitised and bounded — or None if
    absent/malformed.

    Mirrors _claimed_approver()'s sanitisation (strip Unicode Cc/Cf control
    characters, truncate) for the same reason: this value is read by a human
    during an audit, and a bidi override or ANSI escape that renders
    differently than it stores defeats that. Unlike approver, a non-string
    request_id carries no adversarial-claim value worth preserving as-is
    (there's no "identity" being asserted) — agent.py's own mismatch check
    already treats None the same as any other value it didn't generate:
    unsafe to trust, not a crash.
    """
    raw = payload.get("request_id")
    if not isinstance(raw, str):
        return None
    cleaned = "".join(c for c in raw if unicodedata.category(c) not in ("Cc", "Cf"))
    return cleaned[:_REQUEST_ID_MAX]


def _with_claim(record: dict, claimed: str | None) -> dict:
    """Attach the caller's asserted approver to an audit row, if they sent one.

    Kept out of the row literals so every write path — both endpoints, success
    and denial alike — records the claim the same way. The key name is the
    contract: `approver` is what the broker vouches for, anything
    `*_claimed` is what the caller asserted.
    """
    if claimed is not None:
        record["upstream_approver_claimed"] = claimed
    return record


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



# #277 round-2 security-auditor review: request and response signing MUST NOT
# share the same signed-bytes construction. Both directions use the same
# HIVE_MIND_SECRET and the same header names, so with no distinguishing tag
# the agent's own genuine signed REQUEST verifies successfully if replayed
# back to it as if it were the broker's RESPONSE (confirmed empirically) —
# an on-path attacker doesn't need to forge anything, just reflect. Mirrored
# independently in agent.py's BROKER_RESPONSE_DOMAIN (no shared Python path
# between the two separately-deployed services); the two constants' VALUES
# must match, their names don't need to.
_RESPONSE_DOMAIN = b"broker-response:"


def _signed_json_response(payload: dict) -> JSONResponse:
    """#277: sign the response body the same way _verify() checks a request's
    (sha256=HMAC(secret, '<timestamp>.' + raw_body)), so a caller that trusts
    this response (agent.py's dispatch_block_via_broker()) can prove it
    actually came from THIS broker holding HIVE_MIND_SECRET, not an on-path
    attacker who forged {"executed": true} or a fake failure to force an
    unsafe retry / a falsely-closed case. Signs response.body (the exact
    rendered bytes JSONResponse will send), not a re-serialization of
    `payload` — Starlette's JSON encoding is deterministic for a given dict,
    but signing the ACTUAL bytes closes off any theoretical drift between
    what's signed and what's sent, matching how _verify() signs the exact
    raw request body rather than a re-parsed/re-serialized copy of it.

    Scoped to /webhook/dispatch's own 200-status responses only (the ones
    dispatch_block_via_broker() makes a trust decision from) — not every
    endpoint, and not this endpoint's own HTTPException-driven 4xx/5xx
    error responses (raised before this helper is ever reached, e.g. by
    _verify()/_verify_and_parse() or dispatch_block()'s own validation).
    Those already can't cause dispatch_block_via_broker() to trust a
    forged CONFIRMED-success outcome (no 200, no executed/success_count
    fields to trust) — see #308 for the narrower, separate residual risk
    of a forged 4xx forcing an unsafe "confirmed non-dispatch" retry.

    `payload` is expected to carry "attacker_ip" and "request_id" (dispatch_block()
    always includes both) — the agent checks request_id against the fresh
    random value it generated for THIS specific call, since the signature
    alone only proves "the broker signed this," not "in answer to this
    specific request." attacker_ip is included too, for observability, but
    is NOT the binding mechanism (round-2 security-auditor review: checking
    only attacker_ip missed a captured response being replayed against a
    dispatch for the same IP under a DIFFERENT tenant, or the same IP
    re-dispatched later — request_id's per-call uniqueness closes both).
    """
    response = JSONResponse(content=payload)
    ts, sig = sign_response(bytes(response.body))
    response.headers["x-elastic-signature"] = sig
    response.headers["x-elastic-timestamp"] = ts
    # #277 round-4: the agent logs a body_sha256 digest instead of this
    # response's raw (unverified-until-checked) text on any failure path —
    # logged here too, so that digest is actually correlatable against the
    # broker's own logs rather than an orphaned value only the agent has.
    logger.info("Signed /webhook/dispatch response for request_id=%s, body_sha256=%s",
               payload.get("request_id"), hashlib.sha256(response.body).hexdigest()[:16])
    return response


def sign_response(body: bytes) -> tuple[str, str]:
    """(timestamp, 'sha256=<hmac>') for a broker-originated response — same
    scheme _verify() checks incoming requests with (sha256=HMAC(secret,
    '<timestamp>.' + raw_body)), reused bidirectionally per #277's own
    suggested fix rather than provisioning a second secret for this one
    channel, but domain-separated via _RESPONSE_DOMAIN (round-2 review — see
    that constant's comment) so a request signature can never pass as a
    response signature or vice versa. Independently reimplemented here rather
    than imported from agent.py — the two services are separately deployed
    containers with no shared Python path, matching how _verify() already
    reimplements agent.py's sign_request()/verify_signature() scheme rather
    than importing it."""
    ts = str(int(time.time()))
    sig = "sha256=" + hmac.new(
        HMAC_SECRET, _RESPONSE_DOMAIN + f"{ts}.".encode("utf-8") + body, hashlib.sha256).hexdigest()
    return ts, sig


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
    # #277 round-3: echoed into every response below so dispatch_block_via_
    # broker() can bind a response to the exact request that produced it —
    # a valid signature alone only proves "the broker signed this," not
    # "in answer to this specific call" (round-2 security-auditor review:
    # checking attacker_ip alone missed same-IP-different-tenant and
    # same-IP-different-time replay of a captured earlier response). Falls
    # back to None if an older/different caller doesn't send one, which the
    # agent's mismatch check already treats as unsafe-to-trust, not a crash.
    # #309: sanitised/bounded the same way _claimed_approver() sanitises
    # `approver` — see _safe_request_id()'s own docstring.
    request_id = _safe_request_id(payload)
    # #273: identity of record comes from the authenticated credential's
    # configured label; the body's "approver" is retained only as a claim
    # (computed below, past the early returns — neither writes an audit row).
    approver = DISPATCH_IDENTITY

    # §12.4: refuse protected infrastructure, signed or not.
    if is_excluded_ip(attacker_ip):
        logger.warning("REFUSED dispatch: %s is on the exclusion list.", attacker_ip)
        return _signed_json_response({
            "status": "refused", "executed": False, "attacker_ip": attacker_ip,
            "request_id": request_id,
            "message": f"IP {attacker_ip} is on the exclusion list — no block dispatched."})

    # WS0.3: only this tenant's routers are ever touched; unknown tenant => no-op.
    tenant = safe_tenant(payload.get("tenant_id"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        logger.warning("No routers for tenant '%s' — refusing to dispatch %s.", tenant, attacker_ip)
        return _signed_json_response({
            "status": "no_routers", "executed": False, "attacker_ip": attacker_ip,
            "request_id": request_id,
            "message": f"No routers configured for tenant '{tenant}' — nothing to block."})

    count, unknown_count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action(_with_claim({
        "id": uuid.uuid4().hex[:12], "ts": time.time(), "status": "executed",
        "approver": approver, "tenant": tenant, "attacker_ip": attacker_ip,
        "result": f"{count}/{len(routers)} routers ({unknown_count} unknown)",
        # #309: not a secret — already sent in cleartext over the (currently
        # plain-HTTP) broker channel. The join key a responder investigating a
        # signature/request_id-mismatch alert needs to correlate this queue
        # row against the agent's own soc-audit-* record for the same call.
        "request_id": request_id,
    }, _claimed_approver(payload)))
    logger.info("Dispatched block for %s on tenant '%s' (%d/%d routers, %d unknown) — approver=%s.",
                attacker_ip, tenant, count, len(routers), unknown_count, approver)
    # #247 security-auditor review: unknown_count is surfaced separately from
    # success_count, never folded into it — a caller (agent.py's
    # dispatch_block_via_broker) that treated an unconfirmed router the same as
    # a confirmed failure would risk a real double-dispatch on retry.
    return _signed_json_response({
        "status": "executed", "executed": True, "tenant": tenant, "attacker_ip": attacker_ip,
        "request_id": request_id,
        "router_count": len(routers), "success_count": count,
        "unknown_count": unknown_count,
        "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                   f"router(s) for tenant '{tenant}' ({unknown_count} unknown)."})


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
    """Approve a drafted block, which then dispatches.

    Authenticated (HMAC) — this endpoint EXECUTES a router block, so it must be
    gated to the same bar as /webhook/dispatch; an open /approve would let any
    caller execute a drafted block.

    LIMIT OF THE GUARANTEE (#273): this is gated by the SAME HIVE_MIND_SECRET as
    /webhook/dispatch, which the agent container holds. The broker can therefore
    prove only that *a holder of that secret* called this endpoint — not that a
    human did. A compromised agent (or anyone who extracts the secret from it)
    can call /approve for an id read from /pending and have it recorded under
    APPROVER_IDENTITY. Do not read that label as cryptographic proof of a
    human-of-record; closing that gap needs a second, independent credential,
    the way #246 did it for the agent.
    """
    body = await _verify_and_parse(request)
    action_id = body.get("id")
    # #273: the approver of record is the identity bound to the credential that
    # signed this request, never body.get("approver") — that field is
    # caller-controlled and would let any HIVE_MIND_SECRET holder stamp an
    # arbitrary analyst name onto an executed containment action.
    approver = APPROVER_IDENTITY
    # Security review (#273, MEDIUM): /webhook/dispatch keeps the caller's
    # asserted approver as a labelled claim because a hand-crafted payload is
    # worth seeing. /approve is the *higher*-trust endpoint, so it needs that
    # forensic breadcrumb at least as much — it previously kept nothing.
    claimed_approver = _claimed_approver(body)
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
        _append_action(_with_claim({"id": action_id, "ts": time.time(), "status": "denied",
                                    "approver": approver, "result": "invalid attacker_ip"},
                                   claimed_approver))
        raise HTTPException(status_code=422,
                            detail=f"invalid attacker_ip in drafted action {action_id}")
    if excluded:
        _append_action(_with_claim({"id": action_id, "ts": time.time(), "status": "denied",
                                    "approver": approver, "result": "exclusion list"},
                                   claimed_approver))
        raise HTTPException(status_code=422, detail=f"{attacker_ip} is excluded")

    # WS0.3: dispatch only to the drafted action's tenant routers — never all.
    tenant = safe_tenant(action.get("tenant"))
    routers = inv.get_routers_for_tenant(tenant)
    if not routers:
        _append_action(_with_claim(
            {"id": action_id, "ts": time.time(), "status": "denied",
             "approver": approver, "result": f"no routers for tenant {tenant}"},
            claimed_approver))
        raise HTTPException(status_code=422, detail=f"no routers for tenant '{tenant}'")

    count, unknown_count = await dispatch_block_to_all(routers, attacker_ip)
    _append_action(_with_claim(
        {"id": action_id, "ts": time.time(), "status": "approved",
         "approver": approver, "tenant": tenant,
         "result": f"{count}/{len(routers)} routers ({unknown_count} unknown)"},
        claimed_approver))
    return {"status": "executed", "approver": approver, "unknown_count": unknown_count,
            "message": f"IP {attacker_ip} blocked on {count}/{len(routers)} "
                       f"router(s) for tenant '{tenant}' ({unknown_count} unknown)."}


if __name__ == "__main__":
    # #177: dead in production (the container CMD runs `uvicorn app:app` directly,
    # never this block) — but a checked-in dev-mode default (all-interfaces bind +
    # autoreload) is still a footgun if anyone runs this file directly. Loopback +
    # no reload.
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)

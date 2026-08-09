from typing import Optional, Dict, Any
import getpass
import os
import re
import socket
import time
import hashlib
import logging
import requests
from urllib.parse import quote
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# security-auditor review (#276/#278, Finding: ES URL injection): tenant_id
# becomes an INDEX NAME (f"agent-checkpoints-{tenant_id}") — an unvalidated
# value containing "," turns a single-index request into a multi-index
# expression, and "*" (outside the explicit search_stuck_claims wildcard
# case) broadens a read/write across every tenant's checkpoints. Every HTTP
# entry point in this codebase already sanitises tenant via safe_tenant()
# (agent.py, app.py) before it reaches these functions, so this is a
# defense-in-depth net, not a fix for a live exposure — but the new
# get_claim()/search_stuck_claims() (#276) are reachable from an operator
# CLI with no such upstream gate, so they get it applied directly. Same
# grammar as agent.py's _TENANT_RE so a legitimate tenant slug is never
# rejected by one layer and accepted by another.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}$")


def _validate_tenant_id(tenant_id: str, *, allow_wildcard: bool = False) -> str:
    if allow_wildcard and tenant_id == "*":
        return tenant_id
    if not isinstance(tenant_id, str) or not _TENANT_RE.match(tenant_id):
        raise ValueError(f"invalid tenant_id: {tenant_id!r}")
    return tenant_id

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

    Callers MUST pass a safe_tenant()-sanitised tenant_id — see
    write_checkpoint's docstring for why this isn't validated here.
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
    """Upserts a phase transition to the agent-checkpoints-<tenant> index.

    Callers MUST pass a safe_tenant()-sanitised tenant_id — this function
    does not validate it itself (security-auditor round-2 INFO: scoped
    intentionally, see _validate_tenant_id's module comment above; this is
    a hot-path function reached only through agent.py's HTTP entry points,
    which already gate tenant_id before it gets here)."""
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
    """Loads the latest checkpoint from ES for crash resume/idempotency.

    Callers MUST pass a safe_tenant()-sanitised tenant_id — see
    write_checkpoint's docstring for why this isn't validated here."""
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
    other writer for the same alert_id gets 409 and loses.

    #247: a 409 doesn't necessarily mean this alert is genuinely still
    claimed — release_claim() (a confirmed-failed execution) marks the claim
    doc "RELEASED" rather than deleting it (agent_checkpoints's ES role
    deliberately has no delete privilege — #245 — so a compromised agent
    credential can't erase a claim to reopen the at-most-once gate). On a
    409, re-read the existing doc: if it's RELEASED, attempt to re-win it via
    a conditional PUT keyed on if_seq_no/if_primary_term — optimistic
    concurrency gives the SAME "exactly one winner" guarantee op_type=create
    gave the first time, even with several retriers racing. A doc that's
    still CLAIMED (execution in flight, or outcome unknown — #247 never
    releases those) or RESOLVED (already succeeded) correctly loses the race,
    same as before.

    Any other error (ES unreachable, 5xx) propagates — callers must fail
    closed on a lost or unconfirmed claim, since duplicate isolation is worse
    than a delayed one.

    Callers MUST pass a safe_tenant()-sanitised tenant_id — see
    write_checkpoint's docstring for why this isn't validated here.
    """
    index = f"agent-checkpoints-{tenant_id}"
    doc_id = f"{alert_id}.claim"
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant": {"id": tenant_id},
        "alert_id": alert_id,
        "approver": approver,
        "phase": "CLAIMED",
    }
    res = requests.put(f"{ES_HOST}/{index}/_create/{doc_id}", json=doc,
                       auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if res.status_code != 409:
        res.raise_for_status()
        return True

    get_res = requests.get(f"{ES_HOST}/{index}/_doc/{doc_id}",
                           auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    get_res.raise_for_status()
    existing = get_res.json()
    if existing.get("_source", {}).get("phase") != "RELEASED":
        return False  # genuinely still claimed (or already resolved) — lose the race

    reclaim_res = requests.put(
        f"{ES_HOST}/{index}/_doc/{doc_id}"
        f"?if_seq_no={existing['_seq_no']}&if_primary_term={existing['_primary_term']}",
        json=doc, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if reclaim_res.status_code == 409:
        return False  # another retrier won the re-claim race first
    reclaim_res.raise_for_status()
    return True


def _transition_claim(tenant_id: str, alert_id: str, phase: str, *,
                       actor: Optional[str] = None, reason: Optional[str] = None,
                       if_seq_no: Optional[int] = None,
                       if_primary_term: Optional[int] = None) -> bool:
    """Marks a claim doc RELEASED (confirmed non-dispatch, #247) or RESOLVED
    (confirmed success) via a partial update — never delete (see
    claim_approval()'s docstring for why: agent_checkpoints's ES role has no
    delete privilege, and that's deliberate, not an oversight).

    A 404 (claim doc already gone — shouldn't normally happen, since nothing
    deletes these, but tolerate it) is treated as success: the goal state
    (this id is no longer a live, retryable-into CLAIMED claim) already holds.
    Any other error propagates — callers decide how to surface a transition
    that could not be recorded (the claim stays CLAIMED, visibly so — see
    slo_metrics.metric_stuck_approval_claims(), which counts exactly that).

    actor/reason (#276, security-auditor HIGH: unattributed operator writes)
    are ONLY set by manage_stuck_claims.py's manual recovery path — the
    agent's own execute_approved() calls release_claim()/resolve_claim()
    with neither, so those writes keep their original minimal
    {"doc": {"phase": phase}} body and existing behaviour exactly. When
    present, they're recorded directly on the claim doc itself — still
    queryable, still attributable, via the same document claim_approval()
    already puts `approver`/`@timestamp` on.

    KNOWN GAP, not yet closed (security-auditor round-2 MEDIUM): this record
    is not tamper-evident — the same agent_checkpoints credential that wrote
    it can overwrite it with a second _update, since the role holds `index`.
    A durable copy needs a SEPARATE append-only-role credential (mirroring
    hive_mind_broker's own dedicated BROKER_AUDIT_PASSWORD/soc_audit_appender
    pattern in scripts/setup/.env.example, NOT a widening of
    agent_checkpoints's existing grant) writing to soc-audit-<tenant>.
    Tracked as a follow-up, not implemented here.

    security-auditor round-2 MEDIUM: `actor` is operator-typed free text —
    anyone holding the agent_checkpoints credential could otherwise stamp
    any name they like into `resolved_by` and permanently foreclose a
    RESOLVED claim's retry with no accountable trace, the exact attack
    #273 (app.py's upstream_approver_claimed / BROKER_APPROVER_IDENTITY)
    already hardened the broker against for its own approver field. Same
    split here: `resolved_by` binds to what actually authenticated this
    write (the ES service credential plus the OS user/host that ran the
    CLI, neither spoofable by the --actor flag alone), while the operator's
    typed name is kept, unmodified, as `resolution_actor_claimed` — a
    label, not a security boundary, same as app.py's field of the same
    shape.

    if_seq_no/if_primary_term (#276, security-auditor MEDIUM: read-then-write
    race) make the update conditional, the same optimistic-concurrency
    pattern claim_approval() already uses for its re-claim path — a 409
    means someone else changed this claim between the caller's read and this
    write, surfaced as a normal `False` return (not an exception), same as
    any other failed-to-confirm transition.
    """
    _validate_tenant_id(tenant_id)
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_update/{quote(f'{alert_id}.claim', safe='')}"
    doc = {"phase": phase}
    if actor is not None:
        doc["resolved_by"] = f"{ES_USER}:{getpass.getuser()}@{socket.gethostname()}"
        doc["resolved_at"] = datetime.now(timezone.utc).isoformat()
        doc["resolution_reason"] = reason
        doc["resolution_source"] = "manual"
        doc["resolution_actor_claimed"] = actor
    if (if_seq_no is None) != (if_primary_term is None):
        # security-auditor LOW: a half-set pair must not silently degrade to
        # an unconditional write (dropping optimistic-concurrency protection
        # exactly when a caller thought they were using it) nor reach ES to
        # fail there instead — refuse locally, at the boundary.
        raise ValueError("if_seq_no and if_primary_term must be given together or not at all")
    params = {}
    if if_seq_no is not None:
        params["if_seq_no"] = if_seq_no
        params["if_primary_term"] = if_primary_term
    res = requests.post(url, json={"doc": doc}, params=params or None,
                        auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if res.status_code == 404:
        return True
    if res.status_code == 409:
        return False
    res.raise_for_status()
    return True


def get_claim(tenant_id: str, alert_id: str) -> Optional[Dict[str, Any]]:
    """Reads a claim doc directly — the `{alert_id}.claim` document
    claim_approval()/_transition_claim() manage, distinct from the paired
    phase-checkpoint doc read_checkpoint() returns (`{alert_id}`, no
    `.claim` suffix). Used by the stuck-claim recovery tool (#276) to show
    an operator a claim's current phase/approver/age before they decide
    RELEASED vs RESOLVED — and to let them re-check it immediately before
    writing, in case someone else already resolved it out of band.

    The returned dict carries `_seq_no`/`_primary_term` alongside the claim
    fields (ES's own naming for these — mirrors the response body's own
    shape) so a caller can pass them through to a conditional
    release_claim()/resolve_claim() and detect a concurrent modification
    (security-auditor MEDIUM: read-then-write race) instead of blindly
    overwriting it.
    """
    _validate_tenant_id(tenant_id)
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_doc/{quote(f'{alert_id}.claim', safe='')}"
    res = requests.get(url, auth=_get_auth(), verify=ES_VERIFY, timeout=5)
    if res.status_code == 404:
        return None
    res.raise_for_status()
    body = res.json()
    claim = dict(body.get("_source") or {})
    claim["_seq_no"] = body.get("_seq_no")
    claim["_primary_term"] = body.get("_primary_term")
    return claim


def search_stuck_claims(max_age_minutes: float = 30.0, tenant_id: str = "*"):
    """Lists claim docs stuck in phase=CLAIMED older than max_age_minutes —
    the same population slo_metrics.metric_stuck_approval_claims() counts
    (same query shape: phase=CLAIMED AND @timestamp <= now-Nm), surfaced
    with enough detail (tenant/alert_id/approver/@timestamp) for an
    operator to decide what to do about each one (#276). @timestamp here is
    when the claim was WON (claim_approval() sets it; _transition_claim()'s
    partial update never touches it), so "age" means time-since-claimed,
    matching what the SLO metric already measures.

    Returns (claims, total) — `total` is ES's real match count (via
    track_total_hits), which can exceed len(claims) since results are
    capped at 200. Callers must surface that gap rather than silently
    showing a partial list as if it were complete (code-reviewer review:
    an operator trusting an uncapped-looking list could believe every
    stuck claim was cleared when 200 were only ever the oldest slice).

    Raises ValueError for a non-positive/non-finite max_age_minutes
    (code-reviewer: manage_stuck_claims.py's own _positive_float argparse
    type already rejects these, but that's an upstream-caller gate, not a
    property of this function — the same "new functions get validation
    applied directly, not just trusted from the one caller that happens to
    exist today" reasoning _validate_tenant_id's docstring gives applies
    identically here. An unvalidated negative/nan/inf value produces
    malformed ES date math ("now-nanm") and an unhandled traceback deep
    inside requests instead of a clear error at the boundary.)
    """
    if not (0 < max_age_minutes < float("inf")):
        raise ValueError(f"max_age_minutes must be a positive, finite number, got {max_age_minutes!r}")
    _validate_tenant_id(tenant_id, allow_wildcard=True)
    index = f"agent-checkpoints-{tenant_id}"
    url = f"{ES_HOST}/{index}/_search"
    query = {
        "query": {"bool": {"filter": [
            {"term": {"phase": "CLAIMED"}},
            {"range": {"@timestamp": {"lte": f"now-{max_age_minutes:g}m"}}},
        ]}},
        "size": 200,
        "sort": [{"@timestamp": "asc"}],
        "track_total_hits": True,
    }
    res = requests.post(url, json=query, auth=_get_auth(), verify=ES_VERIFY, timeout=10)
    res.raise_for_status()
    hits_obj = res.json().get("hits", {})
    hits = hits_obj.get("hits", [])
    total = hits_obj.get("total", {}).get("value", len(hits))
    return [h["_source"] for h in hits], total


def release_claim(tenant_id: str, alert_id: str, *, actor: Optional[str] = None,
                   reason: Optional[str] = None, if_seq_no: Optional[int] = None,
                   if_primary_term: Optional[int] = None) -> bool:
    """Frees a claim so a CONFIRMED-failed-but-not-executed action can be
    retried (#247).

    claim_approval()'s at-most-once guarantee is a one-way door by design — but
    that also means an execution that fails AFTER winning the claim (broker
    outage, no routers configured, etc.) permanently strands the alert: every
    retried /approve loses the claim race forever, even though nothing was
    actually dispatched. Callers use this ONLY after confirming execution did
    NOT happen — never on an ambiguous outcome (e.g. the broker call timed out
    AFTER it may have already applied the block; see agent.py's
    IsolationOutcomeUnknown) — the at-most-once invariant still holds, since
    marking the claim RELEASED just returns the alert to the same "no live
    claim, PENDING_APPROVAL" state it was in before the failed attempt, not to
    some new state a real dispatch could race against.

    actor/reason/if_seq_no/if_primary_term are #276's manual-recovery-only
    parameters — see _transition_claim's docstring. agent.py's own call
    site passes none of them.
    """
    return _transition_claim(tenant_id, alert_id, "RELEASED", actor=actor, reason=reason,
                             if_seq_no=if_seq_no, if_primary_term=if_primary_term)


def resolve_claim(tenant_id: str, alert_id: str, *, actor: Optional[str] = None,
                   reason: Optional[str] = None, if_seq_no: Optional[int] = None,
                   if_primary_term: Optional[int] = None) -> bool:
    """Marks a claim doc RESOLVED after a CONFIRMED successful execution (#247).

    Without this, a successful claim's doc stays phase=CLAIMED forever (it's
    never deleted), which would make metric_stuck_approval_claims() flag every
    successful approval ever made as "stuck" once it ages past the window —
    and would let claim_approval() try to re-win it (RESOLVED, like a still-
    CLAIMED doc, always loses the race — this alert is done, not retryable).
    Best-effort from the caller's side (agent.py wraps this in try/except): if
    it fails, the claim stays CLAIMED and surfaces as a false "stuck" claim —
    noisy, but never a security issue, and consistent with this module's
    fail-closed-into-visibility posture elsewhere.

    actor/reason/if_seq_no/if_primary_term are #276's manual-recovery-only
    parameters — see _transition_claim's docstring. agent.py's own call
    site passes none of them.
    """
    return _transition_claim(tenant_id, alert_id, "RESOLVED", actor=actor, reason=reason,
                             if_seq_no=if_seq_no, if_primary_term=if_primary_term)

#!/usr/bin/env python3
"""
compact_agent_checkpoints.py — per-document TTL retention for
agent-checkpoints-<tenant> (#256).

#245 dropped this index's ILM policy rather than reinstate a semantically
wrong one: agent-checkpoints-<tenant> is a single, always-growing index
keyed by alert_id (checkpoints.py does upsert-by-id PUT/GET, not
time-series writes) — ILM's delete phase removes an index only once it
ages out AS A WHOLE via rollover, which would delete the entire index,
live data included, the first time a "delete at 30d" policy fired against
a non-rolling index. Per-document TTL via a periodic _delete_by_query is
the fix, matching compact_agent_approval_queue.py's (#176) established
pattern for the exact same class of problem in the JSONL approval queue.

Two DISTINCT document shapes share this index (checkpoints.py):
  - phase checkpoints, doc id = bare alert_id. Terminal phases (safe to
    delete once past retention): NO_ACTION_PROTECTED_ASSET, AUTO_ISOLATED,
    EXECUTED, ISOLATION_FAILED. Non-terminal (must NEVER be deleted, no
    matter how old): PERCEIVING, PENDING_APPROVAL — either means the alert
    is still mid-processing or awaiting a human /approve/retry; deleting it
    would let is_duplicate()/is_awaiting_approval() silently forget an
    alert that hasn't actually been resolved, and a replayed webhook could
    reprocess it as if new.
  - claim docs, doc id = "{alert_id}.claim". ONLY RELEASED is treated as
    terminal here — NOT RESOLVED, and this is deliberate, not an
    incompleteness to "fix" later (security-auditor round 1 MEDIUM, the
    sharpest finding of this review — read this before changing it):
    claim_approval() (#214) uses ES op_type=create as its atomicity
    primitive, so once a claim doc for an alert_id is gone, the NEXT
    /approve for that same alert_id wins a fresh claim unconditionally.
    For a RELEASED claim that is exactly correct (release_claim() already
    means "confirmed non-dispatch, safe to retry" — deleting it changes
    nothing claim_approval() wouldn't already do via its own RELEASED
    reclaim path). For a RESOLVED claim it is NOT safe in general: on an
    execution whose outcome was IsolationOutcomeUnknown, agent.py leaves
    the PAIRED PHASE CHECKPOINT at PENDING_APPROVAL (not EXECUTED) so a
    human can still resolve it — and @timestamp on a claim doc is set ONLY
    by claim_approval() (when it was WON), never updated by resolve_claim()
    (see the note below). So a claim an operator RESOLVED recently, after
    confirming out-of-band that an old, ambiguous execution DID land, can
    still be old enough by claim-age to be deleted here — and once deleted,
    a later /approve on that still-PENDING_APPROVAL checkpoint would win a
    FRESH claim and dispatch a SECOND, real containment action. Never
    deleting RESOLVED closes this path entirely, at the cost of one small
    document per successfully-executed alert accumulating (the much larger
    EXECUTED phase-checkpoint doc, which DOES get cleaned up, held most of
    the retention-relevant size to begin with).
    CLAIMED itself must NEVER be deleted by this script, at any age,
    regardless of the above — that would reopen the at-most-once gate for
    an alert that is not even confirmed non-dispatched yet, the most
    dangerous version of the same class of bug. This is the exact security
    property agent_checkpoints's ES role (#245) is deliberately scoped to
    protect by holding NO delete privilege at all (though see the note
    below on why that guarantee is necessary but not sufficient on its
    own) — this script uses a SEPARATE, purpose-built credential
    (agent_checkpoints_compactor, read+delete on agent-checkpoints-* ONLY)
    so the live agent/CLI credential's delete-free guarantee is never
    touched or widened. Today, a CLAIMED doc that never resolves has no
    automated recovery path — #276 (PR #311, open/unmerged as of this
    writing) proposes adding one (manage_stuck_claims.py); until it lands,
    resolving one requires the hand-crafted ES _update call #276's own
    issue body describes. This script does not depend on that tool
    existing — it simply never touches CLAIMED, with or without it.

    NOTE on the "no delete privilege" guarantee's actual scope: it is
    necessary but not sufficient by itself. agent_checkpoints's role still
    holds `index` (full-document PUT), which can overwrite a live CLAIMED
    doc's phase field directly (bypassing checkpoints.py's own
    release_claim()/resolve_claim() helpers) — claim_approval()'s
    conditional-PUT reclaim path would then hand that alert_id's claim to
    the next /approve exactly as if it had gone through the normal RELEASED
    path. That is a pre-existing #245-era property of the write privilege
    itself, not something this compaction script introduces or can close;
    noted here only so the "delete-free = safe" framing above isn't read
    as a complete guarantee.

suppress: docs (#220's host+technique suppression-window state, same
index) have no `phase` field at all and are therefore never matched by
this script's query (which requires `phase` to exist) — out of scope
here, tracked separately if their own growth ever needs bounding.

@timestamp semantics differ by doc shape (checkpoints.py): on a phase
checkpoint it's set by every write_checkpoint() call (a full PUT, so it
reflects the CURRENT phase's own transition time). On a claim doc it's set
ONLY by claim_approval() and never touched by _transition_claim()'s
partial update — so it reflects when the claim was WON, not when it was
RELEASED/RESOLVED. A claim resolved recently but originally won long ago
is therefore retention-eligible by claim-age, not resolution-age; no other
timestamp exists on the common (non-manually-resolved) path to measure
resolution age instead. Documented, not treated as a bug — matches this
issue's own suggested design.

Run manually or on a schedule (configs/systemd/checkpoints-compact.timer),
mirroring intel-refresh.timer / compact_agent_approval_queue.py's cadence.

#376: the actual delete uses wait_for_completion=false + polls Elasticsearch's
_tasks API for completion (see _wait_for_task()) rather than a single
synchronous request with a fixed client timeout — a client-side give-up used
to leave the server-side delete running unbounded, with a re-run doubling the
work and no record of what the first attempt removed. Ports #358's identical
fix from this script's compact_threat_intel.py sibling (deliberately scoped
out of that PR — see this file's own history). AGENT_CHECKPOINTS_COMPACT_
POLL_TIMEOUT_S / _POLL_INTERVAL_S override the polling budget/cadence.

Usage:
  python compact_agent_checkpoints.py [--tenant TENANT] [--retention-days N] [--dry-run]
"""
import argparse
import os
import re
import sys
import time
from pathlib import Path

import requests

# Shared retrying Session (#170/#358) — see scripts/setup/lib/es_client.py's
# own docstring for the exact policy (502/503/504 + connection failures
# retried with backoff; read=0 so a response-read timeout is never
# retried). Used specifically for _wait_for_task()'s polling below, NOT
# for this module's other calls (count/delete-kickoff) — a transient blip
# mid-poll is exactly the case that should retry rather than abort the
# whole wait, matching compact_threat_intel.py's own #358 fix.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import es_client  # noqa: E402

TERMINAL_CHECKPOINT_PHASES = frozenset({
    "NO_ACTION_PROTECTED_ASSET", "AUTO_ISOLATED", "EXECUTED", "ISOLATION_FAILED",
})
# CLAIMED is deliberately absent — see the module docstring. This is not an
# oversight to "complete" later; a claim doc must never be deleted while CLAIMED.
# RESOLVED is ALSO deliberately absent (security-auditor round 1 MEDIUM — see
# the module docstring's long note on this): a RESOLVED claim's @timestamp
# reflects when it was originally CLAIMED, not when it was resolved, and its
# paired phase checkpoint can still be PENDING_APPROVAL (an
# IsolationOutcomeUnknown execution) — deleting it can let a later /approve
# win a FRESH claim and dispatch a real second containment action. Only
# RELEASED is safe to delete: claim_approval()'s own reclaim path already
# treats a RELEASED claim as freely re-winnable, so removing the document
# changes nothing that function wouldn't already do.
TERMINAL_CLAIM_PHASES = frozenset({"RELEASED"})
ALL_TERMINAL_PHASES = TERMINAL_CHECKPOINT_PHASES | TERMINAL_CLAIM_PHASES
assert "CLAIMED" not in ALL_TERMINAL_PHASES, "refusing to import: CLAIMED must never be deletable"
assert "RESOLVED" not in ALL_TERMINAL_PHASES, "refusing to import: RESOLVED must never be deletable (see docstring)"

DEFAULT_RETENTION_DAYS = 90

# Same grammar as agent.py's own _TENANT_RE/safe_tenant() (checkpoints.py
# itself has no tenant validation of its own as of this writing — every
# caller reaches it only through agent.py's HTTP entry points, which
# already gate tenant_id first). "*" is an explicit sentinel (every
# tenant), not something the regex itself accepts.
# \Z (not $): security-auditor round 1 LOW — Python's $ matches immediately
# before a trailing newline, so re.match(r"...$") against "home-smith\n"
# would incorrectly validate. Not exploitable here (requests/urllib3 reject
# control characters in URLs outright), but the validator should mean what
# it appears to mean regardless.
_TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}\Z")

ES_HOST = os.environ.get("ES_HOST", "https://elasticsearch:9200")
ES_USER = os.environ.get("AGENT_CHECKPOINTS_COMPACTOR_ES_USER", "agent_checkpoints_compactor")
ES_PASS = os.environ.get("AGENT_CHECKPOINTS_COMPACTOR_ES_PASS", "")
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

# #376: _wait_for_task()'s polling GET is idempotent and read-only — safe to
# retry transparently, unlike this module's own writes (_delete_by_query),
# which stay on plain `requests` so this module's existing at-most-once
# write semantics don't change.
TASK_POLL_SESSION = es_client.get_session(ES_USER, ES_PASS)


# #376: a client-side timeout on a SYNCHRONOUS _delete_by_query does not
# cancel the task on the ES server — it keeps running regardless, so a run
# that legitimately exceeds the old fixed 60s (e.g. after a long
# accumulation gap) surfaced as a client failure while ES kept deleting,
# and a re-run then doubled the work with no record of what the first
# attempt actually removed. TASK_POLL_TIMEOUT_SECONDS bounds how long THIS
# SCRIPT waits for the task to report completed=true (see _wait_for_task())
# — it does not bound the task itself, which Elasticsearch keeps running
# either way.
def _env_float(name: str, default: float, *, minimum: float) -> float:
    """Parses an overridable numeric env var, degrading to `default` (with a
    stderr warning, not a crash) on anything malformed — this runs at MODULE
    IMPORT time, before main()'s own try/except error-handling exists, so a
    bad override must never produce a raw traceback on every invocation
    until it's fixed. `minimum` guards specifically against a
    non-positive/too-small poll interval turning _wait_for_task() into an
    unthrottled busy-loop against Elasticsearch. Ported verbatim from
    compact_threat_intel.py's #358 fix."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        print(f"WARN: {name}={raw!r} is not a valid number — using default "
              f"{default:g}", file=sys.stderr)
        return default
    if value < minimum:
        print(f"WARN: {name}={raw!r} is below the minimum {minimum:g} — "
              f"using {minimum:g} instead", file=sys.stderr)
        return minimum
    return value


TASK_POLL_TIMEOUT_SECONDS = _env_float("AGENT_CHECKPOINTS_COMPACT_POLL_TIMEOUT_S", 300.0, minimum=1.0)
TASK_POLL_INTERVAL_SECONDS = _env_float("AGENT_CHECKPOINTS_COMPACT_POLL_INTERVAL_S", 2.0, minimum=0.1)


def _is_transient_poll_error(e: requests.RequestException) -> bool:
    """502/503/504 and connection/timeout failures (no response at all) are
    exactly the class `es_client.get_session()`'s own `Retry` policy already
    treats as safe to retry (see that module's docstring) — `TASK_POLL_
    SESSION` already retried those internally before this ever reaches here,
    so seeing one HERE means a sustained outage, worth `_wait_for_task()`'s
    own OUTER poll-until-deadline retry too. Anything else (401/403/404/400
    — a permission or addressing problem, not a transient one) would fail
    the exact same way on every retry, so it is not worth spinning the
    whole poll budget on before giving up. Ported verbatim from
    compact_threat_intel.py's #358 fix."""
    if isinstance(e, requests.HTTPError):
        if e.response is None:
            return True  # can't confirm it's permanent — the safer default is to retry
        return e.response.status_code in (502, 503, 504)
    return True  # ConnectionError, Timeout, etc. — no response to inspect at all.


def _wait_for_task(task_id: str, index: str) -> dict:
    """Polls `GET _tasks/<task_id>` until Elasticsearch reports the task
    `completed`, returning its `response` body — the same shape a
    SYNCHRONOUS `_delete_by_query` call would have returned directly (#376,
    porting #358's identical fix from compact_threat_intel.py).

    This is the fix for the client-timeout-doesn't-cancel-the-server-task
    gap: this function's own poll budget (`TASK_POLL_TIMEOUT_SECONDS`)
    bounds how long THIS PROCESS waits, never the task itself, which
    Elasticsearch keeps running regardless of whether anything is still
    polling it. If that budget elapses, raises WITHOUT attempting to
    cancel the task, carrying the real `task_id` so the run is reconcilable
    later via a manual `GET _tasks/<task_id>` instead of lost, and warning
    explicitly against a re-run (a second concurrent delete against the
    same query would double the work).

    Also raises if the task itself reports `completed:true` with an
    `error` key (a genuine failure, not a partial per-document one — must
    not be read as "0/0 document(s) deleted, clean run"), or with neither
    `error` nor `response` (a shape this function's contract doesn't
    guarantee can't happen — cannot confirm what, if anything, was
    deleted). A single transient poll failure (502/503/504, a connection
    blip) is treated the same as "not yet complete" and retried within the
    SAME poll budget, with the same reconciliation guidance once that
    budget is exhausted — ported from compact_threat_intel.py's #358 fix
    verbatim; see that module's own docstring for the two live-reproduced
    failure modes this logic was validated against."""
    deadline = time.monotonic() + TASK_POLL_TIMEOUT_SECONDS
    while True:
        try:
            res = TASK_POLL_SESSION.get(f"{ES_HOST}/_tasks/{task_id}",
                                        verify=ES_VERIFY, timeout=15)
            res.raise_for_status()
            task = res.json()
            if task.get("completed"):
                if "error" in task:
                    raise RuntimeError(
                        f"{index}: delete_by_query task {task_id} FAILED: {task['error']}")
                if "response" not in task:
                    raise RuntimeError(
                        f"{index}: delete_by_query task {task_id} completed with "
                        f"neither `response` nor `error` — cannot confirm what, if "
                        f"anything, was deleted (raw task doc: {task})")
                return task["response"]
        except RuntimeError:
            raise
        except requests.RequestException as e:
            if not _is_transient_poll_error(e):
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{index}: delete_by_query task {task_id} — polling failed "
                    f"({e}) and the {TASK_POLL_TIMEOUT_SECONDS:g}s poll budget is "
                    f"exhausted. The task's own completion status is UNKNOWN — it "
                    f"may still be running on Elasticsearch (this script never "
                    f"cancels it). Do NOT re-run this script until confirmed done "
                    f"via `GET _tasks/{task_id}` — a second concurrent delete "
                    f"against the same query would double the work.") from e
            time.sleep(TASK_POLL_INTERVAL_SECONDS)
            continue
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"{index}: delete_by_query task {task_id} did not complete within "
                f"{TASK_POLL_TIMEOUT_SECONDS:g}s of polling — it is STILL RUNNING on "
                f"Elasticsearch (this script never cancels it). Do NOT re-run this "
                f"script until confirmed done via `GET _tasks/{task_id}` — a second "
                f"concurrent delete against the same query would double the work.")
        time.sleep(TASK_POLL_INTERVAL_SECONDS)


def _get_auth():
    return (ES_USER, ES_PASS) if ES_USER else None


def _validate_tenant_id(tenant_id: str) -> str:
    if tenant_id == "*" or _TENANT_RE.match(tenant_id or ""):
        return tenant_id
    raise ValueError(f"invalid tenant_id: {tenant_id!r}")


def _build_query(retention_days: int):
    # code-reviewer round 1: ES date-math ("now-Nd") only accepts an
    # integer digit run before the unit letter — a fractional value here
    # (e.g. "now-45.5d") is not valid date-math and 400s. retention_days is
    # typed int end-to-end (argparse, this function, compact()) specifically
    # so this can never be reached with a fractional value, matching
    # compact_agent_approval_queue.py's own --retention-days precedent.
    return {
        "query": {"bool": {"filter": [
            {"exists": {"field": "phase"}},
            {"terms": {"phase": sorted(ALL_TERMINAL_PHASES)}},
            {"range": {"@timestamp": {"lt": f"now-{retention_days:d}d"}}},
        ]}}
    }


def compact(tenant_id: str = "*", retention_days: int = DEFAULT_RETENTION_DAYS,
            dry_run: bool = False) -> int:
    """Deletes terminal, aged-out checkpoint AND claim documents. Scoped to
    one tenant's index, or every tenant's via the "*" wildcard (the
    scheduled/default case — the same wildcard-tenant convention #276's
    proposed checkpoints.search_stuck_claims() uses, PR #311, unmerged as
    of this writing).

    Returns the count deleted (or, for a dry run, the count that WOULD be
    deleted, via _count instead of _delete_by_query — dry-run mode never
    calls the delete endpoint at all, not even in a conflicts=proceed,
    zero-effect way).
    """
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) or retention_days <= 0:
        raise ValueError(f"retention_days must be a positive integer, got {retention_days!r}")
    _validate_tenant_id(tenant_id)
    index = f"agent-checkpoints-{tenant_id}"
    query = _build_query(retention_days)

    if dry_run:
        res = requests.post(f"{ES_HOST}/{index}/_count", json=query,
                            auth=_get_auth(), verify=ES_VERIFY, timeout=15)
        res.raise_for_status()
        count = res.json().get("count", 0)
        print(f"[dry-run] {index}: {count} document(s) would be deleted "
              f"(phase in {sorted(ALL_TERMINAL_PHASES)}, older than {retention_days}d). "
              f"No changes made.")
        return count

    # #376: wait_for_completion=false returns almost immediately with a task
    # ID rather than blocking on the delete itself — the kickoff call's own
    # short timeout is safe precisely because it no longer has to cover the
    # delete's real duration; _wait_for_task() does that instead, with a
    # bound that (unlike the old fixed client timeout) never orphans the
    # server-side task without a way to reconcile it.
    start_res = requests.post(
        f"{ES_HOST}/{index}/_delete_by_query?conflicts=proceed&wait_for_completion=false",
        json=query, auth=_get_auth(), verify=ES_VERIFY, timeout=15)
    start_res.raise_for_status()
    task_id = start_res.json().get("task")
    if not task_id:
        # A 2xx with no `task` key would otherwise raise an uncaught
        # KeyError here, outside main()'s (requests.RequestException,
        # RuntimeError) catch — surfacing as a raw traceback instead of the
        # clean "Error: ..." exit main() gives every other failure mode.
        raise RuntimeError(
            f"{index}: delete_by_query kickoff returned no task id: "
            f"{start_res.text[:200]}")
    print(f"{index}: delete_by_query started (task {task_id}), polling for completion...")
    body = _wait_for_task(task_id, index)
    deleted = body.get("deleted", 0)
    total = body.get("total", 0)
    version_conflicts = body.get("version_conflicts", 0)
    timed_out = body.get("timed_out", False)
    failures = body.get("failures") or []
    # security-auditor round 1 MEDIUM: only `failures` was ever inspected —
    # with conflicts=proceed, a document that lost a concurrent-modification
    # race (e.g. re-CLAIMED mid-query — the safe, intended outcome) lands in
    # `version_conflicts`, NOT `failures`, so a run that skipped documents
    # for that reason previously reported clean success with no visibility
    # at all. `timed_out` was also never checked — a job that ran out of
    # time reports whatever partial `deleted` count it reached as if it
    # were the complete result. Surface all of it; a scheduled job with
    # nothing consuming its output must not fail silently.
    print(f"{index}: {deleted}/{total} document(s) deleted "
          f"(phase in {sorted(ALL_TERMINAL_PHASES)}, older than {retention_days}d)"
          f"{f', {version_conflicts} version conflict(s) (skipped, safe)' if version_conflicts else ''}"
          f"{', TIMED OUT (partial result)' if timed_out else ''}.")
    if failures:
        print(f"{index}: {len(failures)} failure(s) — first: {failures[0]}", file=sys.stderr)
    if failures or timed_out:
        raise RuntimeError(
            f"{index}: delete_by_query did not complete cleanly "
            f"({len(failures)} failure(s), timed_out={timed_out}) — "
            f"re-run investigation before trusting this run's {deleted} deleted count")
    return deleted


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant", default="*",
                        help="Tenant slug (e.g. home-smith), or omit for every tenant (default)")
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS,
                        help=f"Delete terminal documents older than this many days "
                             f"(default {DEFAULT_RETENTION_DAYS}; must be a whole number — "
                             f"ES date-math (\"now-Nd\") has no fractional-day syntax)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be deleted without deleting anything")
    args = parser.parse_args()
    try:
        compact(args.tenant, args.retention_days, args.dry_run)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.HTTPError as e:
        print(f"Error: Elasticsearch rejected the request: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        # code-reviewer round 1: HTTPError alone misses connection failures
        # (ES unreachable/down, TLS error, timeout) — a realistic scheduled-
        # job failure mode, e.g. running before the stack has come up.
        # Matches slo_metrics.py's own top-level exception handling for the
        # same reason.
        print(f"Error: could not reach Elasticsearch: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        # security-auditor round 1 MEDIUM: a run with failures or a timeout
        # must exit non-zero — systemd (and any other scheduler) must be
        # able to tell a clean run from a dirty one from the exit code
        # alone, not just from parsing stdout/stderr.
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

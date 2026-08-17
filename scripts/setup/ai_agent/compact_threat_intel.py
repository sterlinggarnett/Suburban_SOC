#!/usr/bin/env python3
"""
compact_threat_intel.py — per-document TTL retention for
threat-intel-indicators / threat-intel-meta (#271).

refresh_intel.sh's Elasticsearch bulk-index step (`_id = indicator`)
upserts every indicator on every run but never deletes one a feed has since
removed (e.g. a botnet C2 IP that got remediated/delisted) — the index
accumulates every indicator ever observed, indefinitely. threat-intel-meta
(the per-run freshness heartbeat doc scripts/setup/ai_agent/slo_metrics.py's
metric_intel_feed_stale_heartbeats() and the "Threat Intel Feed Health"
dashboard read — #358; formerly rules/elastic_watcher/intel_feed_stale.json's
Watcher, retired, never actually fired on this Basic-license stack) has the
same problem in a more acute form: it is POSTed with no explicit _id, so a
NEW document is created every single run (every 6h, intel-refresh.timer)
with no natural size cap at all, unlike threat-intel-indicators which is at
least bounded by the number of distinct indicators the feeds have ever
produced.

Both are safe to prune by simple age, unlike agent-checkpoints'
compact_agent_checkpoints.py sibling script (#256) — that index needed a
careful terminal-vs-non-terminal PHASE distinction because deleting the
wrong document could silently reopen an at-most-once execution gate. There
is no equivalent live invariant here — BOTH indices are retention-keyed on
@timestamp, not on the newer threat.indicator.last_seen field (security-
auditor review; live-confirmed against real accumulated data: 170 of 728
real threat-intel-indicators docs pre-dated last_seen entirely and would
have been permanently UNDELETABLE keying on it, since an ES range query
never matches a document missing the field — exactly the already-stale
backlog #271 exists to retract):
  - threat-intel-indicators: refresh_intel.sh's bulk "index" action (not
    "create") fully REPLACES an existing _id, not a partial update, so
    @timestamp is re-stamped to "now" on EVERY run for EVERY indicator
    still present in the merged feed output — this was already true
    before #271 (#222's original design), independent of the new
    threat.indicator.last_seen field #271 also added. An indicator the
    feeds have since dropped simply stops getting its @timestamp
    refreshed and ages out on its own. Deleting an aged-out doc only
    removes a stale IOC record; Zeek's own intel.dat (what live detection
    actually reads) already reflects current feed content independently
    of this index. threat.indicator.last_seen carries the byte-identical
    value on every post-#271 write (refresh_intel.sh stamps both from the
    same $now) — kept as a properly-named ECS field for anyone querying
    "when was this indicator last confirmed live" directly, but retention
    itself keys on the field guaranteed present on every doc, old and new.
  - threat-intel-meta: each doc is an immutable, independent point-in-time
    heartbeat (@timestamp = when that run happened) — nothing about an old
    heartbeat's existence is load-bearing beyond metric_intel_feed_stale_
    heartbeats()'s own `now-8h` window, confirmed by reading that metric
    directly (scripts/setup/ai_agent/slo_metrics.py): DEFAULT_RETENTION_DAYS
    below is a full order of magnitude past that window, so this script
    can never delete a doc that metric still needs.

Run manually or on a schedule (configs/systemd/threat-intel-compact.timer),
mirroring checkpoints-compact.timer / compact_agent_checkpoints.py's cadence
and structure.

#358: the actual delete uses wait_for_completion=false + polls Elasticsearch's
_tasks API for completion (see _wait_for_task()) rather than a single
synchronous request with a fixed client timeout — a client-side give-up used
to leave the server-side delete running unbounded, with a re-run doubling the
work and no record of what the first attempt removed. THREAT_INTEL_COMPACT_
POLL_TIMEOUT_S / _POLL_INTERVAL_S override the polling budget/cadence.

Usage:
  python compact_threat_intel.py [--retention-days N] [--dry-run] [--force]
"""
import argparse
import os
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
# whole wait (security-auditor finding: a bare 502/503 used to abort
# _wait_for_task() immediately, without the "do NOT re-run" guidance the
# genuine-timeout path gives).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import es_client  # noqa: E402

# #271 originally suggested 7d; raised to 30d (security-auditor review): the
# "Threat Intel Feed Health" dashboard's own saved search
# (configs/server/intel_feed_health.ndjson) opens on a `now-7d` window over
# threat-intel-meta — a 7d retention would empty the left edge of every
# trend panel daily, right at the boundary an analyst is most likely to be
# looking at ("when did the feed start degrading?"). 30d clears that with
# room to spare; both indices stay low-volume enough (one heartbeat + at
# most a few hundred indicator docs per 6h refresh) that the extra 23 days
# of retention costs nothing.
DEFAULT_RETENTION_DAYS = 30

ES_HOST = os.environ.get("ES_HOST", "https://elasticsearch:9200")
ES_USER = os.environ.get("THREAT_INTEL_COMPACTOR_ES_USER", "threat_intel_compactor")
ES_PASS = os.environ.get("THREAT_INTEL_COMPACTOR_ES_PASS", "")
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

# #358: _wait_for_task()'s polling GET is idempotent and read-only — safe to
# retry transparently, unlike this module's own writes (_delete_by_query),
# which stay on plain `requests` so this module's existing at-most-once
# write semantics don't change.
TASK_POLL_SESSION = es_client.get_session(ES_USER, ES_PASS)

# #358: a client-side timeout on a SYNCHRONOUS _delete_by_query does not
# cancel the task on the ES server — it keeps running regardless, so a run
# that legitimately exceeds the old fixed 60s (e.g. after a long
# accumulation gap) surfaced as a client failure while ES kept deleting,
# and a re-run then doubled the work with no record of what the first
# attempt actually removed. TASK_POLL_TIMEOUT_SECONDS bounds how long THIS
# SCRIPT waits for the task to report completed=true (see _wait_for_task())
# — it does not bound the task itself, which Elasticsearch keeps running
# either way. Generous relative to this module's own documented volumes
# (one heartbeat + at most a few hundred indicator docs per 6h refresh):
# hitting this should mean a genuinely abnormal backlog, not routine
# operation.
def _env_float(name: str, default: float, *, minimum: float) -> float:
    """Parses an overridable numeric env var, degrading to `default` (with a
    stderr warning, not a crash) on anything malformed — this runs at MODULE
    IMPORT time, before main()'s own try/except error-handling exists, so a
    bad override must never produce a raw traceback on every invocation
    until it's fixed (reviewer finding). `minimum` guards specifically
    against a non-positive/too-small poll interval turning _wait_for_task()
    into an unthrottled busy-loop against Elasticsearch."""
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


TASK_POLL_TIMEOUT_SECONDS = _env_float("THREAT_INTEL_COMPACT_POLL_TIMEOUT_S", 300.0, minimum=1.0)
TASK_POLL_INTERVAL_SECONDS = _env_float("THREAT_INTEL_COMPACT_POLL_INTERVAL_S", 2.0, minimum=0.1)

# Both indices are retention-keyed on the same @timestamp semantics — see
# the module docstring for why threat-intel-indicators keys on @timestamp
# rather than the newer threat.indicator.last_seen field, and why a single
# shared cutoff is safe for both, unlike compact_agent_checkpoints.py's
# per-phase distinctions.
DATE_FIELD = "@timestamp"
TARGET_INDICES = ("threat-intel-indicators", "threat-intel-meta")


def _get_auth():
    return (ES_USER, ES_PASS) if ES_USER else None


def _validate_retention_days(retention_days: int) -> None:
    if not isinstance(retention_days, int) or isinstance(retention_days, bool) or retention_days <= 0:
        raise ValueError(f"retention_days must be a positive integer, got {retention_days!r}")


def _build_query(date_field: str, retention_days: int):
    # code-reviewer precedent (compact_agent_checkpoints.py): ES date-math
    # ("now-Nd") only accepts an integer digit run before the unit letter —
    # retention_days is typed int end-to-end so a fractional value can never
    # reach here.
    return {"query": {"range": {date_field: {"lt": f"now-{retention_days:d}d"}}}}


# security-auditor review: unlike compact_agent_checkpoints.py, this
# script's delete query has a SINGLE predicate (a date range), not a
# multi-clause filter that also requires a specific phase — that sibling
# script's invariant (CLAIMED/PENDING_APPROVAL can never match) survives
# even if its date logic misbehaves, because two other clauses still gate
# it. This script has no second clause to fall back on: a mis-mapped
# date_field (e.g. re-created as keyword/text under some future template —
# none exists today — makes "lt" a lexicographic string compare, matching
# almost everything), a dead writer (refresh_intel.sh failing silently for
# retention_days+), or a direct compact_index() call bypassing compact()'s
# own validation could each make EVERY document in an index match at once.
# BLAST_RADIUS_FRACTION refuses that outcome by default: if what WOULD be
# deleted is more than half of what the index currently holds, treat it as
# suspicious and require an explicit --force to proceed, mirroring the
# review's own recommendation. Below the floor, a small index can
# legitimately clear >50% in one run (e.g. threat-intel-meta after a long
# gap) without tripping this — MIN_DOCS_FOR_BLAST_RADIUS_CHECK exists so
# that a nearly-empty index (a handful of docs, one deleted = "100%") never
# needs --force just because the ratio looks extreme at a trivial scale.
BLAST_RADIUS_FRACTION = 0.5
MIN_DOCS_FOR_BLAST_RADIUS_CHECK = 20


def _is_transient_poll_error(e: requests.RequestException) -> bool:
    """502/503/504 and connection/timeout failures (no response at all) are
    exactly the class `es_client.get_session()`'s own `Retry` policy already
    treats as safe to retry (see that module's docstring) — `TASK_POLL_
    SESSION` already retried those internally before this ever reaches here,
    so seeing one HERE means a sustained outage, worth `_wait_for_task()`'s
    own OUTER poll-until-deadline retry too. Anything else (401/403/404/400
    — a permission or addressing problem, not a transient one) would fail
    the exact same way on every retry, so it is not worth spinning the
    whole poll budget on before giving up."""
    if isinstance(e, requests.HTTPError):
        if e.response is None:
            return True  # can't confirm it's permanent — the safer default is to retry
        return e.response.status_code in (502, 503, 504)
    return True  # ConnectionError, Timeout, etc. — no response to inspect at all.


def _wait_for_task(task_id: str, index: str) -> dict:
    """Polls `GET _tasks/<task_id>` until Elasticsearch reports the task
    `completed`, returning its `response` body — the same shape a
    SYNCHRONOUS `_delete_by_query` call would have returned directly (#358).

    This is the fix for the client-timeout-doesn't-cancel-the-server-task
    gap: this function's own poll budget (`TASK_POLL_TIMEOUT_SECONDS`)
    bounds how long THIS PROCESS waits, never the task itself, which
    Elasticsearch keeps running regardless of whether anything is still
    polling it. If that budget elapses, raises WITHOUT attempting to
    cancel the task — cancellation was never the ask, and half-cancelling
    a delete_by_query construction is its own risk surface — carrying the
    real `task_id` so the run is reconcilable later via a manual `GET
    _tasks/<task_id>` instead of lost, and warning explicitly against a
    re-run (a second concurrent delete against the same query would double
    the work, exactly the failure mode #358 was filed to close).

    security-auditor review, two findings folded in:
    - A task that failed outright (not just a partial per-document failure
      — see below) could in principle still report `completed:true` as
      `{"completed":true,"error":{...}}` with no `response` key at all.
      Returning `{}` for that (the first draft's behavior) would have let
      `compact_index()` print "0/0 document(s) deleted" and exit 0 on a
      genuinely failed delete — the exact "reports clean success on a
      degraded run" this file's own docstring standard (see the
      version_conflicts/timed_out visibility comment below) already
      rejects, so both `error` present and BOTH `error`/`response` absent
      now raise instead of silently returning an empty result. tester-
      debugger live-reproduced two real task failures (deleting the target
      index mid-flight; closing it mid-scroll) against a real cluster —
      BOTH surfaced as `completed:true` with `response.failures` populated
      and no top-level `error` key, which `compact_index()`'s own existing
      `failures`/`timed_out` check (below) already catches correctly
      through the normal `response` return path. The `error`-key branch
      above is a defensive fallback for a shape neither of those two
      real failures actually produced — plausible for something more
      severe (e.g. a coordinating-node crash before any response object
      exists) but NOT independently live-confirmed; the two failure modes
      that ARE confirmed are handled one layer up, not by this branch.
    - A single transient poll failure (a 502/503/504, a connection blip)
      used to abort the whole wait immediately, WITHOUT the "do NOT re-run"
      guidance the timeout path gives — the one path most likely to
      actually occur in practice, and the one where an operator seeing a
      bare "503 Service Unavailable" would reasonably (and dangerously)
      just re-run the script. A transient failure is now treated the same
      as "not yet complete" and retried within the SAME poll budget; only
      once that budget is exhausted does it raise, with the same
      reconciliation guidance as a genuine timeout.
    """
    deadline = time.monotonic() + TASK_POLL_TIMEOUT_SECONDS
    while True:
        try:
            # TASK_POLL_SESSION (es_client.get_session): a 502/503/504 or
            # connection failure is retried transparently, with backoff,
            # INSIDE this one call — the outer except below only sees
            # something after that transport-level retry budget is ALSO
            # exhausted, covering a longer outage the session's own few
            # quick retries wouldn't ride out.
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


def compact_index(index: str, date_field: str, retention_days: int,
                   dry_run: bool = False, force: bool = False) -> int:
    """Deletes (or, dry-run, counts) documents in `index` whose `date_field`
    is older than `retention_days`. Returns the count deleted/would-delete.
    Refuses to delete (RuntimeError) if the match exceeds BLAST_RADIUS_FRACTION
    of the index's current total, unless `force` is set — see the module-level
    comment above BLAST_RADIUS_FRACTION for why this script needs that check
    where compact_agent_checkpoints.py doesn't."""
    _validate_retention_days(retention_days)
    query = _build_query(date_field, retention_days)

    count_res = requests.post(f"{ES_HOST}/{index}/_count", json=query,
                              auth=_get_auth(), verify=ES_VERIFY, timeout=15)
    count_res.raise_for_status()
    matched = count_res.json().get("count", 0)

    if dry_run:
        print(f"[dry-run] {index}: {matched} document(s) would be deleted "
              f"({date_field} older than {retention_days}d). No changes made.")
        return matched

    if matched > 0 and not force:
        total_res = requests.post(f"{ES_HOST}/{index}/_count", json={"query": {"match_all": {}}},
                                  auth=_get_auth(), verify=ES_VERIFY, timeout=15)
        total_res.raise_for_status()
        total = total_res.json().get("count", 0)
        if total >= MIN_DOCS_FOR_BLAST_RADIUS_CHECK and matched > total * BLAST_RADIUS_FRACTION:
            raise RuntimeError(
                f"{index}: refusing to delete {matched}/{total} document(s) "
                f"({matched / total:.0%}, over the {BLAST_RADIUS_FRACTION:.0%} safety "
                f"threshold) — this usually means the writer stopped refreshing "
                f"{date_field} or it's no longer the right field to key retention on, "
                f"not that this many indicators genuinely aged out at once. "
                f"Pass force=True/--force to proceed anyway.")

    # #358: wait_for_completion=false returns almost immediately with a task
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
        # KeyError here — outside compact()'s (requests.RequestException,
        # RuntimeError) catch (security-auditor finding), skipping the
        # OTHER index's own compaction entirely instead of just this one.
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
    # Same visibility fix compact_agent_checkpoints.py's own review round
    # applied (security-auditor MEDIUM there): version_conflicts and
    # timed_out are surfaced explicitly, not just `failures` — a scheduled
    # job with nothing else consuming its output must not report clean
    # success on a partial or degraded run.
    print(f"{index}: {deleted}/{total} document(s) deleted "
          f"({date_field} older than {retention_days}d)"
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


def compact(retention_days: int = DEFAULT_RETENTION_DAYS, dry_run: bool = False,
            force: bool = False) -> dict:
    """Runs compact_index() over both TARGET_INDICES. Returns {index: count}.
    Each index is compacted independently — one index's failure/timeout
    (raised as RuntimeError) still lets the other complete first, matching
    this function's callers wanting partial progress over an all-or-nothing
    run against two otherwise-unrelated indices."""
    _validate_retention_days(retention_days)
    results = {}
    errors = []
    for index in TARGET_INDICES:
        try:
            results[index] = compact_index(index, DATE_FIELD, retention_days, dry_run, force)
        except (requests.RequestException, RuntimeError) as e:
            # Capture type+message now, inside the except block — Python
            # unbinds `e` itself at the block's end, so holding the
            # exception OBJECT past this point (rather than what it says)
            # is the kind of pattern static analysis flags for good reason.
            errors.append((index, type(e), str(e)))
    if len(errors) == 1:
        # code-reviewer/security-auditor finding: wrapping every failure in
        # a bare RuntimeError made main()'s requests.HTTPError/
        # requests.RequestException handlers dead code — "could not reach
        # Elasticsearch" never printed for a connection failure, only the
        # generic message. Re-raising the SAME exception type (with an
        # index-prefixed message) when exactly one index failed lets
        # main()'s specific handlers actually fire; only a genuinely
        # combined multi-index failure falls back to a plain RuntimeError,
        # since there's no single original type left to preserve.
        index, exc_type, msg = errors[0]
        raise exc_type(f"{index}: {msg}")
    if errors:
        raise RuntimeError("; ".join(f"{index}: {msg}" for index, _, msg in errors))
    return results


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS,
                        help=f"Delete documents older than this many days "
                             f"(default {DEFAULT_RETENTION_DAYS}; must be a whole number — "
                             f"ES date-math (\"now-Nd\") has no fractional-day syntax)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be deleted without deleting anything")
    parser.add_argument("--force", action="store_true",
                        help=f"Proceed even if a delete would remove more than "
                             f"{BLAST_RADIUS_FRACTION:.0%} of an index's current documents "
                             f"(the default refuses, since that usually means the writer "
                             f"stopped refreshing {DATE_FIELD} rather than that many "
                             f"documents genuinely aged out at once)")
    args = parser.parse_args()
    try:
        compact(args.retention_days, args.dry_run, args.force)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.HTTPError as e:
        print(f"Error: Elasticsearch rejected the request: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Error: could not reach Elasticsearch: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        # A run with failures or a timeout on either index must exit
        # non-zero — systemd (and any other scheduler) must be able to tell
        # a clean run from a dirty one from the exit code alone.
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

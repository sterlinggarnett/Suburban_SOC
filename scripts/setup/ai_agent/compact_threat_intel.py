#!/usr/bin/env python3
"""
compact_threat_intel.py — per-document TTL retention for
threat-intel-indicators / threat-intel-meta (#271).

refresh_intel.sh's Elasticsearch bulk-index step (`_id = indicator`)
upserts every indicator on every run but never deletes one a feed has since
removed (e.g. a botnet C2 IP that got remediated/delisted) — the index
accumulates every indicator ever observed, indefinitely. threat-intel-meta
(the per-run freshness heartbeat doc intel_feed_stale.json's Watcher and
the "Threat Intel Feed Health" dashboard read) has the same problem in a
more acute form: it is POSTed with no explicit _id, so a NEW document is
created every single run (every 6h, intel-refresh.timer) with no natural
size cap at all, unlike threat-intel-indicators which is at least bounded
by the number of distinct indicators the feeds have ever produced.

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
    heartbeat's existence is load-bearing beyond intel_feed_stale.json's
    own `now-8h` window (rules/elastic_watcher/intel_feed_stale.json),
    confirmed by reading that Watcher directly: DEFAULT_RETENTION_DAYS
    below is a full order of magnitude past that window, so this script
    can never delete a doc the Watcher still needs.

Run manually or on a schedule (configs/systemd/threat-intel-compact.timer),
mirroring checkpoints-compact.timer / compact_agent_checkpoints.py's cadence
and structure.

Usage:
  python compact_threat_intel.py [--retention-days N] [--dry-run] [--force]
"""
import argparse
import os
import sys

import requests

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

    res = requests.post(f"{ES_HOST}/{index}/_delete_by_query?conflicts=proceed",
                        json=query, auth=_get_auth(), verify=ES_VERIFY, timeout=60)
    res.raise_for_status()
    body = res.json()
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

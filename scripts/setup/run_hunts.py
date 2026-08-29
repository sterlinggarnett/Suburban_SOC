#!/usr/bin/env python3
"""
run_hunts.py — WS2.2: execute the versioned threat-hunt library on a schedule.

Loads every hunt in hunts/*.yml (hypothesis + ATT&CK technique + data source +
query), runs its query against Elasticsearch over a window, records a finding to
the `soc-hunts` index, and prints a report. Findings that recur are promotion
candidates for a detection (hunt -> detection loop, WS2.1).

Requires: requests, PyYAML. Env (auto-loaded from scripts/setup/.env):
  ES_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, HUNT_WINDOW (default now-7d).

Cron: see configs/hunts/hunts.cron.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HUNTS_DIR = REPO / "hunts"

# Shared connection-pooled, retrying Session (issue #170) + .env line parser
# (#259) — sibling module, no installable package here yet (tracked
# separately), so sys.path like the tests do. Moved before the .env-loading
# block below (rather than staying next to es_client's own use further down)
# specifically so env_loader is importable there.
sys.path.insert(0, str(HERE / "lib"))
import env_loader  # noqa: E402
import es_client  # noqa: E402

ENV = REPO / "scripts" / "setup" / ".env"
env_loader.load_env_file(ENV)

ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS") or os.environ.get("ELASTIC_PASSWORD", "")
WINDOW = os.environ.get("HUNT_WINDOW", "now-7d")
# FAIL CLOSED (audit P1-2): verify TLS against the stack CA, never verify=False.
# Set ES_CA to your CA path for host/standalone runs, or "" for system trust.
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

SESSION = es_client.get_session(ES_USER, ES_PASS)


class HuntQueryUnavailable(Exception):
    """Raised when a hunt's ES query could not be executed — distinct from a
    genuine zero-match count (audit #165 / NIST SI-11). A down or unreachable
    Elasticsearch must never be reported as 'no findings'."""


# #432: the composite ES _id main() builds (hunt_key:day_bucket) is a
# deliberate UPSERT, not a create-only op — a colliding hunt_key (an unsafe
# character like ':' inside a hunt's own id, or two hunts falling back to
# the same filename-stem-derived key) SILENTLY OVERWRITES one hunt's stored
# findings with another's, rather than erroring or appending. Lost hunt
# data, not just a display/tooltip ambiguity.
_HUNT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _validate_hunt_ids(hunts):
    """Fails loudly, before any bulk write, on an unsafe hunt id or a
    collision between two hunts' composite _id keys — whether from a
    colliding literal `id:` or a colliding filename-stem fallback."""
    seen = {}
    for path in hunts:
        h = yaml.safe_load(path.read_text(encoding="utf-8"))
        hunt_key = h.get("id") or path.stem
        if not _HUNT_ID_RE.match(hunt_key):
            print(f"ERROR: {path.name}: hunt id {hunt_key!r} contains characters "
                  f"outside [A-Za-z0-9_-] — would corrupt the composite ES _id "
                  f"('{hunt_key}:<day-bucket>') this script builds from it",
                  file=sys.stderr)
            sys.exit(1)
        if hunt_key in seen:
            print(f"ERROR: {path.name} and {seen[hunt_key].name} both resolve to "
                  f"hunt id {hunt_key!r} — would silently overwrite one hunt's "
                  f"stored findings with the other's via a colliding composite "
                  f"ES _id", file=sys.stderr)
            sys.exit(1)
        seen[hunt_key] = path


def es_count(index, query_string):
    body = {"query": {"bool": {"filter": [
        {"query_string": {"query": query_string}},
        {"range": {"@timestamp": {"gte": WINDOW}}}]}}}
    try:
        r = SESSION.post(f"{ES_URL}/{index}/_count",
                          verify=ES_VERIFY, headers={"Content-Type": "application/json"},
                          data=json.dumps(body), timeout=20)
        if r.status_code != 200:
            raise HuntQueryUnavailable(f"{index} count returned HTTP {r.status_code}")
        return r.json().get("count", 0)
    except HuntQueryUnavailable:
        raise
    except Exception as e:
        raise HuntQueryUnavailable(f"{index} count request failed: {e}") from e


def main():
    if not ES_PASS:
        print("ERROR: ES_PASS / ELASTIC_PASSWORD required", file=sys.stderr)
        sys.exit(1)
    hunts = sorted(HUNTS_DIR.glob("*.yml"))
    if not hunts:
        print("No hunts found in hunts/", file=sys.stderr)
        sys.exit(1)
    _validate_hunt_ids(hunts)
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    # audit #176: cron runs this hourly (configs/hunts/hunts.cron), and every
    # run re-evaluates the full rolling HUNT_WINDOW — without a stable _id,
    # each run appends a fresh doc per hunt, so soc-hunts grows unbounded
    # (hunts x 24/day forever). A deterministic per-day _id makes the bulk
    # "index" op an upsert: same hunt, same day -> the latest run's result
    # overwrites the prior one, bounding growth to hunts x days.
    day_bucket = now_dt.strftime("%Y-%m-%d")
    bulk, findings, hunt_errors = [], 0, 0
    print(f"Threat hunts @ {now}  (window {WINDOW})")
    print(f"  {'hunt'.ljust(10)} {'attack'.ljust(12)} {'count':>7}  finding")
    for path in hunts:
        h = yaml.safe_load(path.read_text(encoding="utf-8"))
        idx = h.get("index", "logstash-security-*")
        try:
            count = es_count(idx, h.get("query", "*"))
        except HuntQueryUnavailable as e:
            hunt_errors += 1
            print(f"  {str(h.get('id','')).ljust(10)} ERROR: {e}", file=sys.stderr)
            continue  # never fabricate a "0 matches" finding for an unreachable query
        threshold = int(h.get("threshold", 1))
        finding = count >= threshold
        if finding:
            findings += 1
        attack = ",".join(h.get("attack", []) or [])
        print(f"  {str(h.get('id','')).ljust(10)} {attack.ljust(12)} {count:>7}  "
              f"{'YES' if finding else '-'}  {h.get('title','')[:40]}")
        doc = {"@timestamp": now, "hunt": {"id": h.get("id"), "title": h.get("title"),
               "status": h.get("status", "active")}, "attack": h.get("attack", []),
               "data_source": h.get("data_source"), "match_count": count,
               "threshold": threshold, "finding": finding}
        # Fall back to the filename stem if a hunt has no id — otherwise every
        # id-less hunt would share the literal string "None" and collide onto
        # the same per-day doc as each other.
        hunt_key = h.get("id") or path.stem
        doc_id = f"{hunt_key}:{day_bucket}"
        bulk.append(json.dumps({"index": {"_index": "soc-hunts", "_id": doc_id}}))
        bulk.append(json.dumps(doc))
    index_failed = False
    if bulk:
        try:
            SESSION.post(f"{ES_URL}/_bulk", verify=ES_VERIFY,
                          headers={"Content-Type": "application/x-ndjson"},
                          data="\n".join(bulk) + "\n", timeout=20)
            print(f"  -> indexed {len(bulk) // 2} hunt results to soc-hunts ({findings} findings)")
        except Exception as e:
            index_failed = True
            print(f"  -> ES index failed: {e}", file=sys.stderr)
    if index_failed:
        sys.exit(3)
    if hunt_errors:
        print(f"  -> {hunt_errors}/{len(hunts)} hunt(s) failed to query — see stderr", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

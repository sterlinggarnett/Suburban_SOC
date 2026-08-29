#!/usr/bin/env python3
"""
verify_detections.py — Issue #22 verifier.

Queries Elasticsearch for the three expected detections from the anomaly
simulation suite and prints a pass/fail summary. Exits non-zero if any
expected detection is missing within the lookback window.

SCOPE (audit P2-22): these checks confirm the detection SIGNAL is present and
indexed — the Zeek `Scan::Port_Scan` notice, the SSH brute-force *cadence*
(5+ sessions from one source; Zeek's per-conn auth_success inference is
unreliable over loopback, see the SSH check), and the malware file MIME type.
They do NOT assert that the Elastic detection engine produced an alert. The
end-to-end detection->SOAR loop (alert fires -> agent drafts a response) is
validated separately by sim_intel_match.sh, which checks the agent's /pending
count grows. Treat a pass here as "the detectable signal reached the SIEM,"
not "an alert/quarantine fired."

Usage:
    source .env && python3 verify_detections.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any

from elasticsearch import Elasticsearch
from elastic_transport import TransportError


@dataclass
class Check:
    name: str
    query: dict[str, Any]
    min_hits: int = 1
    # If set, pass when a single bucket of this term field has >= min_hits docs
    # (e.g. "5+ sessions from one source"), instead of a flat document count.
    agg_field: str | None = None


def build_checks(lookback_min: int) -> list[Check]:
    time_filter = {"range": {"@timestamp": {"gte": f"now-{lookback_min}m"}}}
    return [
        Check(
            name="Port scan  (Scan::Port_Scan in zeek.notice)",
            query={
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "zeek.notice"}},
                        {"match_phrase": {"note": "Scan::Port_Scan"}},
                    ],
                    "filter": time_filter,
                }
            },
        ),
        Check(
            # Volume-based: 5+ SSH sessions from one source in the window. Zeek's
            # per-connection auth_success inference is unreliable over loopback
            # (large-MTU, unsegmented packets defeat its packet-size heuristic, so
            # auth_attempts stays 0), so we key on the brute-force *cadence* — the
            # same signal Zeek's own detect-bruteforcing policy uses.
            name="SSH brute force  (5+ zeek.ssh sessions from one source)",
            min_hits=5,
            agg_field="source.ip",
            query={
                "bool": {
                    "must": [{"match": {"event.dataset": "zeek.ssh"}}],
                    "filter": time_filter,
                }
            },
        ),
        Check(
            # #383/#413: telemetry-only check — application/zip is not in
            # net_zeek_executable_download.yml's mime_type list, so a pass
            # here confirms Zeek's file-typing pipeline, not that T1105 rule.
            name="Malware download telemetry (application/zip in zeek.files, NOT a T1105 rule hit)",
            query={
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "zeek.files"}},
                        {"match_phrase": {"mime_type": "application/zip"}},
                    ],
                    "filter": time_filter,
                }
            },
        ),
    ]


def main() -> int:
    # Security is enabled (WS0.1): default to HTTPS + auth. ES_PASS falls back to
    # ELASTIC_PASSWORD so `source ../../scripts/setup/.env` just works. ES_CA points
    # at an exported ca.crt for strict TLS.
    es_url = os.environ.get("ES_URL", "https://localhost:9200")
    index = os.environ.get("ES_INDEX", "logstash-security-*")
    lookback = int(os.environ.get("LOOKBACK_MIN", "10"))
    user = os.environ.get("ES_USER", "elastic") or None
    password = os.environ.get("ES_PASS") or os.environ.get("ELASTIC_PASSWORD") or None
    ca = os.environ.get("ES_CA", "/certs/ca/ca.crt")
    insecure = os.environ.get("ES_INSECURE", "false").lower() == "true"

    kwargs: dict[str, Any] = {"hosts": [es_url], "retry_on_timeout": True, "max_retries": 3}
    if user and password:
        kwargs["basic_auth"] = (user, password)
    if es_url.startswith("https"):
        # FAIL CLOSED (audit #166 / NIST SC-8): a missing/unreadable CA no
        # longer silently skips verification — set ES_INSECURE=true to
        # explicitly opt out (lab only), mirroring es_common.sh's pattern.
        if ca and os.path.isfile(ca):
            kwargs["ca_certs"] = ca
        elif insecure:
            print(f"[!] ES_INSECURE=true and no readable CA at {ca} — TLS "
                  f"verification DISABLED (lab only).", file=sys.stderr)
            kwargs["verify_certs"] = False
        else:
            print(f"[!] ERROR: no readable CA at ES_CA={ca} — refusing to skip "
                  f"TLS verification. Set ES_CA or ES_INSECURE=true (lab only).",
                  file=sys.stderr)
            return 2

    es = Elasticsearch(**kwargs)

    print(f"[*] Elasticsearch: {es_url}")
    print(f"[*] Index pattern: {index}")
    print(f"[*] Lookback:      now-{lookback}m\n")

    failures = 0
    for check in build_checks(lookback):
        try:
            if check.agg_field:
                # Bucket by the term field; "hits" = the largest single bucket,
                # i.e. the most sessions attributable to one source.
                resp = es.search(
                    index=index,
                    size=0,
                    query=check.query,
                    aggs={"by_src": {"terms": {"field": check.agg_field, "size": 10}}},
                )
                buckets = resp["aggregations"]["by_src"]["buckets"]
                hits = max((b["doc_count"] for b in buckets), default=0)
            else:
                resp = es.count(index=index, query=check.query)
                hits = resp.get("count", 0)
        except TransportError as exc:
            print(f"  [ERR ] {check.name} — Elasticsearch unreachable: {exc}")
            return 2
        ok = hits >= check.min_hits
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {check.name} — hits={hits} (need >= {check.min_hits})")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"[-] {failures} detection(s) missing. Re-run sims or widen LOOKBACK_MIN.")
        return 1
    print("[+] All expected detections present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

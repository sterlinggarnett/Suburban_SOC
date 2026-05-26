#!/usr/bin/env python3
"""
verify_detections.py — Issue #22 verifier.

Queries Elasticsearch for the three expected detections from the anomaly
simulation suite and prints a pass/fail summary. Exits non-zero if any
expected detection is missing within the lookback window.

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
            name="SSH brute force  (5+ auth_success=F in zeek.ssh)",
            min_hits=5,
            query={
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "zeek.ssh"}},
                        {"match": {"auth_success": False}},
                    ],
                    "filter": time_filter,
                }
            },
        ),
        Check(
            name="Malware download (application/zip in zeek.files)",
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
    es_url = os.environ.get("ES_URL", "http://localhost:9200")
    index = os.environ.get("ES_INDEX", "logstash-security-*")
    lookback = int(os.environ.get("LOOKBACK_MIN", "10"))
    user = os.environ.get("ES_USER") or None
    password = os.environ.get("ES_PASS") or None

    kwargs: dict[str, Any] = {"hosts": [es_url]}
    if user and password:
        kwargs["basic_auth"] = (user, password)

    es = Elasticsearch(**kwargs)

    print(f"[*] Elasticsearch: {es_url}")
    print(f"[*] Index pattern: {index}")
    print(f"[*] Lookback:      now-{lookback}m\n")

    failures = 0
    for check in build_checks(lookback):
        try:
            resp = es.count(index=index, query=check.query)
        except TransportError as exc:
            print(f"  [ERR ] {check.name} — Elasticsearch unreachable: {exc}")
            return 2
        hits = resp.get("count", 0)
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

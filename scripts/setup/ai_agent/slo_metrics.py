#!/usr/bin/env python3
"""
slo_metrics.py — WS2.4: self-measuring SOC metrics & SLOs.

Computes the SOC's own performance metrics against defined targets, indexes them
to the `soc-slo-metrics` index (for the SLO dashboard), and raises an ntfy alert
if any SLO is breached. Run on a schedule (cron) alongside refresh_intel.sh.

  MTTD  (mean time to detect)      <= 30 min   — detection-engine alerts
  MTTR  (automated response)       <= 5  min   — soar-actions response.latency_seconds
  Detection coverage               >= 10 tech  — docs/detections/attack-coverage.json
  False-positive rate              <= 10 %     — Kibana cases disposition tags
  Ingest lag                       <= 300 s    — newest logstash-security event age
  Parse-error (drop) rate          <= 1  %     — pipeline.error over the window
  Raw alert volume                 measured    — Zeek notices + Sigma/Elastic rule
                                                  hits over the window (#216), no
                                                  target — a before/after baseline
                                                  for detection tuning, not a target
  Stuck approval claims            == 0        — /approve claims older than 30 min
                                                  with no EXECUTED resolution (#247)
  Orphaned claims                  == 0        — CLAIMED claims older than 10 min
                                                  with no paired phase checkpoint,
                                                  the claim-squatting signature (#257)
  Vanished claims                  == 0        — a CLAIMED claim doc from the
                                                  prior sample that no longer
                                                  exists at all (deleted, not
                                                  resolved) — the tamper
                                                  signature #357's now-live
                                                  delete-capable credential
                                                  makes possible (#361)
  Field truncation count           measured    — pipeline.truncated over the window
                                                  (#252), no target — baseline for
                                                  whether ScriptBlockText's 32766
                                                  ignore_above ceiling (#263) is ever hit
  Field byte-clamp count           measured    — pipeline.byte_clamped over the window
                                                  (#263), no target — a nonzero count means
                                                  multi-byte content had to be defensively
                                                  clamped to avoid a Lucene immense-term
                                                  whole-document rejection
  Oversized DNS answer count       measured    — pipeline.oversized_dns_answer over the
                                                  window (#352), no target — a nonzero count
                                                  means a dns.answers value over 8191 chars
                                                  was silently dropped from the index,
                                                  possibly evading net_zeek_dns_txt_
                                                  answer_abuse.yml's length-heuristic rule
  Zeek path-grok nomatch count     == 0        — pipeline.zeek_path_nomatch over the
                                                  window (#349) — a nonzero count means a
                                                  zeek-shaped document failed Category 0's
                                                  filename grok, got no event.dataset, and
                                                  is invisible to every zeek Sigma rule
                                                  (#291's event.dataset:zeek.<service>
                                                  scoping) — a real detection blackout,
                                                  not a data-quality baseline
  Capture-loss max %               <= 5   %    — max Zeek capture_loss.log percent_lost
                                                  over its own SLO_CAPTURE_LOSS_WINDOW (#288,
                                                  default now-1h — NOT the shared WINDOW
                                                  below, so one spike self-clears instead of
                                                  breaching for a full 7-day window) — a
                                                  resource-pressure/packet-drop guard for the
                                                  real capture path, which has no load shedding
  Intel feed stale heartbeats       >= 1        — status:ok docs in threat-intel-meta
                                                  within the last 8h (#358) — replaces
                                                  rules/elastic_watcher/intel_feed_stale.json,
                                                  RETIRED because Watcher itself is not
                                                  licensed on this stack (Basic license;
                                                  every Watcher API call 403s) and had
                                                  never actually fired
  Intel indicator count drop %     <= 50  %    — how far threat-intel-indicators' real
                                                  _count sits below the latest heartbeat's
                                                  own indicator_count (#358) — catches a
                                                  malicious/errant wipe via the delete-
                                                  capable threat_intel_compactor credential
                                                  that the two metrics above wouldn't see
                                                  (they read the WRITER's belief, not the
                                                  index's actual contents)
  Broker response tampering count  == 0        — soc-audit-* docs with event.action
                                                  broker_response_signature_invalid or
                                                  broker_response_request_id_mismatch
                                                  and event.outcome:unknown (#309) — the
                                                  "Watcher, or equivalent" detection
                                                  content for #277's two new audit
                                                  actions, on the same infrastructure
                                                  intel_feed_stale_heartbeats already
                                                  proved out (a real Watcher isn't usable
                                                  on this stack's Basic license — #358).
                                                  Near-zero-false-positive: it only fires
                                                  when the containment channel is
                                                  actively being tampered with.

Pure stdlib (requests). Env (auto-loaded from scripts/setup/.env):
  ES_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, KIBANA_URL, NTFY_TOPIC.
Targets overridable via SLO_<NAME> env (e.g. SLO_MTTD_MAX_MIN=20).
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

# Shared connection-pooled, retrying Session (issue #170) + .env line parser
# (#259) — sibling module, no installable package here yet (tracked
# separately), so sys.path like the tests do. Moved before the .env-loading
# block below (rather than staying next to es_client's own use further down)
# specifically so env_loader is importable there.
sys.path.insert(0, str(HERE.parent / "lib"))
import env_loader  # noqa: E402
import es_client  # noqa: E402

ENV = REPO / "scripts" / "setup" / ".env"
env_loader.load_env_file(ENV)

ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS") or os.environ.get("ELASTIC_PASSWORD", "")
KIBANA_URL = os.environ.get("KIBANA_URL", "https://localhost:5601")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
WINDOW = os.environ.get("SLO_WINDOW", "now-7d")

TARGETS = {
    "mttd_minutes":        float(os.environ.get("SLO_MTTD_MAX_MIN", "30")),
    "mttr_minutes":        float(os.environ.get("SLO_MTTR_MAX_MIN", "5")),
    "coverage_techniques": float(os.environ.get("SLO_COVERAGE_MIN", "10")),
    "false_positive_pct":  float(os.environ.get("SLO_FP_MAX_PCT", "10")),
    "ingest_lag_seconds":  float(os.environ.get("SLO_INGEST_LAG_MAX_S", "300")),
    "parse_error_pct":     float(os.environ.get("SLO_PARSE_ERR_MAX_PCT", "1")),
    "audit_write_failures": float(os.environ.get("SLO_AUDIT_WRITE_FAIL_MAX", "2")),
    # #247: any claim still open past SLO_STUCK_CLAIM_MAX_MIN (the AGE window,
    # read inside metric_stuck_approval_claims() below — not this one, which is
    # the COUNT threshold) is a stranded alert, not a routine condition —
    # target is 0.
    "stuck_approval_claims": float(os.environ.get("SLO_STUCK_CLAIM_MAX", "0")),
    # #257: any CLAIMED .claim doc with no corresponding phase checkpoint,
    # past SLO_ORPHANED_CLAIM_MAX_MIN (the AGE window, read inside
    # metric_orphaned_claims() below), is the cheap detectable signature of
    # claim-squatting (pre-creating a .claim doc for a predictable alert_id
    # before the real alert intake ever runs, so a legitimate /approve 409s
    # "already claimed" and containment silently never happens) — target 0.
    "orphaned_claims": float(os.environ.get("SLO_ORPHANED_CLAIM_MAX", "0")),
    # #361: checkpoints.py never deletes a `.claim` doc through its own API —
    # only ever transitions its `phase` field in place — so ANY vanished
    # CLAIMED doc is itself the anomaly; target is 0, same as the two
    # claim-integrity metrics above.
    "vanished_claims": float(os.environ.get("SLO_VANISHED_CLAIM_MAX", "0")),
    # #349: a zeek-shaped document that fails Category 0's filename grok
    # gets no event.dataset and is invisible to every zeek Sigma rule
    # (#291) - a detection blackout, not a data-quality baseline. Target
    # is 0, same as the three claim-integrity metrics above.
    "zeek_path_nomatch_count": float(os.environ.get("SLO_ZEEK_PATH_NOMATCH_MAX", "0")),
    # #288: no target was calibrated against real traffic in this environment
    # (same caveat as field_truncation_count/field_byte_clamp_count below) —
    # 5% is a conservative, overridable starting point, not an
    # empirically-derived number.
    "capture_loss_max_pct": float(os.environ.get("SLO_CAPTURE_LOSS_MAX_PCT", "5")),
    # #358: same 8h window rules/elastic_watcher/intel_feed_stale.json (now
    # retired) used — refresh_intel.sh runs every 6h. security-auditor
    # correction: 8h tolerates ~2h of scheduling jitter around a SUCCESSFUL
    # run, not a fully MISSED one — a single missed run at T+6h leaves this
    # window empty from T+8h until the next success at T+12h, a real ~4h
    # breach window, which is the intended/correct behavior (inherited
    # verbatim from the retired Watcher's own identical window and
    # comment), just not what "tolerates one missed run" implied. >=1 (not
    # ==0-style): a HEALTHY run is what satisfies this.
    "intel_feed_stale_heartbeats": float(os.environ.get("SLO_INTEL_HEARTBEAT_MIN", "1")),
    # #358: reuses compact_threat_intel.py's own BLAST_RADIUS_FRACTION=0.5
    # precedent for "how much shrink is suspicious" — see
    # metric_intel_indicator_count_drop_pct()'s docstring for why actual
    # count normally sits AT OR ABOVE a single heartbeat's indicator_count,
    # making a meaningful shortfall the real anomaly signal.
    "intel_indicator_count_drop_pct": float(os.environ.get("SLO_INTEL_DROP_MAX_PCT", "50")),
    # #309: near-zero-false-positive — a nonzero count means the containment
    # channel between the agent and the broker is actively being tampered
    # with (forged/replayed response), not routine noise. Target is 0, same
    # as the claim-integrity metrics above.
    "broker_response_tampering_count": float(os.environ.get("SLO_BROKER_TAMPER_MAX", "0")),
}
# Comparator per metric: True = lower is better (value <= target).
LOWER_BETTER = {
    "mttd_minutes": True, "mttr_minutes": True, "coverage_techniques": False,
    "false_positive_pct": True, "ingest_lag_seconds": True, "parse_error_pct": True,
    "audit_write_failures": True, "stuck_approval_claims": True,
    "orphaned_claims": True, "vanished_claims": True, "capture_loss_max_pct": True,
    "intel_feed_stale_heartbeats": False, "intel_indicator_count_drop_pct": True,
    "zeek_path_nomatch_count": True, "broker_response_tampering_count": True,
}
# Fail closed: for these metrics an unmeasurable value (None) is itself a breach,
# not a benign "n/a". A dead/unreachable pipeline produces no fresh docs, so
# metric_ingest_lag_seconds() returns None — the single loudest failure must alarm,
# not register as silence. (WS2.4 observability gap: a total ingest outage was being
# scored breach=False because lag could not be read.)
BREACH_IF_NA = {"ingest_lag_seconds"}
# #216: measured but not target-checked. There's no "correct" alert volume to set
# a threshold against yet — that's what this metric exists to establish a baseline
# for (the before/after signal detection tuning needs to prove it reduced noise
# rather than just silencing it). Inventing an uncalibrated number here would be
# worse than no threshold at all. Still participates in the errors/exit-3 path
# below like every other metric — an unmeasurable value is never silently benign.
NO_TARGET = {"raw_alert_volume", "field_truncation_count", "field_byte_clamp_count",
             "oversized_dns_answer_count"}


# FAIL CLOSED (audit P1-2): verify TLS against the stack CA instead of verify=False.
# ES_CA defaults to the agent container's mounted CA; set it to your CA path for
# host/standalone runs, or to "" to verify against the system trust store. requests
# raises a clear error if the path is missing — we never silently skip verification.
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True

# Connection reuse + retry/backoff (issue #170) — same credentials serve both
# ES and Kibana today, so one session covers es() and kb() below.
SESSION = es_client.get_session(ES_USER, ES_PASS)


class MetricUnavailable(Exception):
    """Raised when a metric could not be measured because the ES/Kibana request
    failed (or, for metric_coverage, the local file couldn't be read) — distinct
    from a legitimate empty/zero result (audit #165 / NIST SI-11). A down or
    unreachable dependency must never be reported as a benign 'n/a'."""


def es(method, path, body=None):
    return SESSION.request(
        method, f"{ES_URL}{path}", verify=ES_VERIFY,
        headers={"Content-Type": "application/json"},
        data=json.dumps(body) if body is not None else None, timeout=15)


def kb(path):
    # #177: Kibana now serves TLS (SC-8) on the same stack CA as ES — reuse ES_VERIFY
    # rather than introduce a second CA-path env var for an identical trust root.
    return SESSION.get(f"{KIBANA_URL}{path}", verify=ES_VERIFY,
                        headers={"kbn-xsrf": "true"}, timeout=15)


_SLO_METRICS_READER_ROLE_PATH = (
    REPO / "configs" / "elasticsearch" / "roles" / "slo_metrics_reader.json"
)


def _slo_metrics_reader_read_patterns():
    """Every index pattern configs/elasticsearch/roles/slo_metrics_reader.json
    grants 'read' on, derived from that authoritative role file itself rather
    than a hardcoded snapshot — so a pattern added to the role in the future
    (as #358 already did twice, after #305 was originally filed against a
    smaller list) is covered by the self-check below automatically, with no
    separate edit needed here."""
    try:
        role = json.loads(_SLO_METRICS_READER_ROLE_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        raise MetricUnavailable(f"slo_metrics_reader.json unreadable: {e}") from e
    patterns = []
    for entry in role.get("indices", []):
        if "read" in entry.get("privileges", []):
            patterns.extend(entry["names"])
    return patterns


def _check_slo_metrics_reader_privileges():
    """#305: a one-time, live-cluster self-check that the slo_metrics_reader
    credential this script actually runs as still holds 'read' on every
    index pattern it depends on. The static SloMetricsReaderRoleGrantTests
    (tests/ai_agent/test_slo_metrics.py) only guards the COMMITTED role
    file — it has no visibility into a live cluster's ACTUALLY APPLIED role,
    which a direct edit against a running cluster or a partially-failed
    deploy could still drift from.

    Elasticsearch's own POST /_security/user/_has_privileges is callable by
    any authenticated user to check their OWN granted privileges (no extra
    permission needed) and distinguishes "authorized, zero matching docs"
    from "not authorized" — unlike a bare _count(), which returns the
    identical 404 for both (#275's live-verified finding, documented on
    metric_audit_write_failures() above).

    One request per run, covering every pattern at once (not one call per
    metric) — raises MetricUnavailable, the same loud-failure signal every
    other unmeasurable metric in this file uses, rather than letting a
    revoked grant masquerade as a healthy 0 anywhere else in this run.
    """
    patterns = _slo_metrics_reader_read_patterns()
    if not patterns:
        # Elasticsearch's behavior for "prove read on zero patterns" is not
        # verified in this environment (no live cluster available) — refuse
        # to silently treat an empty list as vacuously satisfied rather than
        # risk it being a no-op self-check.
        raise MetricUnavailable(
            "slo_metrics_reader.json grants no 'read' patterns at all — "
            "cannot run the privilege self-check"
        )
    body = {"index": [{"names": patterns, "privileges": ["read"]}]}
    try:
        r = es("POST", "/_security/user/_has_privileges", body)
    except Exception as e:
        raise MetricUnavailable(f"privilege self-check request failed: {e}")
    if r.status_code != 200:
        raise MetricUnavailable(
            f"privilege self-check returned HTTP {r.status_code}: {r.text[:300]}"
        )
    try:
        data = r.json()
    except ValueError as e:
        raise MetricUnavailable(f"privilege self-check returned a non-JSON response: {e}")
    if not data.get("has_all_requested", False):
        index_grants = data.get("index", {})
        missing = [p for p in patterns if not index_grants.get(p, {}).get("read", False)]
        raise MetricUnavailable(
            f"slo_metrics_reader is missing 'read' on: {missing or patterns} "
            f"(live cluster response: {data})"
        )


def _count(index, query, strict=False):
    """strict=True: allow_no_indices=false/ignore_unavailable=false, so a
    pattern resolving to zero indices raises instead of silently returning a
    healthy-looking 0 (#216) — for index patterns that should always exist in
    a working deployment (e.g. Kibana's own .alerts-security.alerts-*), not
    for patterns a fresh/idle tenant may legitimately not have written yet.
    """
    try:
        path = f"/{index}/_count"
        if strict:
            path += "?allow_no_indices=false&ignore_unavailable=false"
        r = es("POST", path, {"query": query})
        if r.status_code != 200:
            raise MetricUnavailable(f"{index} count returned HTTP {r.status_code}")
        return r.json().get("count", 0)
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"{index} count request failed: {e}") from e


def _cardinality(index, query, field):
    """Distinct-value count of `field` among docs matching `query` (#331) -
    a cardinality aggregation, not an exact count. Approximate once distinct
    values exceed Elasticsearch's default precision_threshold (3000) - a
    large spoofed flood (the scenario this signal exists for) can cross that
    easily, but the resulting error (~1-2%) still separates a few-source
    pattern from a many-thousand-source one, which is all this signal needs
    to do; no explicit threshold override is set."""
    try:
        r = es("POST", f"/{index}/_search",
               {"size": 0, "query": query,
                "aggs": {"distinct": {"cardinality": {"field": field}}}})
        if r.status_code != 200:
            raise MetricUnavailable(f"{index} cardinality({field}) search returned HTTP {r.status_code}")
        body = r.json()
        failed_shards = body.get("_shards", {}).get("failed", 0)
        if failed_shards:
            # A 200 with failed shards (e.g. `field` mapped incompatibly with
            # cardinality on one shard - a legacy/pre-migration index) silently
            # UNDERCOUNTS distinct sources, biasing this signal toward "looks
            # like a few real sources" - must surface as an error, not a
            # quietly-partial value.
            raise MetricUnavailable(
                f"{index} cardinality({field}) search had {failed_shards} failed shard(s)")
        return body.get("aggregations", {}).get("distinct", {}).get("value", 0)
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"{index} cardinality({field}) request failed: {e}") from e


def metric_mttd():
    """Mean detect latency (min): alert creation time minus the source event time."""
    body = {"size": 500, "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "kibana.alert.original_time", "kibana.alert.start"],
            "query": {"range": {"@timestamp": {"gte": WINDOW}}}}
    try:
        r = es("POST", "/.alerts-security.alerts-*/_search", body)
        if r.status_code != 200:
            raise MetricUnavailable(f"mttd search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"mttd search failed: {e}") from e
    deltas = []
    for h in hits:
        s = h.get("_source", {})
        start = s.get("kibana.alert.start") or s.get("@timestamp")
        orig = s.get("kibana.alert.original_time") or s.get("@timestamp")
        try:
            a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
            b = datetime.fromisoformat(str(orig).replace("Z", "+00:00"))
            d = (a - b).total_seconds() / 60.0
            if d >= 0:
                deltas.append(d)
        except Exception:
            continue  # a single malformed hit is skipped — not a measurement error
    return round(sum(deltas) / len(deltas), 2) if deltas else None


def metric_mttr():
    """Mean automated response latency (min) from soar-actions.response.latency_seconds."""
    body = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": WINDOW}}},
        {"exists": {"field": "response.latency_seconds"}}]}},
        "aggs": {"avg_lat": {"avg": {"field": "response.latency_seconds"}}}}
    try:
        r = es("POST", "/soar-actions-*/_search", body)
        if r.status_code != 200:
            raise MetricUnavailable(f"mttr search returned HTTP {r.status_code}")
        v = r.json().get("aggregations", {}).get("avg_lat", {}).get("value")
        return round(v / 60.0, 3) if v is not None else None
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"mttr search failed: {e}") from e


def metric_coverage():
    p = REPO / "docs" / "detections" / "attack-coverage.json"
    try:
        return float(len(json.loads(p.read_text(encoding="utf-8")).get("techniques", [])))
    except Exception as e:
        raise MetricUnavailable(f"attack-coverage.json unreadable: {e}") from e


def metric_false_positive_pct():
    """% of closed cases dispositioned false_positive."""
    try:
        total = kb("/api/cases/_find?perPage=1&status=closed").json().get("total", 0)
        fp = kb("/api/cases/_find?perPage=1&status=closed&tags=disposition:false_positive"
                ).json().get("total", 0)
        return round(100.0 * fp / total, 2) if total else 0.0
    except Exception as e:
        raise MetricUnavailable(f"cases query failed: {e}") from e


def metric_ingest_lag_seconds():
    body = {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp"]}
    try:
        hits = es("POST", "/logstash-security-*/_search", body).json().get("hits", {}).get("hits", [])
        if not hits:
            return None
        newest = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
        return round((datetime.now(timezone.utc) - newest).total_seconds(), 1)
    except Exception as e:
        raise MetricUnavailable(f"ingest-lag search failed: {e}") from e


def metric_parse_error_pct():
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    total = _count("logstash-security-*", win)
    errs = _count("logstash-security-*", {"bool": {"filter": [win, {"term": {"pipeline.error": "true"}}]}})
    return round(100.0 * errs / total, 3) if total else 0.0


def metric_audit_write_failures():
    """Count of write_audit() failures in the window (#184).

    Every doc in soc-agent-health-* IS a failure marker — nothing else writes
    there — so a windowed count is the metric, no extra filter beyond the
    time range.

    #275: the slo_metrics_reader role never granted this pattern, live-
    verified (native security-enabled Elasticsearch, not just reading the
    role file) that the real failure mode is NOT the loud 403/exit-3 the
    issue assumed: a wildcard _count (default, non-strict params) against a
    pattern the caller has ZERO authorized indices under returns HTTP
    200/count:0 — byte-for-byte identical to the healthy "no failures ever
    written" response (_shards.total is 0 in both cases too, confirmed not
    to be a usable distinguishing signal). This metric was silently
    reporting false-healthy on every run instead of erroring.

    strict=True (the "raise instead of silently returning 0" escape hatch
    _count() already has) is deliberately NOT used here even after this
    finding — separately live-verified (both as the restricted slo_metrics
    user AND as a full-access superuser against a genuinely never-created
    index) that strict=True's allow_no_indices=false/ignore_unavailable=false
    turns BOTH the unauthorized case and the legitimately-healthy
    "index never created, no failures yet" case into the IDENTICAL HTTP 404
    index_not_found_exception — so switching to strict=True would not fix
    the ambiguity, it would just convert a silent false-healthy 0 into a
    loud, spurious MetricUnavailable/exit-3 on every fresh or genuinely-quiet
    deployment, which is worse (permanent, unactionable alert noise on the
    common case) than the bug this issue fixes. This function itself has no
    way to detect a future regression of the role grant at runtime — see
    tests/ai_agent/test_slo_metrics.py's static role-file assertion, which is
    the actual regression guard for this specific bug today. A live self-check
    (e.g. Elasticsearch's own POST /_security/user/_has_privileges, which can
    distinguish "authorized, zero docs" from "not authorized" the way _count()
    cannot) could generalize this across every pattern slo_metrics_reader
    depends on, not just this one — untested here, filed as a follow-up
    rather than added to this fix.
    """
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    return _count("soc-agent-health-*", win)


def metric_broker_response_tampering():
    """Count of on-path-tampering indicators against the broker containment
    channel in the window (#309, follow-up from #277's round-4 security-
    auditor review).

    agent.py's dispatch_block_via_broker() writes `event.outcome="unknown"`
    audit rows to soc-audit-{tenant} under exactly two action names when it
    cannot trust a /webhook/dispatch response: `broker_response_signature_
    invalid` (HMAC verification failed — possible on-path tampering) and
    `broker_response_request_id_mismatch` (a genuinely broker-signed response
    that doesn't answer THIS call — possible replay of a captured earlier
    one). Nothing else in this pipeline ever writes either action name, so a
    plain windowed count is exact — same shape as metric_audit_write_
    failures() above, just filtered to these two action values instead of
    covering the whole index.

    This is the "Watcher, or equivalent" detection content #309 asks for:
    Elastic Watcher itself isn't usable on this stack (Basic license — every
    Watcher API call 403s, live-confirmed for #358's own retired Watcher, see
    metric_intel_feed_stale_heartbeats()'s docstring) — this metric reuses
    the same already-proven-out replacement (a scheduled query + ntfy alert +
    soc-slo-metrics history) rather than reviving that dead end.

    Target is 0: both outcomes only fire when the agent could NOT confirm a
    dispatch's authenticity, which #277's own threat model treats as active
    tampering, not a routine/expected condition — see agent.py's own
    dispatch_block_via_broker() docstring for why every other non-200/
    unverified case there is a CONFIRMED (not merely suspected) non-dispatch
    or a genuinely ambiguous outcome, neither of which uses these two action
    names.
    """
    # soc-audit-* has no explicit index template (unlike agent-checkpoints-*,
    # which maps `phase` as `keyword` — see that template's own mappings) —
    # write_audit()'s dotted `event.action`/`event.outcome` keys land under
    # Elasticsearch's default dynamic mapping (`text` + an automatic
    # `.keyword` sub-field, `ignore_above:256`). Querying the bare field
    # names would term-match against the ANALYZED text, not an exact value —
    # `.keyword` is the safe, no-template-change idiom for an exact match here.
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    query = {"bool": {"filter": [
        win,
        {"terms": {"event.action.keyword": ["broker_response_signature_invalid",
                                             "broker_response_request_id_mismatch"]}},
        {"term": {"event.outcome.keyword": "unknown"}},
    ]}}
    return _count("soc-audit-*", query)


def metric_stuck_approval_claims():
    """Count of approval claims stuck with no resolution (#247).

    checkpoints.claim_approval() writes a `{alert_id}.claim` marker doc
    (`phase: "CLAIMED"`) to win the at-most-once execution race. A normal run
    resolves it within seconds: agent.execute_approved() transitions that SAME
    doc to `phase: "RESOLVED"` (confirmed success) or `phase: "RELEASED"`
    (confirmed failure, freed for retry) — see checkpoints.resolve_claim() /
    release_claim(). Only a genuinely stuck claim — most likely a process
    crash between the claim succeeding and either resolution running, or an
    execution whose outcome was UNKNOWN (agent.IsolationOutcomeUnknown; #247
    deliberately never auto-releases those, since a retry could double-
    dispatch) — is left at `phase: "CLAIMED"` past SLO_STUCK_CLAIM_MAX_MIN.
    No other doc in this index ever uses "CLAIMED", so a plain count is exact
    and requires no join against the paired checkpoint doc.
    """
    # A malformed override (e.g. "30m" instead of "30") must degrade to this ONE
    # metric being unmeasurable, not take down the whole run — main()'s per-metric
    # loop only catches MetricUnavailable, so float()'s ValueError needs converting
    # here rather than being allowed to escape uncaught (would silence every other
    # metric's ntfy alerting too, including ingest-lag's — security-auditor review).
    try:
        cutoff_min = float(os.environ.get("SLO_STUCK_CLAIM_MAX_MIN", "30"))
    except ValueError as e:
        raise MetricUnavailable(f"invalid SLO_STUCK_CLAIM_MAX_MIN: {e}") from e
    query = {"bool": {"filter": [
        {"term": {"phase": "CLAIMED"}},
        {"range": {"@timestamp": {"lte": f"now-{cutoff_min:g}m"}}},
    ]}}
    return _count("agent-checkpoints-*", query)


def metric_orphaned_claims():
    """Count of CLAIMED .claim documents with no corresponding phase
    checkpoint document (#257, follow-up from #245's security review).

    checkpoints.claim_approval() wins a `{alert_id}.claim` doc via ES
    op_type=create — atomic against a CONCURRENT claim, but not against one
    PRE-CREATED before the real alert ever arrives. alert_id is a
    deterministic sha256(tenant|ip|mac|severity|5m_bucket)
    (generate_dedup_key), so an attacker who can predict an imminent
    alert's inputs can precompute its alert_id and race to claim it first —
    "claim squatting". A legitimate analyst's later /approve then 409s
    "already claimed" against checkpoints.py's own at-most-once gate, and
    isolation silently never happens, with no error anywhere an operator
    would normally look.

    Every LEGITIMATE claim is created by execute_approved() only after the
    real alert's own phase checkpoint (bare `{alert_id}` doc, written during
    intake — see agent.py's run()) already exists — so a claim doc with NO
    paired phase doc, past a short grace window (to tolerate ordinary write
    ordering/propagation, not a real detection gap), is exactly the
    squatting signature: nothing else in this pipeline produces that shape.

    ES has no native cross-document join, so this is a two-step check:
    fetch the (typically small — genuinely open claims are rare) set of
    CLAIMED docs past the grace window, then batch-check each one's paired
    phase doc via a single _mget call rather than one round-trip per claim.

    security-auditor review: the join key MUST come from the search hit's
    own `_id`/`_index` metadata, never from `_source`. checkpoints.py writes
    both the claim doc (`_index=agent-checkpoints-{tenant}`,
    `_id={alert_id}.claim` — see claim_approval()) and its paired phase doc
    (`_index=agent-checkpoints-{tenant}`, `_id={alert_id}` — see
    write_checkpoint()) into the SAME index, so stripping the literal
    ".claim" suffix off a claim hit's own `_id` and looking that up in that
    SAME `_index` reconstructs the pairing with zero trust in document
    content. `_source` is exactly the field an attacker holding (or having
    compromised) the agent_checkpoints credential controls outright — an
    earlier version of this function read `alert_id`/`tenant` from
    `_source`, which both (a) let a crafted CLAIMED doc claim to pair with
    an unrelated/self-referential target and evade detection entirely, and
    (b) could crash the whole metrics run on a malformed shape (e.g.
    `tenant: null`) — `dynamic: "strict"` accepts either without complaint,
    and main()'s per-metric loop only catches MetricUnavailable, not
    AttributeError.
    """
    try:
        cutoff_min = float(os.environ.get("SLO_ORPHANED_CLAIM_MAX_MIN", "10"))
    except ValueError as e:
        raise MetricUnavailable(f"invalid SLO_ORPHANED_CLAIM_MAX_MIN: {e}") from e

    query = {"bool": {"filter": [
        {"term": {"phase": "CLAIMED"}},
        {"range": {"@timestamp": {"lte": f"now-{cutoff_min:g}m"}}},
    ]}}
    try:
        # No _source needed — only hit metadata (_id/_index) is trusted (see
        # docstring). sort=@timestamp asc so a 200-cap truncation (below)
        # drops the newest, least-suspicious claims first, not arbitrarily.
        r = es("POST", "/agent-checkpoints-*/_search",
               {"query": query, "size": 200, "_source": False,
                # unmapped_type: an agent-checkpoints-* index missing the
                # @timestamp mapping (should never happen once the template
                # applies, but sort — unlike a query filter — has no
                # tolerant default) would otherwise 400 the WHOLE search
                # rather than just skip that index (security-auditor catch).
                "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}]})
        if r.status_code != 200:
            raise MetricUnavailable(f"orphaned-claims search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"orphaned-claims search failed: {e}") from e

    # size=200-capped, same reasoning/precedent as checkpoints.py's
    # search_stuck_claims() (#276) — genuinely open claims should be rare
    # under normal operation, so this is a soft cap, not a silent-truncation
    # risk in practice; a deployment hitting it has a bigger problem than
    # this metric alone can surface.
    docs_to_check = []
    for h in hits:
        doc_id, index = h.get("_id", ""), h.get("_index", "")
        # Every legitimate CLAIMED doc is a ".claim" doc (see docstring) —
        # anything else in this shape is itself anomalous, not something to
        # silently fold into the pairing check. base_id also excludes the
        # degenerate _id==".claim" itself (security-auditor catch: an empty
        # base id would build an _mget target of _id="", which can 400 the
        # whole batch on some ES versions and turn "one crafted doc" into
        # "the entire orphaned-claims metric goes dark").
        base_id = doc_id[: -len(".claim")] if doc_id.endswith(".claim") else ""
        if index and base_id:
            docs_to_check.append({"_index": index, "_id": base_id})
    if not docs_to_check:
        return 0

    try:
        r = es("POST", "/_mget", {"docs": docs_to_check})
        if r.status_code != 200:
            raise MetricUnavailable(f"orphaned-claims mget returned HTTP {r.status_code}")
        results = r.json().get("docs", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"orphaned-claims mget failed: {e}") from e

    return sum(1 for d in results if not d.get("found"))


# #361: how far back metric_vanished_claims() will trust a persisted
# claimed_snapshot as a comparison baseline. Wide enough to tolerate a
# missed run or a stretch of host downtime (slo-metrics.timer's
# Persistent=true catches up after a reboot); far short of
# compact_agent_checkpoints.py's DEFAULT_RETENTION_DAYS=90 for RELEASED
# claims, so a stale baseline can never reach into a doc the compactor was
# always going to delete anyway (see metric_vanished_claims()'s docstring).
SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN = float(
    os.environ.get("SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN", str(2 * 24 * 60)))


def _claimed_snapshot(size=200):
    """Hit metadata for every claim doc whose disappearance would itself be
    anomalous — the baseline `metric_vanished_claims()` diffs the NEXT run
    against (#361). Returns `index`/`id` (deliberately NOT `_index`/`_id` —
    see the note below), never `_source`.

    Covers TWO phases, not just CLAIMED (tester-debugger live-verification
    finding during #361's own review): `claim_approval()`'s `op_type=create`
    reclaim path (checkpoints.py) only checks whether the `.claim` doc
    EXISTS, not what phase it was in before — `_transition_claim()`'s
    conditional-PUT reclaim only fires on a 409 (doc still there), so it
    only ever guards a doc that's still present. Deleting a doc outright
    bypasses that guard entirely regardless of its last phase, exactly like
    deleting a CLAIMED one does.
      - CLAIMED: the case #361 was filed for — a live, in-flight claim.
      - RESOLVED: `resolve_claim()`'s own docstring is explicit that a
        RESOLVED doc must "always lose the race" against a fresh claim —
        deleting one instead of merely reading it lets `op_type=create`
        grant a brand-new claim for an alert that ALREADY, confirmedly,
        successfully executed. That's a real second dispatch of a
        completed containment action, not just a reopened approval gate —
        arguably worse than the CLAIMED case, and this metric had zero
        visibility into it before this addition (a doc leaves every future
        snapshot the instant it stops being CLAIMED).
      - RELEASED is DELIBERATELY excluded, unlike the two above:
        `compact_agent_checkpoints.py`'s own `TERMINAL_CLAIM_PHASES`
        already deletes RELEASED docs routinely (`DEFAULT_RETENTION_DAYS`
        =90) — its docstring's own reasoning is that this is safe because
        `claim_approval()`'s conditional-PUT reclaim path already treats a
        RELEASED doc as freely re-winnable BY DESIGN, so an early/malicious
        deletion "changes nothing that function wouldn't already do."
        Tracking RELEASED here would just reproduce, for RELEASED docs
        specifically, the exact stale-baseline false-positive class this
        file's freshness window already exists to avoid for CLAIMED — for
        zero actual security benefit, since RELEASED's own reclaim
        semantics don't distinguish "doc deleted" from "doc still there."

    Two INDEPENDENT, independently-sorted, independently-capped searches,
    not one combined query — RESOLVED and CLAIMED have opposite growth
    profiles, so a shared sort order would silently starve one of them:
      - CLAIMED: oldest-first (same precedent as `metric_orphaned_claims()`)
        — a claim resolves within seconds under normal operation, so a
        long-open one is the more suspicious one to keep visible under the
        cap.
      - RESOLVED: newest-first. Unlike CLAIMED, RESOLVED docs are NEVER
        intentionally deleted (see above) — this population only grows,
        without bound, for the system's entire operational lifetime.
        Sorting it oldest-first the way CLAIMED is sorted would mean the
        cap fills with ancient resolutions almost immediately and never
        makes room for a newly-resolved doc again — silently blinding this
        metric to the operationally relevant window (an attacker erasing a
        JUST-resolved claim before anyone double-checks it) in favor of
        protecting incidents closed months or years ago.

    Key naming: `_index`/`_id` are Elasticsearch metadata-field names: some
    versions reject (or ambiguously handle) a user document containing a
    nested object with sub-fields of those exact literal names. Persisting
    plain `index`/`id` instead sidesteps that entirely; `metric_vanished_
    claims()` maps them back to `_index`/`_id` only when building the real
    `_mget` request body.

    Deliberately a plain search, not folded into `metric_vanished_claims()`
    itself: this call captures THIS run's state for the NEXT run to compare
    against, not a value this run reports on its own.
    """
    def _search(phase, order):
        r = es("POST", "/agent-checkpoints-*/_search",
               {"query": {"bool": {"filter": [{"term": {"phase": phase}}]}},
                "size": size, "_source": False,
                "sort": [{"@timestamp": {"order": order, "unmapped_type": "date"}}]})
        if r.status_code != 200:
            raise MetricUnavailable(
                f"claimed-snapshot {phase} search returned HTTP {r.status_code}")
        return r.json().get("hits", {}).get("hits", [])

    try:
        hits = _search("CLAIMED", "asc") + _search("RESOLVED", "desc")
        return [{"index": h["_index"], "id": h["_id"]} for h in hits if "_index" in h and "_id" in h]
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"claimed-snapshot search failed: {e}") from e


def metric_vanished_claims():
    """Thin wrapper over `_vanished_claims_detail()` returning just the
    count — the shape every other metric_fns entry returns, and the one
    `main()`'s generic breach-comparison loop expects. `main()` itself
    calls `_vanished_claims_detail()` directly instead (not through this
    wrapper) so it can ALSO persist which specific docs vanished (#373) —
    see that function's own docstring."""
    return _vanished_claims_detail()[0]


def _vanished_claims_detail():
    """Count of, AND the specific identifiers for, CLAIMED-or-RESOLVED claim
    docs from the PRIOR sample that no longer exist at all (#361, follow-up
    from #357's security-auditor review; RESOLVED coverage added after a
    tester-debugger live-verification finding during this same issue's
    review; #373 added returning which docs, not just how many, alongside
    a `slo_dashboard.ndjson` panel — this metric was previously edge-
    triggered with no durable record of which claim vanished, so a
    post-incident investigation had nothing to go on beyond ntfy alert
    text once the baseline rolled forward).

    Returns `(count, vanished)` where `vanished` is a list of
    `{"index", "id"}` dicts (same plain-key convention as
    `_claimed_snapshot()`'s own return shape, for the same ES reserved-
    field-name reason documented there) for exactly the docs this run
    confirmed gone — `main()` persists this list onto the CURRENT run's
    own `soc-slo-metrics` doc (not a future baseline) when non-empty, so
    an investigator doesn't need to reconstruct the vanished doc's
    `_index`/`_id` from ntfy alert text after the next run's baseline has
    already rolled past it.

    #357 made `agent_checkpoints_compactor` (read+delete on
    `agent-checkpoints-*`, no document-level restriction under this stack's
    Basic license) live for the first time on any host that installs
    `checkpoints-compact.service`. checkpoints.py's own CLAIMED/RESOLVED/
    RELEASED protection is enforced only inside the Python layer
    (`_transition_claim()`, an ES `_update` — the doc's `_id` never
    changes, only its `phase` field does; see `resolve_claim()`/
    `release_claim()`). Nothing stops that credential from
    `_delete_by_query`-ing a live claim doc directly — see
    `_claimed_snapshot()`'s docstring for exactly which phases that's
    dangerous for (CLAIMED and RESOLVED; deliberately not RELEASED) and
    why: `claim_approval()`'s `op_type=create` only checks whether the doc
    EXISTS, not what phase it last held, so deleting either one grants a
    fresh claim unconditionally, reopening the at-most-once execution gate
    #214/#247 exist to close.

    `metric_stuck_approval_claims()`/`metric_orphaned_claims()` both count
    CLAIMED docs going UP as the sign of trouble; this is deliberately the
    mirror case — deleting a CLAIMED OR RESOLVED doc drives both of THOSE
    metrics down (RESOLVED docs were never in their scope to begin with),
    making the dashboard read healthier exactly when something is wrong.
    This metric is the one that goes up instead.

    The join key is the prior sample's hit metadata (`index`/`id`), never
    `_source` — captured by an EARLIER run before any tampering could
    target it, so it can't be retroactively forged through the doc it
    describes. It CAN still be forged by writing a NEW `soc-slo-metrics`
    document: `slo_metrics_reader` itself holds `create` on this index (it
    has to, to persist its own runs), and `soc_admin` holds `all` on
    `soc-*` — `agent_checkpoints_compactor` does NOT (zero grants outside
    `agent-checkpoints-*`), so that specific credential can't blind this
    detection, but a credential that CAN write here is a strictly different
    (and on this host, co-located: every service credential in this repo
    is read from the same `scripts/setup/.env`) trust boundary than the one
    this metric defends. The freshness window below narrows, but does not
    eliminate, that surface — see the prior-sample query.

    Prior-sample lookup: `_claimed_snapshot()` unconditionally stamps every
    run's own persisted doc with `claimed_snapshot_at` (see `main()`),
    including when zero claims were open — Elasticsearch's `exists` query
    does NOT match a field indexed as `[]`, so keying the lookup on
    `claimed_snapshot` itself would silently skip every quiet run and reach
    arbitrarily far back for a non-empty one. `claimed_snapshot_at` is
    always a non-empty scalar, so `exists` on IT is reliable regardless of
    how many claims were open. The accompanying `range` bounds that lookup
    to `SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN` in the past AND rejects
    anything timestamped in the future (`lte: now`) — the latter closes a
    forged-baseline doc pinning the search forever via a bogus future
    `@timestamp`/`claimed_snapshot_at`, the sharper version of this
    metric's own known residual gap below.

    No prior sample within the freshness window (first run, a fresh/empty
    index — searched with `ignore_unavailable=true` so a not-yet-created
    `soc-slo-metrics` 404s into an empty result instead of an error, or
    every run in that window genuinely had nothing open) is a real
    "nothing to compare against" — 0, not an error.

    `_mget` per-doc errors (e.g. a tenant's whole `agent-checkpoints-*`
    index gone, not just one doc) are NOT counted as vanished — that is
    "could not determine," not "confirmed gone," and this file's own
    standard (`MetricUnavailable` over a silently-wrong value) applies.

    KNOWN RESIDUAL GAP, deliberately not fixed here: if a deleted claim's
    `alert_id` gets a legitimate NEW claim before the next sample runs
    (`op_type=create` succeeds again once the old doc is gone), the _mget
    below finds a doc again (a fresh CLAIMED document under the SAME `_id`
    — `_mget` only checks existence, not content) and this specific
    vanish-then-recreate race won't register, for either phase this metric
    tracks. Narrowing the SLO run cadence below the claim lifecycle would
    help but is a deployment/tuning decision, not a code change this
    metric's addition should make unilaterally.

    Coverage is asymmetric between the two phases it tracks, by nature of
    what each phase means: a CLAIMED claim only sits in ANY snapshot while
    it's genuinely open — "a normal run resolves it within seconds" (see
    `metric_stuck_approval_claims()`) — so in practice this mostly catches
    stuck/long-lived CLAIMED claims, not fast resolve-in-seconds ones. A
    RESOLVED claim, once it exists, keeps appearing in every snapshot
    (subject to `_claimed_snapshot()`'s own newest-first cap) until it's
    overtaken by newer resolutions — so RESOLVED coverage is closer to
    continuous, bounded mainly by that cap under high claim volume, not by
    sampling timing. Real, partial coverage either way, not full coverage.
    """
    try:
        r = es("POST", "/soc-slo-metrics/_search?ignore_unavailable=true",
               {"size": 1, "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"exists": {"field": "claimed_snapshot_at"}},
                    {"range": {"claimed_snapshot_at": {
                        "gte": f"now-{SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN:g}m",
                        "lte": "now"}}},
                ]}},
                "_source": ["claimed_snapshot"]})
        if r.status_code != 200:
            raise MetricUnavailable(f"vanished-claims prior-sample search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"vanished-claims prior-sample search failed: {e}") from e

    raw_prior = hits[0]["_source"].get("claimed_snapshot", []) if hits else []
    # Trust boundary (see docstring): only accept the exact shape
    # _claimed_snapshot() produces. Anything else — wrong types, extra
    # keys that could smuggle _mget request options like `routing`, an
    # `_index` outside this pipeline's own namespace — is dropped, not
    # passed through to a real ES request body.
    prior = [{"_index": entry["index"], "_id": entry["id"]} for entry in raw_prior
             if isinstance(entry, dict) and set(entry) == {"index", "id"}
             and isinstance(entry.get("index"), str) and isinstance(entry.get("id"), str)
             and entry["index"].startswith("agent-checkpoints-")
             and entry["id"].endswith(".claim")]
    if not prior:
        return 0, []

    try:
        r = es("POST", "/_mget", {"docs": prior})
        if r.status_code != 200:
            raise MetricUnavailable(f"vanished-claims mget returned HTTP {r.status_code}")
        results = r.json().get("docs", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"vanished-claims mget failed: {e}") from e

    errored = [d for d in results if "error" in d]
    if errored:
        raise MetricUnavailable(
            f"vanished-claims mget: {len(errored)} doc(s) unreadable, "
            f"first: {errored[0].get('error')}")
    # code-reviewer follow-up: _mget's response `docs` array preserves the
    # SAME order as the request `docs` array (`prior`) — the pre-existing
    # metric_orphaned_claims() above already implicitly relies on the same
    # correspondence for its own count, where a length mismatch would only
    # under/over-count. Here, zip() uses that same ordering to positionally
    # ATTRIBUTE a specific _index/_id to each "vanished" verdict — a
    # silently truncated/malformed response (results shorter than prior)
    # would zip() into a wrong-but-plausible-looking attribution instead of
    # visibly failing. This file's own standard (MetricUnavailable over a
    # silently-wrong value) applies here too.
    if len(results) != len(prior):
        raise MetricUnavailable(
            f"vanished-claims mget: expected {len(prior)} result(s), got "
            f"{len(results)} — cannot reliably attribute _index/_id to "
            f"each vanished doc")
    # Plain index/id keys (not _index/_id), matching _claimed_snapshot()'s
    # own convention.
    vanished = [{"index": p["_index"], "id": p["_id"]}
                for p, d in zip(prior, results) if not d.get("found")]
    return len(vanished), vanished


def metric_raw_alert_volume():
    """Raw detection signal volume in the window, independent of whether a case
    was ever opened (#216) — metric_false_positive_pct() only sees analyst-
    dispositioned Kibana Cases; a Zeek notice or Sigma/discovery-rule hit that
    never escalates to a case is invisible to it. Detection tuning needs this
    as a before/after signal to prove it reduces noise rather than just
    silencing it.

    Two independent detection paths, per configs/logstash.conf's own Category-5
    comment ("ENDPOINT (Sigma) ... are Elastic Detection Engine rules now ...
    Only the Zeek scan/brute detections remain pipeline-classified"):
      - zeek_notices: threat.technique.id tagged in-pipeline directly on
        logstash-security-* docs (excludes the parse-failure quarantine index,
        which can carry the same tag). Named for the ATT&CK technique it
        represents, not for Zeek's own notice.log framework - both T1046
        (Scan::Port_Scan) and T1110 (SSH::Password_Guessing/
        Login_By_Password_Guesser) are real, thresholded, aggregated Zeek
        notices (#261 fixed T1110's tag, which previously matched every
        single auth_success=false event instead).
      - rule_hits: Sigma/Elastic Detection Engine alerts in
        .alerts-security.alerts-* (same index metric_mttd() already reads).
        Queried strict (#216) - this index should always exist once Kibana's
        Security app has initialized, so a missing/unresolvable pattern here
        is a real problem, not a benign "no alerts yet."
      - zeek_notices_distinct_sources: #331 - scan-detection.zeek's Scan::
        Port_Scan counts a port on the initial SYN alone (no completed
        handshake), so a spoofed-source SYN sweep can generate one notice
        per forged source with zero real network presence, inflating
        zeek_notices in a way a before/after tuning comparison can't tell
        apart from real activity. Two sensor-side fixes were tried and
        rejected by live security review before landing here: (1) gating
        the count on connection_established/connection_rejected (only
        count once the responder's reply was observed) doesn't actually
        defend against spoofing at THIS deployment's capture topology -
        zeek-host-capture.service captures at the monitored host's OWN
        interface, so that host's real reply to a spoofed SYN is exactly as
        visible to Zeek as a reply to a genuine one (the textbook
        SYN-flood-reflection mechanism, not a Zeek quirk) - and it cost
        real detection recall (filtered-host scans and non-SYN scan types
        stopped counting at all). (2) a sensor-side global notice-volume
        cap bounded the metric-gaming impact but introduced a WORSE
        problem: a cheap, silent denial-of-detection primitive (a
        sub-second burst of spoofed sources exhausts the cap, then a real,
        concurrent scan generates no notice at all for the rest of the
        window, with zero telemetry marking that anything was dropped).
        source-authenticity verification isn't achievable at Zeek's own
        vantage point without destroying recall, and any sensor-side
        remedy trades real detections away to fix what is fundamentally a
        REPORTING problem, not a detection one - so the fix lives here
        instead, where the raw data survives. A cardinality aggregation on
        source.ip for the same zeek_notices query: a flood from many
        distinct (spoofed or real) sources reads very differently from a
        few real sources repeatedly triggering the notice, which is
        exactly the discrimination a before/after comparison needs and a
        sensor-side volume cap can never provide (it can only say "some
        flood happened," never "and here's how many distinct sources it
        came from"). scan-detection.zeek itself is intentionally
        UNCHANGED by #331 - reverted to its original, pre-#331 form after
        both sensor-side attempts were found unsound.

    Known limitation: this signal catches WIDE floods (many distinct forged
    sources), not NARROW high-volume ones. scan-detection.zeek suppresses to
    one notice per source per port_scan_resuppress (1 min), so a handful of
    forged sources sustained across the full WINDOW (default 7d) can still
    push zeek_notices into the thousands while zeek_notices_distinct_sources
    stays in the single digits - reading identically to a few real repeat
    scanners. A high zeek_notices count paired with a low
    zeek_notices_distinct_sources count is AMBIGUOUS (real repeat activity or
    a small-N spoofed flood), not confirmed-benign - see
    docs/SOP-022-anomaly-validation-procedure.md and
    docs/SOP-147-evidence-validation-procedure.md for analyst guidance.

    Returns all sub-counts separately, not just zeek_notices + rule_hits
    summed: collapsing them into one number would hide exactly the kind of
    swing described above, making a before/after comparison unable to tell
    "tuning reduced noise" from "someone stopped scanning me" (or, with
    zeek_notices_distinct_sources, from "someone spoofed a flood at me").
    """
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    zeek_notices_query = {"bool": {"filter": [win, {"exists": {"field": "threat.technique.id"}}]}}
    zeek_notices_index = "logstash-security-*,-logstash-security-quarantine-*"
    zeek_notices = _count(zeek_notices_index, zeek_notices_query)
    rule_hits = _count(".alerts-security.alerts-*", win, strict=True)
    zeek_notices_distinct_sources = _cardinality(zeek_notices_index, zeek_notices_query, "source.ip")
    return {"zeek_notices": zeek_notices, "rule_hits": rule_hits,
            "zeek_notices_distinct_sources": zeek_notices_distinct_sources,
            "value": zeek_notices + rule_hits}


def metric_field_truncation_count():
    """Count of pipeline.truncated:"true" docs in the window (#252).

    process.args/process.parent.args/winlog.event_data.ScriptBlockText are
    mapped ignore_above:32766 (#249/#250 raised it from 1024 to 8191; #263
    raised it again to 32766, the Lucene keyword term byte ceiling, after
    8191 turned out to still be below real PowerShell 4104 chunk sizes and
    encoded command-line lengths) — a value longer than that ceiling is
    silently dropped from the index while remaining in _source, invisible to
    any query. configs/logstash.conf's ruby filter tags
    pipeline.truncated="true" (+ pipeline.truncated_fields) when it detects
    this; this metric turns that tag into a measured rate.

    NO_TARGET (see below): whether a still-bigger/unbounded field (a
    wildcard-typed multi-field, #326) is ever needed is conditional on real
    data showing 32766 is actually hit — no real Windows/process telemetry
    flows through this pipeline in this environment yet (per #253's
    live-verification notes), so there is no data to set a threshold
    against. This metric exists to produce that data, not to enforce a
    guessed number.
    """
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    return _count("logstash-security-*",
                  {"bool": {"filter": [win, {"term": {"pipeline.truncated": "true"}}]}})


def metric_field_byte_clamp_count():
    """Count of pipeline.byte_clamped:"true" docs in the window (#263).

    ignore_above:32766 on process.args/process.parent.args/winlog.event_data.
    ScriptBlockText/winlog.event_data.ImagePath is a CHARACTER ceiling, but
    Lucene's own per-term hard limit is a UTF-8 BYTE ceiling (also 32766) —
    a value under the char ceiling but byte-heavy (multi-byte UTF-8 content,
    e.g. Unicode identifier/homoglyph obfuscation) can still exceed Lucene's
    byte limit. Confirmed live during #263's review: unclamped, that makes
    Elasticsearch reject the WHOLE DOCUMENT (HTTP 400 "immense term"), not
    just drop the field — total event loss, strictly worse than the
    field-drop field_truncation_count measures. configs/logstash.conf's ruby
    filter defensively clamps the value before it reaches Elasticsearch and
    tags pipeline.byte_clamped="true" (+ pipeline.byte_clamped_fields); this
    metric turns that tag into a measured rate.

    NO_TARGET (see below), matching field_truncation_count's own precedent:
    a nonzero count here is unusual enough to be worth manually
    investigating on sight (it means genuinely pathological multi-byte
    content, not just a long script), but no real Windows/process telemetry
    flows through this pipeline in this environment yet (per #253's
    live-verification notes), so there is no data to justify a specific
    breach threshold rather than a guessed one.
    """
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    return _count("logstash-security-*",
                  {"bool": {"filter": [win, {"term": {"pipeline.byte_clamped": "true"}}]}})


def metric_oversized_dns_answer_count():
    """Count of pipeline.oversized_dns_answer:"true" docs in the window (#352).

    dns.answers (Zeek's TXT-record DNS answers, #292) is mapped
    ignore_above:8191 — unlike dns.question.name (protocol-capped at 253
    bytes, structurally unable to reach even the old 1024 default), a Zeek
    dns.log answers value has no such bound short of DNS's 65535-byte
    RDLENGTH, so a value over 8191 chars is silently dropped from the index
    with no error and (before #352) no visibility either.
    configs/logstash.conf's ruby filter tags
    pipeline.oversized_dns_answer="true" when it detects this (scalar or
    array [dns][answers], either shape); this metric turns that tag into a
    measured rate, matching field_truncation_count/field_byte_clamp_count's
    own precedent (#252/#263) rather than leaving the tag write-only
    (security-auditor follow-up to #352's first draft — a tag nothing
    queries doesn't actually deliver the "visibility" #352 asked for).

    A nonzero count here has a specific analyst meaning worth acting on
    directly, unlike the two precedent metrics above: it means
    net_zeek_dns_txt_answer_abuse.yml's length-heuristic rule may have been
    evaded by an answer too long for its compiled query to ever match —
    real TXT-based C2 tools chunk payload into ~250-byte answers (UDP
    response-size limits), so an oversized answer is itself an anomaly, not
    organic traffic shaped this way (see that rule's own description).

    HONEST DISCLOSURE (tester-debugger, #352 review): a >8191-char
    dns.answers value has been live-verified as structurally unreachable
    for real TXT-record traffic today — Zeek's own DNS analyzer
    independently truncates a TXT record's joined answers[] string at
    ~4096 chars, with no marker, before Elasticsearch's ignore_above ever
    gets a chance to matter (filed as #389, needs a Zeek-side fix, out of
    scope for this pipeline). This metric should read 0 in production
    right now; that is expected, not evidence the tag/metric are dead —
    they remain defense-in-depth against a non-Zeek dns.answers producer —
    NOT hypothetical, the unauthenticated :5514 HTTP input this pipeline
    exposes on soc-mesh-net can write an arbitrary [dns][answers] shape
    today (configs/logstash.conf's own Category 0 comment) — as well as a
    future Zeek version without this cap, or #389 being fixed in a way
    that raises real answer lengths past 8191. See the ruby
    filter's own comment in configs/logstash.conf (right above the
    `if [dns][answers]` block) for the paired half of this disclosure -
    the two are meant to be read together, not each a complete account
    on its own.

    NO_TARGET (see below), matching field_truncation_count/
    field_byte_clamp_count's own precedent: no real DNS telemetry volume
    has been measured through this pipeline in this environment yet, so
    there is no data to set a breach threshold against rather than a
    guessed one.
    """
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    return _count("logstash-security-*",
                  {"bool": {"filter": [win, {"term": {"pipeline.oversized_dns_answer": "true"}}]}})


def metric_zeek_path_nomatch_count():
    """Count of pipeline.zeek_path_nomatch:"true" docs in the window (#349).

    configs/logstash.conf's Category 0 grok (`[log][file][path] =>
    /(?<zeek_stream>[a-z0-9_]+)\\.log$/`) tags _zeek_path_nomatch when a
    Zeek log's filename doesn't match the pattern (e.g. an uppercase
    letter, hyphen, or dot before .log - outside [a-z0-9_]+). Before
    #291, a grok-failed document (no event.dataset, since the dataset
    stamp is gated on the grok's own success) was still fully ECS-mapped
    and still matched by any zeek Sigma rule, since nothing checked
    event.dataset. #291's event.dataset:zeek.<service> scoping condition
    means a grok-failed document is now completely invisible to every
    zeek-sourced detection - a real, if rare, detection blackout with
    zero visible signal, since the tag itself had no consumer until now.

    Unlike field_truncation_count/field_byte_clamp_count/oversized_dns_
    answer_count (measured, NO_TARGET baselines - no calibration data
    exists yet to set a threshold against), this has a real target of 0:
    it isn't a data-quality curiosity, it's a detection-coverage signal,
    same shape as stuck_approval_claims/orphaned_claims/vanished_claims
    (a condition that should never legitimately occur, not one this
    metric exists to characterize the normal rate of).

    Deliberately NOT the shared module-level WINDOW (security-auditor
    review, same reasoning metric_capture_loss_percent() already
    documents for itself): this counts immutable indexed docs, not
    self-clearing state like stuck/orphaned/vanished_claims, so combined
    with WINDOW's 7-day default and this metric's own 15-min poll cadence
    (configs/systemd/slo-metrics.timer), a SINGLE nomatch document would
    pin this metric in breach for ~672 consecutive runs - a week of
    repeated ntfy alerts sharing the same topic as genuinely urgent
    metrics, drowning them out. A short, separately-overridable window
    lets the metric self-clear once the triggering document ages out of
    a 1-hour lookback instead of a 7-day one.

    NOT hardened against active forgery, same pre-existing gap
    metric_capture_loss_percent() already documents for itself:
    configs/logstash.conf's Category 0 gates purely on event content
    (log.file.path matching *zeek_logs*/*.log), not on which input
    produced it, so this tag is triggerable via the unauthenticated
    :5514 HTTP input - tracked as the SAME pre-existing, separate
    pipeline-boundary gap (private security advisory, not a public
    issue - this repo is public and the gap is live/unpatched), not
    fixed here. The short window above bounds the practical impact to a
    transient, self-clearing false breach rather than a permanent one,
    matching the residual risk this repo already accepts for
    capture_loss_percent's identical exposure - not a NEW, worse-than-
    precedent risk this metric introduces on its own.
    """
    win = {"range": {"@timestamp": {"gte": os.environ.get("SLO_ZEEK_PATH_NOMATCH_WINDOW", "now-1h")}}}
    return _count("logstash-security-*",
                  {"bool": {"filter": [win, {"term": {"pipeline.zeek_path_nomatch": "true"}}]}})


def metric_capture_loss_percent():
    """Max Zeek capture_loss.log percent_lost in the window (#288).

    #228's policy/protocols/ssl/validate-certs adds real per-connection
    OpenSSL cert-chain verification with no aggregate resource guard — a
    burst of connections presenting unique/large certificate chains could
    show up as sustained CPU pressure, and the real capture path
    (configs/systemd/zeek-host-capture.service: tcpdump | docker run zeek
    -r -) has no load shedding, so that pressure surfaces as PACKET DROPS,
    a blind spot across every protocol, not just TLS. Zeek's own
    policy/misc/capture-loss (now @load-ed in configs/intel/config.zeek
    right after validate-certs) already computes this as percent_lost, on a
    0-100 scale (confirmed against the real policy/misc/capture-loss.zeek
    source: `100 * gaps / acks` — not the unrelated 0-1-scaled
    CaptureLoss::too_much_loss OPTION, a different, internal-only value),
    per watch_interval (default 15m); this metric turns that into a
    measured, alertable SLO instead of a log nobody reads. Live-confirmed
    end to end against a real `zeek/zeek` container + PCAP: the log file is
    genuinely named capture_loss.log (matching this metric's
    event.dataset:zeek.capture_loss filter) and percent_lost lands as a
    JSON float.

    Deliberately NOT the shared module-level WINDOW (security-auditor
    review): every other windowed metric here is self-averaging (mttd/mttr)
    or a ratio (parse_error_pct), so a long WINDOW just widens the sample.
    percent_lost is a per-watch_interval HIGH-WATER MARK — combined with
    WINDOW's 7-day default and this metric's own 15-min poll cadence
    (configs/systemd/slo-metrics.timer), one transient spike would pin this
    metric in breach for ~672 consecutive runs (a week of repeated ntfy
    alerts sharing the same topic as genuinely urgent metrics like
    ingest_lag_seconds, drowning them out). A short, separately-overridable
    window keeps `max` doing its job (catching a real spike at all) while
    letting the metric self-clear once the spike ages out of a 1-hour
    lookback instead of a 7-day one.

    Not NO_TARGET like field_truncation_count/field_byte_clamp_count: those
    have no calibrated threshold because there's no real Windows/process
    telemetry in this environment to set one against, but packet-loss
    percentage is a well-understood operational concept independent of this
    pipeline's own schema — 5% (TARGETS above) is a conservative,
    overridable starting point, not an empirically-derived number.

    Not in BREACH_IF_NA (security-auditor review: the original reasoning
    here was incomplete, not wrong) — a blanket BREACH_IF_NA would falsely
    alarm on every fresh deployment before the first watch_interval, the
    exact "permanent, unactionable alert noise" metric_audit_write_
    failures' own docstring already rejects for the same shape. But
    metric_ingest_lag_seconds does NOT actually cover "capture-loss
    monitoring itself silently stopped" the way the original version of
    this docstring claimed: ingest_lag only catches TOTAL pipeline death,
    and endpoint (Winlogbeat/Filebeat-non-Zeek) telemetry alone keeps it
    green while the Zeek sensor itself is dead or a restart raced past the
    ExecStartPre check without this @load ever taking effect. So the
    no-aggregation-value case below distinguishes the two: no Zeek data at
    all in the window is benign (None, "n/a"); Zeek data flowing but zero
    capture_loss docs among it is now itself an error, not silence — but
    only once that Zeek data is itself over 30 minutes old (2x the default
    watch_interval), so a short offline PCAP replay (scripts/setup/
    zeek_run_pcap.sh), a brief manual stream_capture.sh session, or the
    first run after a fresh deploy don't false-trigger it (security-auditor
    follow-up: an unqualified check did exactly that on all 3).

    NOT hardened against active forgery: configs/logstash.conf's Category 0
    gates purely on event content (log.file.path matching *_logs/*.log),
    not on which input produced it, so event.dataset is spoofable via the
    unauthenticated :5514 HTTP input — tracked as a pre-existing, separate
    pipeline-boundary gap (private security advisory, not a public issue —
    this repo is public and the gap is live/unpatched), not fixed here.
    """
    win = {"range": {"@timestamp": {"gte": os.environ.get("SLO_CAPTURE_LOSS_WINDOW", "now-1h")}}}
    body = {"size": 0, "query": {"bool": {"filter": [
        win, {"term": {"event.dataset": "zeek.capture_loss"}}]}},
        "aggs": {"max_loss": {"max": {"field": "percent_lost"}}}}
    try:
        r = es("POST", "/logstash-security-*/_search", body)
        if r.status_code != 200:
            raise MetricUnavailable(f"capture-loss search returned HTTP {r.status_code}")
        v = r.json().get("aggregations", {}).get("max_loss", {}).get("value")
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"capture-loss search failed: {e}") from e
    if v is not None:
        return round(v, 3)
    # No capture_loss docs in the window — distinguish "no Zeek data yet"
    # (benign) from "Zeek is flowing but capture-loss reporting itself is
    # dead" (a real, previously-silent failure).
    #
    # security-auditor follow-up review: an unqualified "any Zeek doc in the
    # window" check false-triggers on 3 real workflows this exact host
    # documents — offline PCAP replay (scripts/setup/zeek_run_pcap.sh,
    # SOP-001), a short manual stream_capture.sh session, and the first run
    # after a fresh deploy — none of which run long enough to reach even one
    # CaptureLoss::watch_interval (default 15m), so "Zeek docs exist, no
    # capture_loss docs yet" is the NORMAL case for all three, not a
    # failure. Requiring the Zeek data to predate 2x the default
    # watch_interval before treating its absence as suspicious keeps the
    # genuine failure case (capture alive for a sustained period, zero
    # capture_loss docs the whole time) while no longer firing on any of
    # the three short-lived cases above.
    stale_zeek_filter = {"bool": {"filter": [
        win, {"term": {"event.module": "zeek"}},
        {"range": {"@timestamp": {"lte": "now-30m"}}}]}}
    zeek_flowing = _count("logstash-security-*", stale_zeek_filter)
    if zeek_flowing:
        raise MetricUnavailable(
            "zeek data has been flowing for over 30 minutes in the window but no "
            "capture_loss docs were seen — capture-loss monitoring itself may not be running")
    return None


def metric_intel_feed_stale_heartbeats():
    """Count of `status:"ok"` heartbeat docs in `threat-intel-meta` within
    the last 8h (#358).

    Replaces `rules/elastic_watcher/intel_feed_stale.json` — RETIRED
    (`rules/elastic_watcher/retired/`) because Elastic Watcher itself is
    not licensed on this stack: `xpack.license.self_generated.type=basic`
    (`.env`), and every Watcher API call — live-confirmed against the real
    running cluster, including a brand-new trivial watch — is rejected
    with `security_exception: current license is non-compliant for
    [watcher]` (HTTP 403). That Watcher's install step
    (`deploy_dashboards.sh`) has silently absorbed this failure via its own
    best-effort `WARN` logging since WS1.3 — this stale-feed alert has
    never actually fired here. Same condition, same 8h window (6h refresh
    cadence + ~2h of scheduling-jitter tolerance around a successful run —
    see the TARGETS entry above for why "tolerates one missed run" is NOT
    what this window does), now on infrastructure that actually runs: this
    file's own proven ntfy-alerting/indexed-history pipeline.

    `refresh_intel.sh` writes one heartbeat doc per run (`status:"ok"` or
    `status:"stale"` — see that script's own `status=` assignments) whether
    or not `ES_PASS` is even set to index it at all; a dead
    `intel-refresh.timer`, a `refresh_intel.sh` itself crashing, or every
    run in the window landing `status:"stale"` (a fetch failure on both
    feeds, a missing seed, or a failed heartbeat write) all collapse to the
    same observable here: zero matching docs. Target `>= 1` — a healthy run
    is what satisfies this, not a count to keep low.
    """
    win = {"range": {"@timestamp": {"gte": "now-8h"}}}
    return _count("threat-intel-meta",
                  {"bool": {"filter": [win, {"term": {"status": "ok"}}]}})


# #358: freshness window for the run-over-run actual-count baseline
# metric_intel_indicator_count_drop_pct() persists onto its own
# soc-slo-metrics doc — same pattern/reasoning as
# SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN (#361): wide enough to tolerate a
# missed run, far short of compact_threat_intel.py's DEFAULT_RETENTION_DAYS
# so a stale baseline can't reach into legitimately-aged-out data.
SLO_INTEL_DROP_BASELINE_MAX_AGE_MIN = float(
    os.environ.get("SLO_INTEL_DROP_BASELINE_MAX_AGE_MIN", str(2 * 24 * 60)))


def _intel_indicator_actual_count():
    """`threat-intel-indicators`' real document count, right now — the one
    number in `metric_intel_indicator_count_drop_pct()`'s comparison
    neither `threat_intel_compactor` nor `intel_writer` can retroactively
    manipulate once persisted (see that metric's docstring on why it's
    needed as a SECOND baseline, not just the heartbeat-reported one)."""
    return _count("threat-intel-indicators", {"match_all": {}})


def _prior_intel_actual_count():
    """Most recent PRIOR run's real `threat-intel-indicators` count,
    persisted onto its own `soc-slo-metrics` doc by `main()` — untouchable
    by `threat_intel_compactor` (delete on `threat-intel-*` only) or
    `intel_writer` (index on `threat-intel-*` only), neither of which holds
    any grant on `soc-slo-metrics`. Freshness-windowed the same way
    `metric_vanished_claims()`'s baseline is (#361 precedent): `exists` on
    an always-non-empty scalar timestamp field (not the count field itself,
    which — unlike `vanished_claims`' snapshot array — is never legitimately
    absent once written, but keying on the same sibling timestamp field
    keeps this consistent with that established pattern), bounded both past
    (tolerates a missed run) and future (rejects a forged baseline dated
    ahead of `now`).

    None if no persisted baseline exists within the window — a genuine
    "nothing to compare against yet" for THIS specific comparison, not an
    error; `metric_intel_indicator_count_drop_pct()` still has the
    heartbeat-based comparison to fall back on.
    """
    try:
        r = es("POST", "/soc-slo-metrics/_search?ignore_unavailable=true",
               {"size": 1, "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"exists": {"field": "intel_indicator_actual_count_at"}},
                    {"range": {"intel_indicator_actual_count_at": {
                        "gte": f"now-{SLO_INTEL_DROP_BASELINE_MAX_AGE_MIN:g}m",
                        "lte": "now"}}},
                ]}},
                "_source": ["intel_indicator_actual_count"]})
        if r.status_code != 200:
            raise MetricUnavailable(f"intel-drop actual-count baseline search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"intel-drop actual-count baseline search failed: {e}") from e

    if not hits:
        return None
    value = hits[0]["_source"].get("intel_indicator_actual_count")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None  # malformed/forged baseline doc — treat as no usable baseline, not a crash
    return value


def metric_intel_indicator_count_drop_pct():
    """How far `threat-intel-indicators`' real document count sits below
    EITHER of two independent baselines (#358) — whichever shows the WORSE
    (larger) drop wins:

    (a) The latest `threat-intel-meta` heartbeat's own `indicator_count`.
        `indicator_count` is a SINGLE RUN's merged-feed total (seed + both
        live feeds' current output), not the cumulative historical set
        `threat-intel-indicators` actually holds: `refresh_intel.sh`'s bulk
        upsert only touches indicators present in the CURRENT run's
        output — one that drops out of the feed keeps its existing
        document, unrefreshed, until `compact_threat_intel.py`'s own
        30-day retention ages it out (see that script's module docstring).
        So under healthy operation the real count normally sits AT OR
        ABOVE any single heartbeat's `indicator_count` — a MEANINGFUL
        shortfall is the actual anomaly, not routine feed churn.
    (b) The PRIOR run's own persisted real count (`_prior_intel_actual_
        count()`), untouchable by either credential named below.

    Why (a) alone isn't enough (security-auditor finding): comparison (a)
    depends entirely on `threat-intel-meta`, which the SAME credential
    this metric exists to catch can also reach.
    `threat_intel_compactor` holds `delete` on `threat-intel-meta` itself
    (not just `-indicators`) — wiping every heartbeat makes (a) return
    "no baseline" instead of a breach. `intel_writer` holds `index` on
    `threat-intel-meta` — forging one `{"status":"ok","indicator_count":0}`
    doc makes `metric_intel_feed_stale_heartbeats()` read healthy AND (a)'s
    `indicator_count` falsy, again "no baseline". Comparison (b) reads
    from `soc-slo-metrics` instead, which neither credential can write —
    persisted by an EARLIER run, before any tampering could target it, the
    same trust-boundary shape `metric_vanished_claims()` already
    establishes for `agent-checkpoints-*` (#361).

    Reuses `compact_threat_intel.py`'s own `BLAST_RADIUS_FRACTION=0.5`
    precedent for "how much shrink is suspicious" (`SLO_INTEL_DROP_MAX_PCT`
    in `TARGETS`) for both comparisons, rather than inventing a second,
    uncoordinated threshold for the same underlying shape.

    None (no breach) only when NEITHER baseline is available — a genuine
    "nothing to compare against yet" (fresh deployment, or comparison (b)'s
    own freshness window hasn't been populated yet). A degenerate
    `indicator_count:0` heartbeat is excluded from (a) specifically (can't
    divide by zero, and `metric_intel_feed_stale_heartbeats()` already
    flags a genuinely-empty heartbeat on its own terms) but does NOT by
    itself suppress (b).

    KNOWN RESIDUAL GAP, deliberately not fixed here: if `slo-metrics.timer`
    itself has been down long enough for comparison (b)'s own freshness
    window to lapse, a wipe timed into that gap is caught only by
    comparison (a) — which the same wipe-capable credential can also
    blind, per the trust-boundary analysis above. Narrowing the freshness
    window trades against tolerating a legitimately missed run; matches
    `metric_vanished_claims()`'s own accepted tradeoff for the identical
    shape.
    """
    candidates = []

    try:
        r = es("POST", "/threat-intel-meta/_search?ignore_unavailable=true",
               {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["indicator_count"]})
        if r.status_code != 200:
            raise MetricUnavailable(f"intel-indicator-drop heartbeat search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"intel-indicator-drop heartbeat search failed: {e}") from e

    reported = hits[0]["_source"].get("indicator_count") if hits else None
    # security-auditor MEDIUM: reported comes straight from a doc
    # intel_writer can shape arbitrarily — a non-numeric/negative value
    # must not reach arithmetic (a TypeError here would escape main()'s
    # per-metric loop, which only catches MetricUnavailable, killing the
    # ENTIRE metrics run over one malformed heartbeat).
    if isinstance(reported, bool) or not isinstance(reported, (int, float)) or reported < 0:
        if reported is not None:
            raise MetricUnavailable(
                f"threat-intel-meta heartbeat has a non-numeric indicator_count: {reported!r}")
        reported = None

    actual = _intel_indicator_actual_count()

    if reported:  # excludes both None and the degenerate 0 case
        candidates.append(max(0.0, 100.0 * (reported - actual) / reported))

    prior_actual = _prior_intel_actual_count()
    if prior_actual:
        candidates.append(max(0.0, 100.0 * (prior_actual - actual) / prior_actual))

    return round(max(candidates), 2) if candidates else None


def main():
    if not ES_PASS:
        print("ERROR: ES_PASS / ELASTIC_PASSWORD required", file=sys.stderr)
        sys.exit(1)

    metric_fns = {
        "mttd_minutes": metric_mttd,
        "mttr_minutes": metric_mttr,
        "coverage_techniques": metric_coverage,
        "false_positive_pct": metric_false_positive_pct,
        "ingest_lag_seconds": metric_ingest_lag_seconds,
        "parse_error_pct": metric_parse_error_pct,
        "audit_write_failures": metric_audit_write_failures,
        "broker_response_tampering_count": metric_broker_response_tampering,
        "stuck_approval_claims": metric_stuck_approval_claims,
        "orphaned_claims": metric_orphaned_claims,
        "vanished_claims": metric_vanished_claims,
        "raw_alert_volume": metric_raw_alert_volume,
        "field_truncation_count": metric_field_truncation_count,
        "field_byte_clamp_count": metric_field_byte_clamp_count,
        "oversized_dns_answer_count": metric_oversized_dns_answer_count,
        "zeek_path_nomatch_count": metric_zeek_path_nomatch_count,
        "capture_loss_max_pct": metric_capture_loss_percent,
        "intel_feed_stale_heartbeats": metric_intel_feed_stale_heartbeats,
        "intel_indicator_count_drop_pct": metric_intel_indicator_count_drop_pct,
    }
    values, errors = {}, {}

    # #305: run once, before any metric — a live privilege regression here
    # would otherwise silently masquerade as a healthy 0 on whichever
    # metric below happens to query the affected pattern.
    try:
        _check_slo_metrics_reader_privileges()
    except MetricUnavailable as e:
        errors["slo_metrics_reader_privileges"] = str(e)
        print(f"  -> slo_metrics_reader privilege self-check failed: {e}", file=sys.stderr)

    for name, fn in metric_fns.items():
        try:
            values[name] = fn()
        except MetricUnavailable as e:
            # audit #165 / NIST SI-11: a measurement failure must never look
            # like a benign "n/a" or a healthy "0" — it is always a breach.
            values[name] = None
            errors[name] = str(e)

    now = datetime.now(timezone.utc).isoformat()
    doc = {"@timestamp": now, "slo": {}, "window": WINDOW}
    breaches = []
    print(f"SOC SLO metrics @ {now}")
    print(f"  {'metric'.ljust(20)} {'value':>10}  {'target':>8}  status")
    for name, val in values.items():
        if name in NO_TARGET:
            # #216: a NO_TARGET metric has no breach threshold, but an
            # unmeasurable value must still surface as a real failure - never
            # let this look like a silently healthy "ok" the way every other
            # metric's error path already guarantees (audit #165 / SI-11).
            if name in errors:
                status = "ERROR(unmeasurable)"
                entry = {"error": errors[name]}
            else:
                status = "measured"
                entry = dict(val) if isinstance(val, dict) else {"value": val}
            doc["slo"][name] = entry
            display = val.get("value") if isinstance(val, dict) else val
            print(f"  {name.ljust(20)} {str(display):>10}  {'n/a':>8}  {status}")
            continue
        target = TARGETS[name]
        lower = LOWER_BETTER[name]
        if name in errors:
            breach = True
            status = "ERROR(unmeasurable)"
        elif val is None:
            # Fail closed for liveness-critical metrics: unmeasurable == breach.
            breach = name in BREACH_IF_NA
            status = "BREACH(no-data)" if breach else "n/a"
        else:
            breach = (val > target) if lower else (val < target)
            status = "BREACH" if breach else "ok"
        if breach:
            breaches.append(name)
        entry = {"value": val, "target": target,
                 "comparator": "<=" if lower else ">=", "breach": breach}
        if name in errors:
            entry["error"] = errors[name]
        doc["slo"][name] = entry
        print(f"  {name.ljust(20)} {str(val):>10}  {('<=' if lower else '>=')+str(target):>8}  {status}")
    doc["breach_count"] = len(breaches)
    doc["error_count"] = len(errors)
    # #216: errors (including a NO_TARGET metric's) take priority in the
    # persisted status — a run with any unmeasurable metric must never
    # persist "ok", even if every metric that DOES have a target is healthy.
    doc["status"] = "error" if errors else ("breach" if breaches else "ok")

    # #361: this run's own CLAIMED-doc snapshot, persisted for
    # metric_vanished_claims() to diff the NEXT run against. Top-level, not
    # under "slo" — it isn't a value/target/breach dashboard entry, it's
    # state for this metric's own future comparison. claimed_snapshot_at is
    # stamped UNCONDITIONALLY, even when the snapshot itself is empty — see
    # metric_vanished_claims()'s docstring for why the prior-sample lookup
    # depends on that (Elasticsearch's `exists` query does not match `[]`).
    # Best-effort: a capture failure here means the NEXT run either compares
    # against an older baseline still inside its freshness window, or (once
    # that window elapses) gets a clean "no prior sample" 0 — either way,
    # not a reason to fail this run's own otherwise-successful metrics.
    try:
        doc["claimed_snapshot"] = _claimed_snapshot()
        doc["claimed_snapshot_at"] = now
    except MetricUnavailable as e:
        print(f"  -> claimed-snapshot capture failed (next vanished_claims "
              f"check will compare against an older baseline, if still "
              f"within its freshness window): {e}", file=sys.stderr)

    # #373: this run's own vanished-doc identifiers, persisted onto THIS
    # run's doc (not a future baseline, unlike claimed_snapshot above) so a
    # post-incident investigation doesn't need to reconstruct which
    # specific claim disappeared from ntfy alert text alone, after the
    # NEXT run's own claimed_snapshot has already rolled the baseline
    # forward past it. Only set when non-empty — every healthy run finding
    # nothing vanished shouldn't carry a redundant empty array. Recomputes
    # via a second call to _vanished_claims_detail() rather than reusing
    # `values["vanished_claims"]` from the metric_fns loop above (deliberately
    # kept separate/unchanged there, matching every other metric's plain-int
    # contract) — a second read-only query, not a second decision; best-
    # effort like claimed_snapshot/intel_indicator_actual_count above, since
    # a capture failure here costs only forensic detail, not this run's own
    # otherwise-successful breach detection (values["vanished_claims"] is
    # already set from the loop regardless of whether this block succeeds).
    try:
        _, vanished_docs = _vanished_claims_detail()
        if vanished_docs:
            doc["vanished_claim_docs"] = vanished_docs
    except MetricUnavailable as e:
        print(f"  -> vanished-claims detail capture failed (breach count "
              f"above is still accurate; only the specific doc identifiers "
              f"for this run are unavailable): {e}", file=sys.stderr)

    # #358: this run's own real threat-intel-indicators count, persisted for
    # metric_intel_indicator_count_drop_pct()'s run-over-run comparison —
    # same top-level/best-effort/unconditional-timestamp shape as
    # claimed_snapshot above, and for the same reason (an always-non-empty
    # sibling timestamp field the `exists` prior-sample lookup can key on
    # reliably). Untouchable by threat_intel_compactor/intel_writer, neither
    # of which holds any grant on soc-slo-metrics — see that metric's own
    # docstring for the trust-boundary analysis this defends.
    try:
        doc["intel_indicator_actual_count"] = _intel_indicator_actual_count()
        doc["intel_indicator_actual_count_at"] = now
    except MetricUnavailable as e:
        print(f"  -> intel-indicator actual-count capture failed (next "
              f"intel_indicator_count_drop_pct check falls back to the "
              f"heartbeat-only comparison, or an older baseline if still "
              f"within its freshness window): {e}", file=sys.stderr)

    # Index for the SLO dashboard.
    index_failed = False
    try:
        r = es("POST", "/soc-slo-metrics/_doc", doc)
        if r.status_code >= 300:
            index_failed = True
            print(f"  -> ES index failed: HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
        else:
            print(f"  -> indexed to soc-slo-metrics (breaches: {len(breaches)}, errors: {len(errors)})")
    except Exception as e:
        index_failed = True
        print(f"  -> ES index failed: {e}", file=sys.stderr)

    # Alert on breach OR measurement error (best-effort) — an unmeasurable
    # metric is never allowed to be silent just because it happens to be
    # NO_TARGET (#216: this used to only fire on `breaches`, so a
    # raw_alert_volume-only failure raised no alert at all).
    if (breaches or errors) and NTFY_TOPIC:
        try:
            parts = []
            if breaches:
                parts.append(f"breached: {', '.join(breaches)}")
            if errors:
                parts.append(f"unmeasurable: {', '.join(errors)}")
            requests.post(f"https://ntfy.sh/{NTFY_TOPIC}",
                          data=f"SOC SLO ISSUE: {'; '.join(parts)}".encode(),
                          headers={"Title": "Suburban-SOC SLO breach", "Priority": "high",
                                   "Tags": "chart_with_downwards_trend,warning"}, timeout=8)
        except Exception:
            pass

    # audit #165 / NIST SI-11: a measurement error (or a failure to persist the
    # doc at all) is a harder failure than a routine target breach — exit 3 so
    # slo-metrics.service (SuccessExitStatus=0 2) correctly reports a failed
    # run instead of blending it into "successful run, breach".
    if errors or index_failed:
        sys.exit(3)
    sys.exit(2 if breaches else 0)


if __name__ == "__main__":
    main()

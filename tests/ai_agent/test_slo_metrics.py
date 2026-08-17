#!/usr/bin/env python3
"""
SLO metrics — measurement-error visibility tests (audit #165 / NIST SI-11).

slo_metrics.py must distinguish "ES/Kibana unreachable" from "genuinely no
data this window": a down dependency must always surface as an error/breach,
never silently collapse into a healthy-looking None/0 reading.

Run:  pytest tests/ai_agent/test_slo_metrics.py
"""

import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# ES_PASS is read at import time; must be truthy or main() exits(1) immediately.
os.environ["ES_PASS"] = "unit_test_pass"

import env_loader
import slo_metrics


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class MetricFunctionTests(unittest.TestCase):
    """Each metric must raise MetricUnavailable on a real failure, but still
    return the same legitimate value (None/0) as before on genuine no-data."""

    def test_count_raises_on_request_exception(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._count("logstash-security-*", {"match_all": {}})

    def test_count_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._count("logstash-security-*", {"match_all": {}})

    def test_count_returns_real_zero_when_es_is_healthy(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics._count("logstash-security-*", {"match_all": {}}), 0)

    def test_mttd_raises_on_request_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=TimeoutError("timed out")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_mttd()

    def test_mttd_returns_none_on_genuinely_empty_window(self):
        # Regression guard: a healthy ES with zero alerts must NOT be treated
        # as a measurement error — that would be a false alarm.
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertIsNone(slo_metrics.metric_mttd())

    def test_mttd_averages_real_hits_and_skips_bad_ones(self):
        hits = [
            # 10-minute detection delay
            {"_source": {"kibana.alert.start": "2026-01-01T00:10:00Z",
                          "kibana.alert.original_time": "2026-01-01T00:00:00Z"}},
            # 20-minute detection delay
            {"_source": {"kibana.alert.start": "2026-01-01T01:20:00Z",
                          "kibana.alert.original_time": "2026-01-01T01:00:00Z"}},
            # negative delta (clock skew) — must be skipped, not averaged in
            {"_source": {"kibana.alert.start": "2026-01-01T02:00:00Z",
                          "kibana.alert.original_time": "2026-01-01T02:30:00Z"}},
            # malformed timestamp — must be skipped, not raise
            {"_source": {"kibana.alert.start": "not-a-timestamp",
                          "kibana.alert.original_time": "2026-01-01T03:00:00Z"}},
        ]
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": hits}})):
            self.assertEqual(slo_metrics.metric_mttd(), 15.0)  # avg(10, 20)

    def test_mttr_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(500)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_mttr()

    def test_mttr_returns_none_on_empty_aggregation(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"aggregations": {"avg_lat": {}}})):
            self.assertIsNone(slo_metrics.metric_mttr())

    def test_coverage_raises_on_missing_file(self):
        with mock.patch.object(slo_metrics, "REPO", Path("/nonexistent-path-for-test")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_coverage()

    def test_coverage_returns_technique_count_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            coverage_path = repo / "docs" / "detections"
            coverage_path.mkdir(parents=True)
            (coverage_path / "attack-coverage.json").write_text(
                json.dumps({"techniques": ["T1110", "T1046", "T1078"]}), encoding="utf-8")
            with mock.patch.object(slo_metrics, "REPO", repo):
                self.assertEqual(slo_metrics.metric_coverage(), 3.0)

    def test_false_positive_pct_raises_on_kibana_failure(self):
        with mock.patch.object(slo_metrics, "kb", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_false_positive_pct()

    def test_false_positive_pct_computes_percentage_on_success(self):
        with mock.patch.object(slo_metrics, "kb", side_effect=[
            _FakeResponse(200, {"total": 20}),
            _FakeResponse(200, {"total": 4}),
        ]):
            self.assertEqual(slo_metrics.metric_false_positive_pct(), 20.0)

    def test_false_positive_pct_zero_total_returns_zero_not_division_error(self):
        with mock.patch.object(slo_metrics, "kb", side_effect=[
            _FakeResponse(200, {"total": 0}),
            _FakeResponse(200, {"total": 0}),
        ]):
            self.assertEqual(slo_metrics.metric_false_positive_pct(), 0.0)

    def test_parse_error_pct_computes_percentage_on_success(self):
        with mock.patch.object(slo_metrics, "_count", side_effect=[200, 2]):
            self.assertEqual(slo_metrics.metric_parse_error_pct(), 1.0)

    def test_parse_error_pct_zero_total_returns_zero_not_division_error(self):
        with mock.patch.object(slo_metrics, "_count", side_effect=[0, 0]):
            self.assertEqual(slo_metrics.metric_parse_error_pct(), 0.0)

    def test_ingest_lag_raises_on_request_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_ingest_lag_seconds()

    def test_ingest_lag_returns_none_when_no_docs_yet(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertIsNone(slo_metrics.metric_ingest_lag_seconds())

    def test_parse_error_pct_propagates_count_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_parse_error_pct()

    def test_audit_write_failures_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_audit_write_failures()

    def test_audit_write_failures_returns_count_on_success(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 5})):
            self.assertEqual(slo_metrics.metric_audit_write_failures(), 5)

    def test_audit_write_failures_returns_zero_when_healthy(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics.metric_audit_write_failures(), 0)

    # --- #247: stuck approval claims -----------------------------------------
    # A stuck claim is exactly a `phase: "CLAIMED"` doc older than the window —
    # since #247, both resolution paths (checkpoints.resolve_claim() on
    # success, release_claim() on a confirmed failure) transition the SAME
    # claim doc away from "CLAIMED", so a plain count needs no second lookup.
    def test_stuck_approval_claims_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_stuck_approval_claims()

    def test_stuck_approval_claims_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_stuck_approval_claims()

    def test_stuck_approval_claims_returns_count_on_success(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 3})):
            self.assertEqual(slo_metrics.metric_stuck_approval_claims(), 3)

    def test_stuck_approval_claims_returns_zero_when_healthy(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics.metric_stuck_approval_claims(), 0)

    def test_stuck_approval_claims_queries_only_claimed_phase_past_the_window(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})) as mock_es:
            slo_metrics.metric_stuck_approval_claims()
        query = mock_es.call_args[0][2]["query"]
        filters = query["bool"]["filter"]
        self.assertIn({"term": {"phase": "CLAIMED"}}, filters)
        self.assertTrue(any("range" in f and "@timestamp" in f["range"] for f in filters))
        index = mock_es.call_args[0][1]
        self.assertIn("agent-checkpoints-*", index)

    def test_stuck_approval_claims_window_is_configurable(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})) as mock_es, \
             mock.patch.dict(os.environ, {"SLO_STUCK_CLAIM_MAX_MIN": "45"}):
            slo_metrics.metric_stuck_approval_claims()
        query = mock_es.call_args[0][2]["query"]
        filters = query["bool"]["filter"]
        self.assertIn({"range": {"@timestamp": {"lte": "now-45m"}}}, filters)

    def test_stuck_approval_claims_invalid_window_raises_not_crashes(self):
        # A malformed override must degrade to THIS metric being unmeasurable,
        # not raise ValueError uncaught (which would silence every other
        # metric's ntfy alerting too — main()'s loop only catches
        # MetricUnavailable).
        with mock.patch.dict(os.environ, {"SLO_STUCK_CLAIM_MAX_MIN": "not-a-number"}):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_stuck_approval_claims()

    # --- #257: orphaned (claim-squatted) claims -------------------------------
    # A CLAIMED claim doc with no paired phase checkpoint, past the grace
    # window, is the claim-squatting signature (see metric_orphaned_claims()'s
    # docstring) — a two-step check (search, then a batched _mget), unlike
    # stuck_approval_claims' plain count. The join key comes from search-hit
    # metadata (_id/_index — ES-assigned, not attacker-writable), NEVER from
    # _source — see the HIGH-2/HIGH-3 security-auditor findings below.
    def test_orphaned_claims_raises_on_search_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_orphaned_claims()

    def test_orphaned_claims_raises_on_search_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_orphaned_claims()

    def test_orphaned_claims_returns_zero_when_no_claims_open(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 0)

    def test_orphaned_claims_returns_zero_when_every_claim_is_paired(self):
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": True}]})
        with mock.patch.object(slo_metrics, "es", side_effect=[search_resp, mget_resp]):
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 0)

    def test_orphaned_claims_counts_unpaired_claims_as_orphaned(self):
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
            {"_index": "agent-checkpoints-home-smith", "_id": "def456.claim"},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": False}, {"found": True}]})
        with mock.patch.object(slo_metrics, "es", side_effect=[search_resp, mget_resp]):
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 1)

    def test_orphaned_claims_skips_hits_whose_id_is_not_a_claim_doc(self):
        # Anything at phase:CLAIMED whose _id doesn't end ".claim" is itself
        # an anomalous shape (nothing in checkpoints.py produces it) — must
        # not crash or get silently paired against the wrong doc.
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123"},  # no .claim suffix
        ]}})
        with mock.patch.object(slo_metrics, "es", return_value=search_resp) as mock_es:
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 0)
        # No docs_to_check means no mget round-trip at all.
        self.assertEqual(mock_es.call_count, 1)

    def test_orphaned_claims_skips_degenerate_claim_only_id(self):
        # security-auditor catch: an _id of exactly ".claim" strips to an
        # empty base id — building an _mget target of _id="" could 400 the
        # whole batch on some ES versions, blinding the metric entirely off
        # one crafted doc. Must be excluded, same as a non-.claim _id.
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": ".claim"},
        ]}})
        with mock.patch.object(slo_metrics, "es", return_value=search_resp) as mock_es:
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 0)
        self.assertEqual(mock_es.call_count, 1)

    def test_orphaned_claims_ignores_source_entirely_no_crash_on_malformed_shape(self):
        # security-auditor HIGH-2: an earlier version derived the join key
        # from _source (tenant.id/alert_id), which crashed with an
        # AttributeError — uncaught by main()'s MetricUnavailable-only
        # catch — on a malformed shape like tenant:null. The fixed version
        # never reads _source at all (the query even sets _source:False),
        # so a malformed/missing _source must have zero effect.
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim",
             "_source": {"tenant": None, "alert_id": ["not", "a", "string"]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": False}]})
        with mock.patch.object(slo_metrics, "es", side_effect=[search_resp, mget_resp]):
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 1)

    def test_orphaned_claims_ignores_forged_source_self_reference_evasion(self):
        # security-auditor HIGH-3: an earlier version trusted _source.
        # alert_id/tenant as the mget target — a squatter controlling the
        # document body could point the pairing check at their OWN claim
        # doc (or an unrelated victim's real checkpoint) and evade detection
        # (found: true, count 0) even though no real paired phase doc
        # exists. The fixed version derives the target purely from this
        # hit's own _id/_index, so a forged _source claiming to be paired
        # with itself must NOT suppress the orphaned count.
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim",
             "_source": {"alert_id": "abc123.claim", "tenant": {"id": "home-smith"}}},
        ]}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[search_resp, _FakeResponse(200, {"docs": [{"found": False}]})]) \
                as mock_es:
            self.assertEqual(slo_metrics.metric_orphaned_claims(), 1)
        # The real target must be the _id-derived "abc123" (stripped
        # suffix), never the forged _source.alert_id value.
        mget_body = mock_es.call_args_list[1][0][2]
        self.assertEqual(mget_body["docs"],
                          [{"_index": "agent-checkpoints-home-smith", "_id": "abc123"}])

    def test_orphaned_claims_raises_on_mget_non_200(self):
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
        ]}})
        with mock.patch.object(slo_metrics, "es", side_effect=[search_resp, _FakeResponse(500)]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_orphaned_claims()

    def test_orphaned_claims_raises_on_mget_failure(self):
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
        ]}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[search_resp, ConnectionError("refused")]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_orphaned_claims()

    def test_orphaned_claims_queries_only_claimed_phase_past_the_window(self):
        with mock.patch.object(
                slo_metrics, "es",
                return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es:
            slo_metrics.metric_orphaned_claims()
        body = mock_es.call_args[0][2]
        filters = body["query"]["bool"]["filter"]
        self.assertIn({"term": {"phase": "CLAIMED"}}, filters)
        self.assertTrue(any("range" in f and "@timestamp" in f["range"] for f in filters))
        index = mock_es.call_args[0][1]
        self.assertIn("agent-checkpoints-*", index)
        # HIGH-2/HIGH-3 fix: never request _source for this search.
        self.assertEqual(body.get("_source"), False)
        # LOW-4/LOW-D fix: oldest-first with unmapped_type so a 200-cap
        # truncation drops newest first, and one unmapped index can't 400
        # the whole multi-index search.
        self.assertEqual(body.get("sort"),
                          [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}])

    def test_orphaned_claims_window_is_configurable(self):
        with mock.patch.object(
                slo_metrics, "es",
                return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es, \
             mock.patch.dict(os.environ, {"SLO_ORPHANED_CLAIM_MAX_MIN": "20"}):
            slo_metrics.metric_orphaned_claims()
        query = mock_es.call_args[0][2]["query"]
        filters = query["bool"]["filter"]
        self.assertIn({"range": {"@timestamp": {"lte": "now-20m"}}}, filters)

    def test_orphaned_claims_invalid_window_raises_not_crashes(self):
        with mock.patch.dict(os.environ, {"SLO_ORPHANED_CLAIM_MAX_MIN": "not-a-number"}):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_orphaned_claims()

    def test_orphaned_claims_mget_targets_same_index_with_claim_suffix_stripped(self):
        search_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": True}]})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[search_resp, mget_resp]) as mock_es:
            slo_metrics.metric_orphaned_claims()
        mget_body = mock_es.call_args_list[1][0][2]
        self.assertEqual(mget_body["docs"],
                          [{"_index": "agent-checkpoints-home-smith", "_id": "abc123"}])

    # #361: agent_checkpoints_compactor (live since #357) can delete a CLAIMED
    # doc directly, bypassing checkpoints.py's own phase-transition-only API.
    # metric_vanished_claims() diffs the PRIOR sample's claimed_snapshot
    # (persisted by _claimed_snapshot()/main()) against a fresh _mget — a
    # doc that's gone now (found: false) is the tamper signature; a doc
    # that's still there, just resolved (found: true), is normal operation.
    #
    # security-auditor + code-reviewer review (both independently converged
    # on the same root cause): Elasticsearch's `exists` query does not match
    # a field indexed as `[]`, so keying the prior-sample lookup on
    # claimed_snapshot itself silently skipped every quiet run — fixed by
    # keying on the always-non-empty claimed_snapshot_at instead, age-bounded
    # both directions (not too old, not future-dated) against forging.

    def test_vanished_claims_raises_on_prior_sample_search_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_vanished_claims()

    def test_vanished_claims_raises_on_prior_sample_search_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_vanished_claims()

    def test_vanished_claims_returns_zero_on_first_run_no_prior_doc(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es:
            self.assertEqual(slo_metrics.metric_vanished_claims(), 0)
        # No prior snapshot means nothing to _mget — one round-trip only.
        self.assertEqual(mock_es.call_count, 1)

    def test_vanished_claims_returns_zero_when_prior_snapshot_was_genuinely_empty(self):
        # A prior doc DOES exist (claimed_snapshot_at makes it visible to the
        # exists filter) but its claimed_snapshot array is empty — a quiet
        # run with nothing open, not a missing baseline.
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": []}},
        ]}})
        with mock.patch.object(slo_metrics, "es", return_value=prior_resp) as mock_es:
            self.assertEqual(slo_metrics.metric_vanished_claims(), 0)
        self.assertEqual(mock_es.call_count, 1)

    def test_vanished_claims_counts_a_doc_that_no_longer_exists(self):
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            ]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": False}]})
        with mock.patch.object(slo_metrics, "es", side_effect=[prior_resp, mget_resp]):
            self.assertEqual(slo_metrics.metric_vanished_claims(), 1)

    def test_vanished_claims_does_not_count_a_doc_that_still_exists(self):
        # Still exists = resolved in place (RESOLVED/RELEASED) or still
        # CLAIMED — either way, checkpoints.py's own API never deletes it.
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            ]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": True}]})
        with mock.patch.object(slo_metrics, "es", side_effect=[prior_resp, mget_resp]):
            self.assertEqual(slo_metrics.metric_vanished_claims(), 0)

    def test_vanished_claims_mget_targets_derived_from_prior_snapshot(self):
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
                {"index": "agent-checkpoints-home-jones", "id": "def456.claim"},
            ]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": False}, {"found": False}]})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[prior_resp, mget_resp]) as mock_es:
            self.assertEqual(slo_metrics.metric_vanished_claims(), 2)
        mget_body = mock_es.call_args_list[1][0][2]
        self.assertEqual(mget_body["docs"], [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"},
            {"_index": "agent-checkpoints-home-jones", "_id": "def456.claim"},
        ])

    def test_vanished_claims_raises_on_mget_non_200(self):
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            ]}},
        ]}})
        with mock.patch.object(slo_metrics, "es", side_effect=[prior_resp, _FakeResponse(500)]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_vanished_claims()

    def test_vanished_claims_raises_on_mget_failure(self):
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            ]}},
        ]}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[prior_resp, ConnectionError("refused")]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_vanished_claims()

    def test_vanished_claims_raises_not_counts_on_per_doc_mget_error(self):
        # security-auditor MEDIUM: a whole tenant index gone (or otherwise
        # unreadable) surfaces as an `error` object with no `found` key on
        # that _mget entry — "could not determine" must not silently count
        # as "confirmed vanished".
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            ]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [
            {"error": {"type": "index_not_found_exception"}},
        ]})
        with mock.patch.object(slo_metrics, "es", side_effect=[prior_resp, mget_resp]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_vanished_claims()

    def test_vanished_claims_prior_sample_query_shape(self):
        with mock.patch.object(
                slo_metrics, "es",
                return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es:
            slo_metrics.metric_vanished_claims()
        path = mock_es.call_args[0][1]
        body = mock_es.call_args[0][2]
        self.assertIn("soc-slo-metrics", path)
        self.assertIn("ignore_unavailable=true", path)
        filters = body["query"]["bool"]["filter"]
        self.assertIn({"exists": {"field": "claimed_snapshot_at"}}, filters)
        self.assertTrue(any(
            "range" in f and "claimed_snapshot_at" in f["range"] for f in filters))
        range_filter = next(f["range"]["claimed_snapshot_at"] for f in filters if "range" in f)
        self.assertEqual(range_filter.get("lte"), "now")
        self.assertIn("gte", range_filter)
        self.assertEqual(body["sort"], [{"@timestamp": "desc"}])
        self.assertEqual(body["size"], 1)

    def test_vanished_claims_baseline_window_is_configurable(self):
        with mock.patch.object(
                slo_metrics, "es",
                return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es, \
             mock.patch.object(slo_metrics, "SLO_VANISHED_CLAIM_BASELINE_MAX_AGE_MIN", 60.0):
            slo_metrics.metric_vanished_claims()
        body = mock_es.call_args[0][2]
        filters = body["query"]["bool"]["filter"]
        range_filter = next(f["range"]["claimed_snapshot_at"] for f in filters if "range" in f)
        self.assertEqual(range_filter["gte"], "now-60m")

    def test_vanished_claims_drops_malformed_prior_entries_before_mget(self):
        # security-auditor MEDIUM (baseline poisoning): a soc-slo-metrics
        # writer other than the compactor (slo_metrics_reader's own `create`
        # grant, or soc_admin) could shape claimed_snapshot arbitrarily —
        # only entries matching exactly what _claimed_snapshot() itself
        # produces may reach a real _mget request body.
        prior_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_source": {"claimed_snapshot": [
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},  # valid
                {"index": "agent-checkpoints-home-smith", "id": "abc123"},  # no .claim suffix
                {"index": "some-other-index", "id": "abc123.claim"},  # wrong index namespace
                {"index": "agent-checkpoints-home-smith", "id": "abc123.claim",
                 "routing": "attacker-controlled"},  # extra key
                "not-a-dict",
                {"id": "abc123.claim"},  # missing index
            ]}},
        ]}})
        mget_resp = _FakeResponse(200, {"docs": [{"found": False}]})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[prior_resp, mget_resp]) as mock_es:
            self.assertEqual(slo_metrics.metric_vanished_claims(), 1)
        mget_body = mock_es.call_args_list[1][0][2]
        self.assertEqual(mget_body["docs"],
                          [{"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim"}])

    # _claimed_snapshot() now runs TWO independent searches (CLAIMED
    # asc-sorted, then RESOLVED desc-sorted — see its docstring on why the
    # sort orders differ) and concatenates their hits. Tests below use
    # side_effect=[claimed_resp, resolved_resp] to target each call
    # individually; call_args_list[0]/[1] correspond to CLAIMED/RESOLVED
    # respectively, matching the function's own call order.

    def test_claimed_snapshot_raises_if_claimed_search_fails(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._claimed_snapshot()

    def test_claimed_snapshot_raises_if_claimed_search_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(503)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._claimed_snapshot()

    def test_claimed_snapshot_raises_if_resolved_search_fails(self):
        # The CLAIMED leg succeeds; only the second (RESOLVED) call fails —
        # must still surface as MetricUnavailable, not a partial result.
        claimed_resp = _FakeResponse(200, {"hits": {"hits": []}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[claimed_resp, ConnectionError("refused")]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._claimed_snapshot()

    def test_claimed_snapshot_raises_if_resolved_search_non_200(self):
        claimed_resp = _FakeResponse(200, {"hits": {"hits": []}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[claimed_resp, _FakeResponse(503)]):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics._claimed_snapshot()

    def test_claimed_snapshot_combines_claimed_and_resolved_hits(self):
        claimed_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-smith", "_id": "abc123.claim",
             "_source": {"alert_id": "abc123", "tenant": {"id": "home-smith"}}},
        ]}})
        resolved_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_index": "agent-checkpoints-home-jones", "_id": "def456.claim"},
        ]}})
        with mock.patch.object(slo_metrics, "es",
                               side_effect=[claimed_resp, resolved_resp]) as mock_es:
            result = slo_metrics._claimed_snapshot()
        # Deliberately "index"/"id", not "_index"/"_id" — see the
        # function's own docstring on why (ES metadata-field-name risk).
        self.assertEqual(result, [
            {"index": "agent-checkpoints-home-smith", "id": "abc123.claim"},
            {"index": "agent-checkpoints-home-jones", "id": "def456.claim"},
        ])
        claimed_body = mock_es.call_args_list[0][0][2]
        resolved_body = mock_es.call_args_list[1][0][2]
        self.assertEqual(claimed_body["query"],
                          {"bool": {"filter": [{"term": {"phase": "CLAIMED"}}]}})
        self.assertEqual(resolved_body["query"],
                          {"bool": {"filter": [{"term": {"phase": "RESOLVED"}}]}})
        self.assertEqual(claimed_body.get("_source"), False)
        self.assertEqual(resolved_body.get("_source"), False)

    def test_claimed_snapshot_returns_empty_list_when_nothing_open_or_resolved(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"hits": {"hits": []}})):
            self.assertEqual(slo_metrics._claimed_snapshot(), [])

    def test_claimed_snapshot_query_shape_and_opposite_sort_orders(self):
        with mock.patch.object(
                slo_metrics, "es",
                return_value=_FakeResponse(200, {"hits": {"hits": []}})) as mock_es:
            slo_metrics._claimed_snapshot()
        self.assertEqual(mock_es.call_count, 2)
        claimed_index, claimed_body = mock_es.call_args_list[0][0][1], mock_es.call_args_list[0][0][2]
        resolved_index, resolved_body = mock_es.call_args_list[1][0][1], mock_es.call_args_list[1][0][2]
        self.assertIn("agent-checkpoints-*", claimed_index)
        self.assertIn("agent-checkpoints-*", resolved_index)
        self.assertEqual(claimed_body["size"], 200)
        self.assertEqual(resolved_body["size"], 200)
        # CLAIMED: oldest-first (a long-open claim is the suspicious one to
        # keep). RESOLVED: newest-first (that population never shrinks, so
        # oldest-first would starve out newly-resolved coverage — see the
        # function's own docstring).
        self.assertEqual(claimed_body["sort"],
                          [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}])
        self.assertEqual(resolved_body["sort"],
                          [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}])

    def test_claimed_snapshot_skips_hits_missing_index_or_id_metadata(self):
        claimed_resp = _FakeResponse(200, {"hits": {"hits": [
            {"_id": "abc123.claim"},  # missing _index
            {"_index": "agent-checkpoints-home-smith"},  # missing _id
            {"_index": "agent-checkpoints-home-smith", "_id": "def456.claim"},
        ]}})
        resolved_resp = _FakeResponse(200, {"hits": {"hits": []}})
        with mock.patch.object(slo_metrics, "es", side_effect=[claimed_resp, resolved_resp]):
            result = slo_metrics._claimed_snapshot()
        self.assertEqual(result, [{"index": "agent-checkpoints-home-smith", "id": "def456.claim"}])

    def test_raw_alert_volume_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_raw_alert_volume()

    def test_raw_alert_volume_sums_zeek_notices_and_rule_hits(self):
        # First _count() call is logstash-security-* (Zeek notices), second is
        # .alerts-security.alerts-* (Sigma/Elastic rule hits) — same call order
        # as the function body. Sub-counts stay visible, not just their sum
        # (#216 review: collapsing them hides which side moved).
        with mock.patch.object(slo_metrics, "_count", side_effect=[7, 3]):
            result = slo_metrics.metric_raw_alert_volume()
        self.assertEqual(result, {"zeek_notices": 7, "rule_hits": 3, "value": 10})

    def test_raw_alert_volume_returns_zero_when_healthy_and_quiet(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            result = slo_metrics.metric_raw_alert_volume()
        self.assertEqual(result, {"zeek_notices": 0, "rule_hits": 0, "value": 0})

    def test_raw_alert_volume_rule_hits_query_is_strict(self):
        # #216 review: .alerts-security.alerts-* should always exist once
        # Kibana's Security app has initialized, so its count is queried
        # strict (allow_no_indices=false) - a missing/unresolvable pattern is
        # a real problem, not a benign "no alerts yet" the way an idle
        # tenant's logstash-security-* legitimately can be.
        with mock.patch.object(slo_metrics, "_count", side_effect=[0, 0]) as mock_count:
            slo_metrics.metric_raw_alert_volume()
        zeek_call, rule_call = mock_count.call_args_list
        self.assertNotIn("strict", zeek_call.kwargs)
        self.assertTrue(rule_call.kwargs.get("strict"))
        # Excludes the parse-failure quarantine index from the Zeek half —
        # it can carry the same threat.technique.id tag.
        self.assertIn("-logstash-security-quarantine-*", zeek_call.args[0])

    # --- #252: field truncation count -----------------------------------------
    def test_field_truncation_count_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_field_truncation_count()

    def test_field_truncation_count_returns_count_on_success(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 4})):
            self.assertEqual(slo_metrics.metric_field_truncation_count(), 4)

    def test_field_truncation_count_returns_zero_when_no_truncation_seen(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics.metric_field_truncation_count(), 0)

    def test_field_truncation_count_queries_pipeline_truncated_tag(self):
        with mock.patch.object(slo_metrics, "_count", return_value=0) as mock_count:
            slo_metrics.metric_field_truncation_count()
        index, query = mock_count.call_args[0]
        self.assertIn("logstash-security-*", index)
        self.assertIn({"term": {"pipeline.truncated": "true"}}, query["bool"]["filter"])

    # --- #263: field byte-clamp count -------------------------------------
    def test_field_byte_clamp_count_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_field_byte_clamp_count()

    def test_field_byte_clamp_count_returns_count_on_success(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 2})):
            self.assertEqual(slo_metrics.metric_field_byte_clamp_count(), 2)

    def test_field_byte_clamp_count_returns_zero_when_no_clamp_seen(self):
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"count": 0})):
            self.assertEqual(slo_metrics.metric_field_byte_clamp_count(), 0)

    def test_field_byte_clamp_count_queries_pipeline_byte_clamped_tag(self):
        with mock.patch.object(slo_metrics, "_count", return_value=0) as mock_count:
            slo_metrics.metric_field_byte_clamp_count()
        index, query = mock_count.call_args[0]
        self.assertIn("logstash-security-*", index)
        self.assertIn({"term": {"pipeline.byte_clamped": "true"}}, query["bool"]["filter"])

    # --- #288: capture-loss max percent -----------------------------------
    def test_capture_loss_percent_raises_on_non_200(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(500)):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_capture_loss_percent()

    def test_capture_loss_percent_raises_on_es_failure(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_capture_loss_percent()

    def test_capture_loss_percent_returns_none_on_empty_aggregation(self):
        # No capture_loss.log docs in the window yet (sensor hasn't hit a
        # watch_interval, or the @load hasn't rolled out to a running
        # capture) — a real "no data yet" case, not a measurement error.
        with mock.patch.object(slo_metrics, "es",
                               return_value=_FakeResponse(200, {"aggregations": {"max_loss": {}}})):
            self.assertIsNone(slo_metrics.metric_capture_loss_percent())

    def test_capture_loss_percent_returns_value_on_success(self):
        with mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(
                200, {"aggregations": {"max_loss": {"value": 2.5}}})):
            self.assertEqual(slo_metrics.metric_capture_loss_percent(), 2.5)

    def test_capture_loss_percent_queries_capture_loss_dataset_and_field(self):
        captured = {}

        def fake_es(method, path, body=None):
            captured["path"] = path
            captured["body"] = body
            # A real aggregation value, not an empty {} — the {} case exercises
            # the zeek-liveness fallback path (a SECOND es() call, see the
            # tests below), which would overwrite `captured` before this
            # test gets to inspect the query it actually cares about.
            return _FakeResponse(200, {"aggregations": {"max_loss": {"value": 1.0}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es):
            slo_metrics.metric_capture_loss_percent()
        self.assertEqual(captured["path"], "/logstash-security-*/_search")
        self.assertIn({"term": {"event.dataset": "zeek.capture_loss"}},
                      captured["body"]["query"]["bool"]["filter"])
        self.assertEqual(captured["body"]["aggs"]["max_loss"]["max"]["field"], "percent_lost")

    def test_capture_loss_percent_uses_own_window_not_shared_window(self):
        # security-auditor review: this metric must NOT inherit the shared
        # module-level WINDOW (default now-7d) — a max aggregation over a
        # long window combined with a 15-min poll would pin a single
        # transient spike in breach for hundreds of consecutive runs. Must
        # default to something short, and be independently overridable.
        # code-reviewer follow-up: assert the DECOUPLING from WINDOW, not
        # the literal default value — hardcoding "now-1h" here would break
        # for anyone who actually uses the documented SLO_CAPTURE_LOSS_
        # WINDOW override this test exists to protect.
        captured = {}

        def fake_es(method, path, body=None):
            captured["body"] = body
            return _FakeResponse(200, {"aggregations": {"max_loss": {"value": 1.0}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es), \
             mock.patch.object(slo_metrics, "WINDOW", "now-7d"), \
             mock.patch.dict(os.environ, {"SLO_CAPTURE_LOSS_WINDOW": "now-45m"}):
            slo_metrics.metric_capture_loss_percent()
        gte = captured["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
        self.assertNotEqual(gte, "now-7d")
        self.assertEqual(gte, "now-45m")

    def test_capture_loss_percent_returns_none_when_no_zeek_data_at_all(self):
        # Genuinely benign: nothing Zeek-sourced in the window yet (fresh
        # deployment, sensor hasn't hit a watch_interval) — not an error.
        def fake_es(method, path, body=None):
            if path.endswith("/_count"):
                return _FakeResponse(200, {"count": 0})
            return _FakeResponse(200, {"aggregations": {"max_loss": {}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es):
            self.assertIsNone(slo_metrics.metric_capture_loss_percent())

    def test_capture_loss_percent_raises_when_zeek_flows_but_no_capture_loss_docs(self):
        # security-auditor review: distinguishes "no Zeek data at all"
        # (benign) from "Zeek is flowing but capture-loss reporting itself
        # died" (a real failure metric_ingest_lag_seconds cannot see, since
        # other Zeek/endpoint telemetry keeps ingest lag looking healthy).
        def fake_es(method, path, body=None):
            if path.endswith("/_count"):
                return _FakeResponse(200, {"count": 42})
            return _FakeResponse(200, {"aggregations": {"max_loss": {}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_capture_loss_percent()

    def test_capture_loss_percent_liveness_check_requires_stale_zeek_data(self):
        # security-auditor follow-up (MEDIUM): an unqualified "any Zeek doc
        # in the window" liveness check false-triggers on offline PCAP
        # replay, a short manual stream_capture.sh session, and the first
        # run after a fresh deploy — none run long enough to reach even one
        # CaptureLoss::watch_interval. The fallback _count query must
        # require the Zeek data to predate now-30m before treating its
        # absence as suspicious, not just filter on event.module:zeek alone.
        captured = {}

        def fake_es(method, path, body=None):
            if path.endswith("/_count"):
                captured["count_body"] = body
                return _FakeResponse(200, {"count": 1})
            return _FakeResponse(200, {"aggregations": {"max_loss": {}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es):
            with self.assertRaises(slo_metrics.MetricUnavailable):
                slo_metrics.metric_capture_loss_percent()
        filters = captured["count_body"]["query"]["bool"]["filter"]
        self.assertIn({"term": {"event.module": "zeek"}}, filters)
        self.assertIn({"range": {"@timestamp": {"lte": "now-30m"}}}, filters)


class EsKbWrapperTests(unittest.TestCase):
    """Cover the real es()/kb() request wrappers — every test above mocks them
    out entirely, so their own bodies (SESSION.request/get plumbing) were
    otherwise never exercised."""

    def test_es_wrapper_calls_session_request(self):
        with mock.patch.object(slo_metrics.SESSION, "request",
                               return_value=_FakeResponse(200, {"ok": True})) as m:
            r = slo_metrics.es("POST", "/some-index/_search", {"query": {}})
        m.assert_called_once()
        args, kwargs = m.call_args
        self.assertEqual(args[0], "POST")
        self.assertTrue(args[1].endswith("/some-index/_search"))
        self.assertEqual(kwargs["data"], json.dumps({"query": {}}))
        self.assertEqual(r.json(), {"ok": True})

    def test_kb_wrapper_calls_session_get(self):
        with mock.patch.object(slo_metrics.SESSION, "get",
                               return_value=_FakeResponse(200, {"total": 5})) as m:
            r = slo_metrics.kb("/api/cases/_find")
        m.assert_called_once()
        self.assertEqual(r.json(), {"total": 5})


class MainExitCodeTests(unittest.TestCase):
    """End-to-end: main() must exit 3 (not the routine breach code 2) when a
    metric could not be measured, and must still behave exactly as before for
    a genuinely healthy, quiet system."""

    def _run_main_capturing_exit(self):
        try:
            slo_metrics.main()
        except SystemExit as e:
            return e.code
        return None

    def test_total_es_outage_exits_3_not_2(self):
        with mock.patch.object(slo_metrics, "es", side_effect=ConnectionError("refused")), \
             mock.patch.object(slo_metrics, "kb", side_effect=ConnectionError("refused")), \
             mock.patch.object(slo_metrics, "metric_coverage",
                               side_effect=slo_metrics.MetricUnavailable("no file")), \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)

    def test_healthy_quiet_system_exits_0(self):
        # Fresh ingest doc (healthy pipeline) but otherwise empty windows —
        # the pre-#165 baseline behavior for a quiet, working SOC.
        import datetime as _dt
        now_iso = _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")

        def fake_es(method, path, body=None):
            if path == "/logstash-security-*/_search":
                return _FakeResponse(200, {"hits": {"hits": [{"_source": {"@timestamp": now_iso}}]}})
            return _FakeResponse(200, {"hits": {"hits": []}, "aggregations": {"avg_lat": {}}})

        with mock.patch.object(slo_metrics, "es", side_effect=fake_es), \
             mock.patch.object(slo_metrics, "kb", return_value=_FakeResponse(200, {"total": 0})), \
             mock.patch.object(slo_metrics, "metric_coverage", return_value=105.0), \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def _mock_all_metrics(self, mttd=0.0, mttr=0.0, coverage=12.0, fp_pct=0.0,
                           ingest_lag=10.0, parse_err=0.0, audit_write_failures=0.0,
                           orphaned_claims=0.0, vanished_claims=0.0, raw_alert_volume=None,
                           field_truncation_count=0, field_byte_clamp_count=0,
                           capture_loss_max_pct=0.0):
        if raw_alert_volume is None:
            raw_alert_volume = {"zeek_notices": 0, "rule_hits": 0, "value": 0}
        return [
            mock.patch.object(slo_metrics, "metric_mttd", return_value=mttd),
            mock.patch.object(slo_metrics, "metric_mttr", return_value=mttr),
            mock.patch.object(slo_metrics, "metric_coverage", return_value=coverage),
            mock.patch.object(slo_metrics, "metric_false_positive_pct", return_value=fp_pct),
            mock.patch.object(slo_metrics, "metric_ingest_lag_seconds", return_value=ingest_lag),
            mock.patch.object(slo_metrics, "metric_parse_error_pct", return_value=parse_err),
            mock.patch.object(slo_metrics, "metric_audit_write_failures",
                               return_value=audit_write_failures),
            mock.patch.object(slo_metrics, "metric_orphaned_claims",
                               return_value=orphaned_claims),
            mock.patch.object(slo_metrics, "metric_vanished_claims",
                               return_value=vanished_claims),
            mock.patch.object(slo_metrics, "metric_raw_alert_volume",
                               return_value=raw_alert_volume),
            mock.patch.object(slo_metrics, "metric_field_truncation_count",
                               return_value=field_truncation_count),
            mock.patch.object(slo_metrics, "metric_field_byte_clamp_count",
                               return_value=field_byte_clamp_count),
            mock.patch.object(slo_metrics, "metric_capture_loss_percent",
                               return_value=capture_loss_max_pct),
            mock.patch.object(slo_metrics, "es", return_value=_FakeResponse(200, {})),
        ]

    def test_breach_detected_exits_2_and_sends_ntfy(self):
        # mttd_minutes=999 blows through its <=30min target -> a real breach,
        # everything else healthy.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(mttd=999.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        ntfy_post.assert_called_once()
        self.assertIn("mttd_minutes", ntfy_post.call_args.kwargs["data"].decode())

    def test_orphaned_claims_breach_exits_2_and_sends_ntfy(self):
        # Regression guard for #257: metric_orphaned_claims must actually be
        # wired into main()'s metric_fns dict, not just defined — a defined-
        # but-unregistered metric would silently never breach regardless of
        # its value, exactly like stuck_approval_claims before #247's fix.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(orphaned_claims=1.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        ntfy_post.assert_called_once()
        self.assertIn("orphaned_claims", ntfy_post.call_args.kwargs["data"].decode())

    def test_vanished_claims_breach_exits_2_and_sends_ntfy(self):
        # Regression guard for #361: metric_vanished_claims must actually be
        # wired into main()'s metric_fns dict, not just defined — same bug
        # shape #216/#247/#257/#288 already guard other metrics against.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(vanished_claims=1.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        ntfy_post.assert_called_once()
        self.assertIn("vanished_claims", ntfy_post.call_args.kwargs["data"].decode())

    def test_audit_write_failures_below_threshold_does_not_breach(self):
        # coverage pinned to the real env's SLO_COVERAGE_MIN (105-rule
        # corpus) rather than _mock_all_metrics' default 12.0 — that default
        # predates the corpus growing past M12 and trips an unrelated
        # breach in this environment regardless of this test's own subject
        # (same pre-existing gap the field_truncation_count/
        # field_byte_clamp_count NO_TARGET tests already work around).
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(audit_write_failures=2.0, coverage=105.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_audit_write_failures_at_threshold_breaches(self):
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(audit_write_failures=3.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        self.assertIn("audit_write_failures", ntfy_post.call_args.kwargs["data"].decode())

    def test_capture_loss_below_threshold_does_not_breach(self):
        # coverage pinned to the real env's SLO_COVERAGE_MIN, same
        # pre-existing reason as test_audit_write_failures_below_threshold_
        # does_not_breach above.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(capture_loss_max_pct=4.9, coverage=105.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_capture_loss_over_threshold_breaches(self):
        # Regression guard for #288: metric_capture_loss_percent must
        # actually be wired into main()'s metric_fns dict, not just
        # defined — same bug shape #216/#247/#257 already guard other
        # metrics against.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics(capture_loss_max_pct=12.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)
        ntfy_post.assert_called_once()
        self.assertIn("capture_loss_max_pct", ntfy_post.call_args.kwargs["data"].decode())

    def test_raw_alert_volume_never_breaches_regardless_of_value(self):
        # #216: NO_TARGET means this is measured but never checked against a
        # threshold — an arbitrarily large value must not trip a breach.
        # coverage pinned to the real env's SLO_COVERAGE_MIN for the same
        # pre-existing reason as test_audit_write_failures_below_threshold_
        # does_not_breach above.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(
                    raw_alert_volume={"zeek_notices": 500000, "rule_hits": 499999,
                                       "value": 999999},
                    coverage=105.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_raw_alert_volume_unmeasurable_is_never_silent(self):
        # #216 review (MEDIUM): a NO_TARGET metric's failure used to leave
        # doc["status"]="ok" and send no ntfy, since only `breaches` gated
        # both — a real regression of the "measurement failure is never
        # silently healthy" invariant every other metric already honors.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics():
                stack.enter_context(p)
            stack.enter_context(mock.patch.object(
                slo_metrics, "metric_raw_alert_volume",
                side_effect=slo_metrics.MetricUnavailable("es down")))
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)
        ntfy_post.assert_called_once()
        self.assertIn("raw_alert_volume", ntfy_post.call_args.kwargs["data"].decode())

    def test_field_truncation_count_never_breaches_regardless_of_value(self):
        # #252: NO_TARGET, same as raw_alert_volume — a large count is a
        # baseline signal for whether the 32766 ceiling (#263) needs
        # revisiting, not a threshold breach. coverage is pinned to the real env's
        # SLO_COVERAGE_MIN (105-rule corpus) rather than _mock_all_metrics'
        # default 12.0 — that default predates the corpus growing past M12
        # and trips an unrelated breach in this environment regardless of
        # this test's own subject (same pre-existing gap
        # test_raw_alert_volume_never_breaches_regardless_of_value has).
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(field_truncation_count=500, coverage=105.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_field_truncation_count_unmeasurable_is_never_silent(self):
        # Regression guard: metric_field_truncation_count must actually be
        # wired into main()'s metric_fns dict, not just defined — an
        # unregistered metric would never surface a measurement failure,
        # same failure shape #216 found for raw_alert_volume.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics():
                stack.enter_context(p)
            stack.enter_context(mock.patch.object(
                slo_metrics, "metric_field_truncation_count",
                side_effect=slo_metrics.MetricUnavailable("es down")))
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)
        ntfy_post.assert_called_once()
        self.assertIn("field_truncation_count", ntfy_post.call_args.kwargs["data"].decode())

    def test_field_byte_clamp_count_never_breaches_regardless_of_value(self):
        # #263: NO_TARGET, same reasoning as field_truncation_count — no real
        # data yet to justify a specific breach threshold rather than a
        # guessed one, even though any nonzero count is worth investigating
        # manually. coverage pinned to the real env's SLO_COVERAGE_MIN for
        # the same pre-existing reason as the sibling test above.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(field_byte_clamp_count=500, coverage=105.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def test_field_byte_clamp_count_unmeasurable_is_never_silent(self):
        # Regression guard: metric_field_byte_clamp_count must actually be
        # wired into main()'s metric_fns dict, not just defined.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post") as ntfy_post:
            for p in self._mock_all_metrics():
                stack.enter_context(p)
            stack.enter_context(mock.patch.object(
                slo_metrics, "metric_field_byte_clamp_count",
                side_effect=slo_metrics.MetricUnavailable("es down")))
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 3)
        ntfy_post.assert_called_once()
        self.assertIn("field_byte_clamp_count", ntfy_post.call_args.kwargs["data"].decode())

    def test_ntfy_failure_is_swallowed_not_fatal(self):
        # A downed ntfy.sh must not crash main() or change the breach exit code.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(slo_metrics.requests, "post",
                               side_effect=ConnectionError("refused")):
            for p in self._mock_all_metrics(mttd=999.0):
                stack.enter_context(p)
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 2)


class SloMetricsReaderRoleGrantTests(unittest.TestCase):
    """#275: every index pattern a metric_*() function queries via _count()/es()
    must have a matching read grant in the slo_metrics_reader role, in BOTH the
    authoritative role file and docker-compose.yml's inline provisioning copy —
    or the query silently returns a healthy-looking empty result rather than
    erroring (see metric_audit_write_failures()'s docstring for the live-
    verified finding this test exists to guard against). This codebase has no
    live self-check for this today (a future one could use Elasticsearch's own
    POST /_security/user/_has_privileges, not exercised here — untested, and
    out of scope for this fix), so this static check is the actual regression
    guard for the specific soc-agent-health-* bug this issue fixed, and for
    any future metric that queries a new index pattern without also granting
    it here."""

    ROLE_PATH = slo_metrics.REPO / "configs" / "elasticsearch" / "roles" / "slo_metrics_reader.json"
    COMPOSE_PATH = slo_metrics.REPO / "scripts" / "setup" / "docker-compose.yml"

    def _granted_patterns(self) -> set:
        role = json.loads(self.ROLE_PATH.read_text(encoding="utf-8"))
        return {name for entry in role["indices"] for name in entry["names"]}

    def _granted_privileges(self, pattern: str) -> set:
        role = json.loads(self.ROLE_PATH.read_text(encoding="utf-8"))
        for entry in role["indices"]:
            if pattern in entry["names"]:
                return set(entry["privileges"])
        return set()

    def test_role_file_grants_soc_agent_health(self):
        self.assertIn("soc-agent-health-*", self._granted_patterns(),
                       "slo_metrics_reader.json is missing the soc-agent-health-* "
                       "read grant metric_audit_write_failures() needs (#275 "
                       "regression: this bug produces no runtime error, only a "
                       "silently-wrong healthy reading)")

    def test_role_file_grants_read_on_soc_slo_metrics(self):
        # #361 security-auditor finding: soc-slo-metrics was write-only
        # (create_index/create) by design until metric_vanished_claims()
        # started _search-ing it for the prior sample — pattern PRESENCE
        # alone (already covered by test_role_file_grants_soc_agent_health's
        # sibling checks) isn't enough; a role entry can list a pattern with
        # the wrong privileges and this class's other tests wouldn't notice.
        self.assertIn("read", self._granted_privileges("soc-slo-metrics"),
                       "slo_metrics_reader.json's soc-slo-metrics entry is missing "
                       "'read' — metric_vanished_claims()'s prior-sample _search "
                       "against soc-slo-metrics will 403 under the real slo_metrics "
                       "service account (#361)")

    def test_compose_inline_copy_matches_role_file(self):
        # The compose file's inline PUT body must stay byte-for-byte in sync
        # with the authoritative role file. The JSON file is what actually
        # wins on a full bring-up (the `roles` service re-applies every file
        # in configs/elasticsearch/roles/ after `provision`, and that PUT is
        # what persists) — but the inline copy is still the one that governs
        # the bootstrap window before `roles` runs, so drift between the two
        # is a real, live bug, not just cosmetic duplication.
        role_json = self.ROLE_PATH.read_text(encoding="utf-8")
        role_compact = json.dumps(json.loads(role_json), separators=(",", ":"))
        compose_text = self.COMPOSE_PATH.read_text(encoding="utf-8")
        self.assertIn(role_compact.replace('"', '\\"'), compose_text,
                       "scripts/setup/docker-compose.yml's inline slo_metrics_reader "
                       "role PUT has drifted from configs/elasticsearch/roles/"
                       "slo_metrics_reader.json — keep them in sync")


class EnvLineParsingTests(unittest.TestCase):
    """#259: slo_metrics.py's hand-rolled .env loader (unlike every other
    script in this repo, which bash-sources .env and gets comment-stripping
    for free) used to take the whole line remainder as the value, breaking
    float()/int() conversion on a real "KEY=10   # comment" style .env
    line — reproduced live against this environment's local .env. The
    parsing logic itself now lives in the shared env_loader module (full
    edge-case coverage in tests/setup/test_env_loader.py, alongside
    run_hunts.py's identical dependency on it) — these two tests exist here
    specifically to prove slo_metrics.py is actually WIRED to it (not a
    reverted-to-private-copy regression) and to lock in the exact scenario
    this issue's evidence section reproduced."""

    def test_slo_metrics_is_wired_to_the_shared_env_loader(self):
        # security-auditor review: the actual production call path is
        # load_env_file(), not parse_env_line() directly — a regression
        # that re-inlined the loading loop while still importing
        # parse_env_line would pass a parse_env_line-only wiring check.
        self.assertIs(slo_metrics.env_loader.parse_env_line, env_loader.parse_env_line)
        self.assertIs(slo_metrics.env_loader.load_env_file, env_loader.load_env_file)

    def test_inline_comment_value_is_actually_usable_as_a_float(self):
        # The regression this issue exists to prevent: this must not raise.
        _, v = slo_metrics.env_loader.parse_env_line(
            "SLO_MTTD_MAX_MIN=10         # Max Mean Time to Detect (in minutes)")
        self.assertEqual(float(v), 10.0)


class LogstashWriterRoleDriftTests(unittest.TestCase):
    """#257 (security-auditor review of #245): configs/elasticsearch/roles/
    logstash_writer.json is authoritative (re-applied by apply_roles.sh), but
    docker-compose.yml also carries an inline bootstrap PUT of the same role
    for the window before that reconciliation runs — this pair had ALREADY
    drifted once (the inline copy was missing asset-inventory-*/
    soc-agent-health-*/auto_configure) before #257 fixed it. Same regression
    shape and same fix pattern as SloMetricsReaderRoleGrantTests above,
    generalized per the security-auditor's INFO-2 note that only
    slo_metrics_reader had this guard."""

    ROLE_PATH = slo_metrics.REPO / "configs" / "elasticsearch" / "roles" / "logstash_writer.json"
    COMPOSE_PATH = slo_metrics.REPO / "scripts" / "setup" / "docker-compose.yml"

    def test_compose_inline_copy_matches_role_file(self):
        role_json = self.ROLE_PATH.read_text(encoding="utf-8")
        role_compact = json.dumps(json.loads(role_json), separators=(",", ":"))
        compose_text = self.COMPOSE_PATH.read_text(encoding="utf-8")
        self.assertIn(role_compact.replace('"', '\\"'), compose_text,
                       "scripts/setup/docker-compose.yml's inline logstash_writer "
                       "role PUT has drifted from configs/elasticsearch/roles/"
                       "logstash_writer.json — keep them in sync")

    def test_role_file_does_not_grant_template_or_ilm_management(self):
        # #257: the whole point of this issue's second acceptance criterion —
        # logstash_internal must not be able to DELETE/overwrite
        # agent-checkpoints-template via cluster-level template/ILM privileges
        # it never needs for its actual job (writing documents).
        role = json.loads(self.ROLE_PATH.read_text(encoding="utf-8"))
        cluster_privs = set(role.get("cluster", []))
        self.assertNotIn("manage_index_templates", cluster_privs)
        self.assertNotIn("manage_ilm", cluster_privs)


if __name__ == "__main__":
    unittest.main(verbosity=2)

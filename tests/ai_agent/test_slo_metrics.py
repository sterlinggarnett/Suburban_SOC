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
             mock.patch.object(slo_metrics, "metric_coverage", return_value=12.0), \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            code = self._run_main_capturing_exit()
        self.assertEqual(code, 0)

    def _mock_all_metrics(self, mttd=0.0, mttr=0.0, coverage=12.0, fp_pct=0.0,
                           ingest_lag=10.0, parse_err=0.0, audit_write_failures=0.0,
                           raw_alert_volume=None):
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
            mock.patch.object(slo_metrics, "metric_raw_alert_volume",
                               return_value=raw_alert_volume),
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

    def test_audit_write_failures_below_threshold_does_not_breach(self):
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(audit_write_failures=2.0):
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

    def test_raw_alert_volume_never_breaches_regardless_of_value(self):
        # #216: NO_TARGET means this is measured but never checked against a
        # threshold — an arbitrarily large value must not trip a breach.
        with contextlib.ExitStack() as stack, \
             mock.patch.object(slo_metrics, "NTFY_TOPIC", ""):
            for p in self._mock_all_metrics(
                    raw_alert_volume={"zeek_notices": 500000, "rule_hits": 499999,
                                       "value": 999999}):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

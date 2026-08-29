#!/usr/bin/env python3
"""
weekly_ciso_report.py — reporting-plane test coverage (issue #172, SA-11).

Covers NIST tag parsing, ES metrics fetch (+ demo-data fallback), the LLM
executive summary (+ hosted-egress gate), real PDF rendering, Slack's
three-step upload, ntfy delivery, and the pipeline orchestrator.

Run:  pytest tests/ai_agent/test_weekly_ciso_report.py
"""

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

# test_alert_auth.py unconditionally replaces sys.modules["weekly_ciso_report"]
# with a stub before importing agent_app (so that import doesn't pull in
# weasyprint/elasticsearch). In a combined test run that file collects first
# alphabetically, so without evicting it here this module would silently bind
# to that stub instead of the real implementation it exists to test.
sys.modules.pop("weekly_ciso_report", None)
import weekly_ciso_report as wcr  # noqa: E402


class _FakeLLMResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise wcr.requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class TagToNistTests(unittest.TestCase):
    def test_extracts_valid_nist_tags(self):
        self.assertEqual(wcr._tag_to_nist(["NIST:Detect", "NIST:Respond"]),
                          ["Detect", "Respond"])

    def test_case_insensitive_prefix_and_function_name(self):
        self.assertEqual(wcr._tag_to_nist(["nist:detect"]), ["Detect"])

    def test_ignores_non_nist_tags(self):
        self.assertEqual(wcr._tag_to_nist(["some-other-tag", "priority:high"]), [])

    def test_ignores_unknown_nist_function(self):
        self.assertEqual(wcr._tag_to_nist(["NIST:Bogus"]), [])

    def test_empty_tag_list(self):
        self.assertEqual(wcr._tag_to_nist([]), [])

    def test_non_string_tag_does_not_raise(self):
        self.assertEqual(wcr._tag_to_nist([123, None]), [])


class FetchAndCalculateMetricsTests(unittest.TestCase):
    def test_es_unreachable_falls_back_to_demo_data(self):
        with mock.patch.object(wcr, "Elasticsearch", side_effect=ConnectionError("refused")):
            metrics = wcr.fetch_and_calculate_metrics()
        self.assertTrue(metrics["demo_mode"])
        self.assertEqual(metrics["total_alerts"], 342)
        self.assertIn("nist_breakdown", metrics)

    def test_real_hits_compute_mttd_and_nist_breakdown(self):
        hits = [
            {"_source": {"@timestamp": "2026-01-01T00:00:00Z",
                          "kibana": {"alert": {"start": "2026-01-01T00:10:00Z"}},
                          "tags": ["NIST:Detect"]}},
            {"_source": {"@timestamp": "2026-01-01T01:00:00Z",
                          "kibana": {"alert": {"start": "2026-01-01T01:20:00Z"}},
                          "tags": ["NIST:Respond", "NIST:Detect"]}},
            # negative delta (clock skew) — must not be averaged in
            {"_source": {"@timestamp": "2026-01-01T02:30:00Z",
                          "kibana": {"alert": {"start": "2026-01-01T02:00:00Z"}},
                          "tags": []}},
            # missing timestamps entirely — must not raise
            {"_source": {"tags": ["not-nist"]}},
        ]
        fake_es_instance = mock.Mock()
        fake_es_instance.search.return_value = {"hits": {"hits": hits}}
        with mock.patch.object(wcr, "Elasticsearch", return_value=fake_es_instance):
            metrics = wcr.fetch_and_calculate_metrics()

        self.assertFalse(metrics["demo_mode"])
        self.assertEqual(metrics["total_alerts"], 4)
        self.assertEqual(metrics["average_mttd_minutes"], 15.0)  # avg(10, 20)
        self.assertEqual(metrics["nist_breakdown"]["Detect"], 2)
        self.assertEqual(metrics["nist_breakdown"]["Respond"], 1)
        self.assertEqual(metrics["nist_breakdown"]["Protect"], 0)


class GenerateExecutiveSummaryTests(unittest.TestCase):
    METRICS = {"total_alerts": 10, "average_mttd_minutes": 5.0,
               "nist_breakdown": {"Detect": 10}}

    def test_hosted_llm_blocked_by_default(self):
        with mock.patch.object(wcr, "LLM_API_URL", "https://api.openai.com/v1/chat/completions"), \
             mock.patch.object(wcr, "LLM_ALLOW_HOSTED", False), \
             mock.patch.object(wcr.requests, "post") as post:
            summary = wcr.generate_executive_summary(self.METRICS)
        post.assert_not_called()
        self.assertIn("skipped", summary.lower())

    def test_local_llm_is_never_blocked(self):
        with mock.patch.object(wcr, "LLM_API_URL", "http://localhost:11434/v1/chat/completions"), \
             mock.patch.object(wcr, "LLM_ALLOW_HOSTED", False), \
             mock.patch.object(wcr.requests, "post",
                               return_value=_FakeLLMResponse(200, {
                                   "choices": [{"message": {"content": "  Board summary.  "}}]})):
            summary = wcr.generate_executive_summary(self.METRICS)
        self.assertEqual(summary, "Board summary.")

    def test_hosted_llm_allowed_when_opted_in(self):
        with mock.patch.object(wcr, "LLM_API_URL", "https://api.openai.com/v1/chat/completions"), \
             mock.patch.object(wcr, "LLM_ALLOW_HOSTED", True), \
             mock.patch.object(wcr.requests, "post",
                               return_value=_FakeLLMResponse(200, {
                                   "choices": [{"message": {"content": "Hosted summary."}}]})) as post:
            summary = wcr.generate_executive_summary(self.METRICS)
        post.assert_called_once()
        self.assertEqual(summary, "Hosted summary.")

    def test_llm_failure_returns_fallback_message(self):
        with mock.patch.object(wcr, "LLM_API_URL", "http://localhost:11434/v1/chat/completions"), \
             mock.patch.object(wcr.requests, "post", side_effect=ConnectionError("refused")):
            summary = wcr.generate_executive_summary(self.METRICS)
        self.assertIn("could not be generated", summary)

    def test_llm_non_200_returns_fallback_message(self):
        with mock.patch.object(wcr, "LLM_API_URL", "http://localhost:11434/v1/chat/completions"), \
             mock.patch.object(wcr.requests, "post", return_value=_FakeLLMResponse(500)):
            summary = wcr.generate_executive_summary(self.METRICS)
        self.assertIn("could not be generated", summary)


class CreatePdfReportTests(unittest.TestCase):
    def test_renders_real_pdf_with_demo_banner_and_zero_tagged(self):
        metrics = {"total_alerts": 0, "average_mttd_minutes": 0,
                   "nist_breakdown": {f: 0 for f in wcr.NIST_FUNCTIONS}, "demo_mode": True}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "reports")
            with mock.patch.object(wcr, "PDF_OUTPUT_DIR", out_dir):
                result = wcr.create_pdf_report(metrics, "Paragraph one.\n\nParagraph two.")
            self.assertTrue(result.startswith(out_dir))
            self.assertTrue(os.path.isfile(result))
            self.assertGreater(os.path.getsize(result), 0)
            with open(result, "rb") as fh:
                self.assertTrue(fh.read(5).startswith(b"%PDF-"))

    def test_renders_real_pdf_with_nist_breakdown_percentages(self):
        metrics = {"total_alerts": 100, "average_mttd_minutes": 12.3,
                   "nist_breakdown": {"Identify": 5, "Protect": 15, "Detect": 60,
                                      "Respond": 15, "Recover": 5}, "demo_mode": False}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "reports")
            with mock.patch.object(wcr, "PDF_OUTPUT_DIR", out_dir):
                result = wcr.create_pdf_report(metrics, "Some narrative.")
            self.assertTrue(os.path.isfile(result))
            self.assertTrue(result.startswith(out_dir))

    def test_output_dir_created_owner_only(self):
        metrics = {"total_alerts": 0, "average_mttd_minutes": 0,
                   "nist_breakdown": {}, "demo_mode": False}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "reports")
            with mock.patch.object(wcr, "PDF_OUTPUT_DIR", out_dir):
                wcr.create_pdf_report(metrics, "Narrative.")
            # audit #176 (SC-28): not world-readable — owner-only.
            self.assertEqual(os.stat(out_dir).st_mode & 0o777, 0o700)

    def test_each_run_gets_a_distinct_filename(self):
        metrics = {"total_alerts": 0, "average_mttd_minutes": 0,
                   "nist_breakdown": {}, "demo_mode": False}
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "reports")
            with mock.patch.object(wcr, "PDF_OUTPUT_DIR", out_dir):
                first = wcr.create_pdf_report(metrics, "Narrative one.")
                time.sleep(1.1)  # filenames are second-precision timestamps
                second = wcr.create_pdf_report(metrics, "Narrative two.")
            self.assertNotEqual(first, second)
            self.assertTrue(os.path.isfile(first))
            self.assertTrue(os.path.isfile(second))

    def test_prunes_old_reports_beyond_retention_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "reports")
            os.makedirs(out_dir)
            # Pre-seed more report files than the retention count, with distinct
            # mtimes so "oldest" is unambiguous.
            paths = []
            for i in range(5):
                p = os.path.join(out_dir, f"Weekly_NIST_Security_Report_fake-{i}.pdf")
                with open(p, "wb") as fh:
                    fh.write(b"%PDF-1.7 fake")
                os.utime(p, (1000 + i, 1000 + i))
                paths.append(p)
            with mock.patch.object(wcr, "PDF_OUTPUT_DIR", out_dir), \
                 mock.patch.object(wcr, "PDF_RETENTION_COUNT", 3):
                metrics = {"total_alerts": 0, "average_mttd_minutes": 0,
                           "nist_breakdown": {}, "demo_mode": False}
                wcr.create_pdf_report(metrics, "Narrative.")
            remaining = sorted(os.listdir(out_dir))
            # 5 pre-seeded + 1 new = 6 candidates; retention=3 must prune to 3.
            self.assertEqual(len(remaining), 3)
            # The 2 oldest pre-seeded files must be the ones pruned.
            self.assertNotIn(os.path.basename(paths[0]), remaining)
            self.assertNotIn(os.path.basename(paths[1]), remaining)


class SendToSlackTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.pdf_path = os.path.join(self._tmp.name, "report.pdf")
        with open(self.pdf_path, "wb") as fh:
            fh.write(b"%PDF-1.7 fake pdf content")

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_credentials_configured_returns_false_without_calling_slack(self):
        with mock.patch.object(wcr, "SLACK_TOKEN", ""), \
             mock.patch.object(wcr, "SLACK_CHANNEL", ""), \
             mock.patch.object(wcr.requests, "get") as get:
            self.assertFalse(wcr.send_to_slack(self.pdf_path))
        get.assert_not_called()

    def test_full_three_step_upload_succeeds(self):
        with mock.patch.object(wcr, "SLACK_TOKEN", "xoxb-test"), \
             mock.patch.object(wcr, "SLACK_CHANNEL", "C123"), \
             mock.patch.object(wcr.requests, "get",
                               return_value=_FakeLLMResponse(200, {
                                   "ok": True, "upload_url": "https://slack.example/upload",
                                   "file_id": "F123"})), \
             mock.patch.object(wcr.requests, "put",
                               return_value=mock.Mock(status_code=200)), \
             mock.patch.object(wcr.requests, "post",
                               return_value=_FakeLLMResponse(200, {"ok": True})):
            self.assertTrue(wcr.send_to_slack(self.pdf_path))

    def test_step1_failure_returns_false(self):
        with mock.patch.object(wcr, "SLACK_TOKEN", "xoxb-test"), \
             mock.patch.object(wcr, "SLACK_CHANNEL", "C123"), \
             mock.patch.object(wcr.requests, "get",
                               return_value=_FakeLLMResponse(200, {"ok": False})):
            self.assertFalse(wcr.send_to_slack(self.pdf_path))

    def test_step2_non_2xx_returns_false(self):
        with mock.patch.object(wcr, "SLACK_TOKEN", "xoxb-test"), \
             mock.patch.object(wcr, "SLACK_CHANNEL", "C123"), \
             mock.patch.object(wcr.requests, "get",
                               return_value=_FakeLLMResponse(200, {
                                   "ok": True, "upload_url": "https://slack.example/upload",
                                   "file_id": "F123"})), \
             mock.patch.object(wcr.requests, "put",
                               return_value=mock.Mock(status_code=500)):
            self.assertFalse(wcr.send_to_slack(self.pdf_path))

    def test_step3_failure_returns_false(self):
        with mock.patch.object(wcr, "SLACK_TOKEN", "xoxb-test"), \
             mock.patch.object(wcr, "SLACK_CHANNEL", "C123"), \
             mock.patch.object(wcr.requests, "get",
                               return_value=_FakeLLMResponse(200, {
                                   "ok": True, "upload_url": "https://slack.example/upload",
                                   "file_id": "F123"})), \
             mock.patch.object(wcr.requests, "put",
                               return_value=mock.Mock(status_code=200)), \
             mock.patch.object(wcr.requests, "post",
                               return_value=_FakeLLMResponse(200, {"ok": False, "error": "bad"})):
            self.assertFalse(wcr.send_to_slack(self.pdf_path))


class SendNtfyNotificationTests(unittest.TestCase):
    METRICS = {"total_alerts": 7, "average_mttd_minutes": 3.5}

    def test_success_posts_expected_message(self):
        with mock.patch.object(wcr, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(wcr.requests, "post") as post:
            wcr.send_ntfy_notification(self.METRICS, pdf_delivered=True)
        post.assert_called_once()
        sent = post.call_args.kwargs["data"].decode()
        self.assertIn("Delivered to Slack", sent)
        self.assertIn("7", sent)

    def test_failure_is_swallowed_not_raised(self):
        with mock.patch.object(wcr, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(wcr.requests, "post", side_effect=ConnectionError("refused")):
            wcr.send_ntfy_notification(self.METRICS, pdf_delivered=False)  # must not raise

    def test_title_header_is_latin1_safe(self):
        # #424: requests/http.client encode header VALUES as latin-1 — the
        # hardcoded Title ("📊 Weekly Security Report Ready") contains an
        # emoji well outside latin-1's range, which raised
        # UnicodeEncodeError deep in http.client.putheader() and was
        # silently swallowed by this function's own `except Exception`,
        # dropping the push with only a log line (found during code review
        # of agent.py's identical fix — this call site had the live bug
        # too, uncovered by that fix alone).
        with mock.patch.object(wcr, "NTFY_TOPIC", "test-topic"), \
             mock.patch.object(wcr.requests, "post") as post:
            wcr.send_ntfy_notification(self.METRICS, pdf_delivered=True)
        title = post.call_args.kwargs["headers"]["Title"]
        title.encode("latin-1")  # must not raise
        self.assertNotIn("📊", title)


class RunReportingPipelineTests(unittest.TestCase):
    def test_orchestrates_all_stages_in_order_and_returns_summary(self):
        metrics = {"total_alerts": 5, "average_mttd_minutes": 2.0, "demo_mode": False}
        with mock.patch.object(wcr, "fetch_and_calculate_metrics", return_value=metrics) as m_fetch, \
             mock.patch.object(wcr, "generate_executive_summary", return_value="narrative") as m_gen, \
             mock.patch.object(wcr, "create_pdf_report", return_value="/tmp/report.pdf") as m_pdf, \
             mock.patch.object(wcr, "send_to_slack", return_value=True) as m_slack, \
             mock.patch.object(wcr, "send_ntfy_notification") as m_ntfy:
            result = wcr.run_reporting_pipeline()

        m_fetch.assert_called_once()
        m_gen.assert_called_once_with(metrics)
        m_pdf.assert_called_once_with(metrics, "narrative")
        m_slack.assert_called_once_with("/tmp/report.pdf")
        m_ntfy.assert_called_once_with(metrics, True)
        self.assertEqual(result, {
            "status": "complete", "pdf": "/tmp/report.pdf",
            "total_alerts": 5, "average_mttd_minutes": 2.0,
            "slack_delivered": True, "demo_mode": False,
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)

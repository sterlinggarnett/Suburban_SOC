"""
compact_threat_intel.py — #271's per-document TTL retention for
threat-intel-indicators / threat-intel-meta. Tests the module's
compact_index()/compact()/CLI surface against a mocked `requests` module,
matching this repo's existing unittest.mock conventions (see
test_compact_agent_checkpoints.py, the closest analog — same shape,
adapted for two independent, non-tenant-scoped indices instead of one
per-tenant index with a terminal/non-terminal phase distinction, and for
this script's blast-radius safety check, which that sibling script doesn't
need — see compact_threat_intel.py's own comment above BLAST_RADIUS_FRACTION
for why).
"""
import io
import json
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import requests

import compact_threat_intel as tool

ROOT = Path(__file__).resolve().parents[2]
ROLE_PATH = ROOT / "configs" / "elasticsearch" / "roles" / "threat_intel_compactor.json"
INTEL_WRITER_ROLE_PATH = ROOT / "configs" / "elasticsearch" / "roles" / "intel_writer.json"
DOCKER_COMPOSE = (ROOT / "scripts" / "setup" / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / "scripts" / "setup" / ".env.example").read_text(encoding="utf-8")
SERVICE_FILE = (ROOT / "configs" / "systemd" / "threat-intel-compact.service").read_text(encoding="utf-8")
REFRESH_INTEL_SH = (ROOT / "configs" / "intel" / "refresh_intel.sh").read_text(encoding="utf-8")


def _mock_response(status_code=200, json_body=None):
    resp = mock.Mock()
    resp.status_code = status_code
    if status_code >= 400:
        # response=resp (matching real requests.Response.raise_for_status(),
        # which always binds the response onto the error it raises) — #358's
        # _is_transient_poll_error() reads err.response.status_code, so a
        # bare no-response HTTPError here would silently misclassify every
        # 5xx in this file's tests.
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error", response=resp)
    else:
        resp.raise_for_status.return_value = None
    resp.json.return_value = json_body or {}
    return resp


def _counts_then_delete(matched, total=None, delete_body=None):
    """A requests.post side_effect distinguishing the two DIFFERENT _count
    calls compact_index() can make (matched-by-query vs total-via-match_all)
    from the async _delete_by_query KICKOFF call, by URL suffix + query body
    shape — both counts share the same /_count URL, so the body is the only
    way to tell them apart.

    #358: compact_index()'s actual delete is now async
    (wait_for_completion=false) — the kickoff POST this mocks only ever
    returns a task ID; the real completion body a synchronous call used to
    return directly now comes from _wait_for_task(), which every test using
    this helper must mock SEPARATELY (see _expected_delete_body() below) —
    that's a real, separately-tested function
    (WaitForTaskTests), not something these
    count/kickoff-focused tests need to re-simulate."""
    def side_effect(url, json=None, **kwargs):
        if url.endswith("/_count"):
            if json and "match_all" in json.get("query", {}):
                return _mock_response(200, {"count": total if total is not None else 0})
            return _mock_response(200, {"count": matched})
        if "_delete_by_query" in url:
            assert "wait_for_completion=false" in url, \
                "compact_index() must kick off the delete asynchronously, not synchronously (#358)"
            return _mock_response(200, {"task": "test-node:1"})
        raise AssertionError(f"unexpected URL in test: {url}")
    return side_effect


def _expected_delete_body(matched, delete_body=None):
    """The completion body _wait_for_task() should be mocked to return for
    a given _counts_then_delete(matched=..., delete_body=...) setup — same
    default-fallback logic that helper uses internally for the (now
    separate) kickoff mock, factored out so callers only state the delete
    outcome once."""
    return delete_body if delete_body is not None else {"deleted": matched, "total": matched}


class ConstantsTests(unittest.TestCase):
    """The exact two indices and shared date field this module must cover
    — guards against a typo'd index name silently scoping this script to
    the wrong (or a nonexistent) target."""

    def test_covers_exactly_the_two_threat_intel_indices(self):
        self.assertEqual(set(tool.TARGET_INDICES), {"threat-intel-indicators", "threat-intel-meta"})

    def test_both_indices_share_the_same_date_field(self):
        # security-auditor review: threat.indicator.last_seen (a field #271
        # also added) cannot be the retention field for threat-intel-indicators
        # — an ES range query never matches a document missing the field, so
        # every indicator that predates this fix would be permanently
        # undeletable. @timestamp is present on every doc, old and new
        # (refresh_intel.sh's bulk "index" action has fully replaced it on
        # every run since #222, independent of #271's last_seen addition).
        self.assertEqual("@timestamp", tool.DATE_FIELD)


class BuildQueryTests(unittest.TestCase):
    def test_query_filters_on_the_given_date_field(self):
        query = tool._build_query("@timestamp", 7)
        self.assertEqual(query["query"]["range"]["@timestamp"]["lt"], "now-7d")

    def test_query_uses_the_given_retention_window(self):
        query = tool._build_query("@timestamp", 45)
        self.assertEqual(query["query"]["range"]["@timestamp"]["lt"], "now-45d")


class CompactIndexDryRunTests(unittest.TestCase):
    @mock.patch("compact_threat_intel.requests.post")
    def test_dry_run_uses_count_not_delete_by_query(self, mock_post):
        mock_post.side_effect = _counts_then_delete(matched=7)
        out = io.StringIO()
        with redirect_stdout(out):
            result = tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=True)
        self.assertEqual(result, 7)
        self.assertIn("[dry-run]", out.getvalue())
        for call in mock_post.call_args_list:
            self.assertIn("_count", call[0][0])
            self.assertNotIn("_delete_by_query", call[0][0])

    @mock.patch("compact_threat_intel.requests.post")
    def test_dry_run_never_calls_delete_by_query_at_all(self, mock_post):
        mock_post.side_effect = _counts_then_delete(matched=0)
        tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=True)
        for call in mock_post.call_args_list:
            self.assertNotIn("_delete_by_query", call[0][0])

    @mock.patch("compact_threat_intel.requests.post")
    def test_dry_run_does_not_check_blast_radius(self, mock_post):
        # A dry-run reporting "this would exceed the safety threshold" would
        # be confusing (it can never actually delete anything) — it should
        # simply report the matched count via one _count call, not also
        # query the index total.
        mock_post.side_effect = _counts_then_delete(matched=1000)
        tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=True)
        count_calls = [c for c in mock_post.call_args_list if c[0][0].endswith("/_count")]
        self.assertEqual(1, len(count_calls))


class WaitForTaskTests(unittest.TestCase):
    """#358: the client's own timeout on the OLD synchronous _delete_by_query
    call never canceled the server-side task if exceeded — a client-side
    give-up is not a server-side cancellation. wait_for_completion=false +
    polling _tasks/<id> replaces that with a client that never "gives up" on
    a still-running task, and reports the real task ID for reconciliation if
    ITS OWN poll budget elapses instead.

    _wait_for_task() polls via TASK_POLL_SESSION (an es_client.get_session()
    instance, not bare `requests`), so every test here mocks
    `compact_threat_intel.TASK_POLL_SESSION.get`, not `requests.get`."""

    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_returns_response_once_task_reports_completed(self, mock_session, mock_sleep):
        mock_session.get.side_effect = [
            _mock_response(200, {"completed": False}),
            _mock_response(200, {"completed": False}),
            _mock_response(200, {"completed": True, "response": {"deleted": 5, "total": 5}}),
        ]
        result = tool._wait_for_task("node1:1", "threat-intel-indicators")
        self.assertEqual(result, {"deleted": 5, "total": 5})
        self.assertEqual(mock_session.get.call_count, 3)
        # Slept BETWEEN polls (2 sleeps for 3 polls), not after the final one.
        self.assertEqual(mock_sleep.call_count, 2)

    # security-auditor HIGH: a task that FAILED still reports
    # completed:true, as {"completed":true,"error":{...}} with no
    # `response` key — must raise (naming the failure), never silently
    # return {} and let compact_index() print a fake "0/0 deleted, clean
    # run" for a delete that never actually happened.
    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_raises_when_the_task_itself_reports_an_error(self, mock_session, mock_sleep):
        mock_session.get.return_value = _mock_response(
            200, {"completed": True, "error": {"type": "circuit_breaking_exception"}})
        with self.assertRaises(RuntimeError) as ctx:
            tool._wait_for_task("node1:1", "threat-intel-meta")
        self.assertIn("FAILED", str(ctx.exception))
        self.assertIn("circuit_breaking_exception", str(ctx.exception))

    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_raises_when_completed_with_neither_response_nor_error(self, mock_session, mock_sleep):
        # A shape this function's own contract doesn't guarantee can't
        # happen — must fail loudly (cannot confirm what was deleted), not
        # silently return an empty dict compact_index() would read as "0
        # deleted, clean run".
        mock_session.get.return_value = _mock_response(200, {"completed": True})
        with self.assertRaises(RuntimeError) as ctx:
            tool._wait_for_task("node1:1", "threat-intel-meta")
        self.assertIn("neither `response` nor `error`", str(ctx.exception))

    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_polls_the_exact_task_id_url(self, mock_session, mock_sleep):
        mock_session.get.return_value = _mock_response(200, {"completed": True, "response": {}})
        tool._wait_for_task("node1:42", "threat-intel-meta")
        self.assertIn("_tasks/node1:42", mock_session.get.call_args_list[0][0][0])

    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_raises_immediately_on_a_non_transient_http_error(self, mock_session, mock_sleep):
        # 500 (and 401/403/404/400) are NOT in the transient set (only
        # 502/503/504 are, matching es_client.py's own Retry policy) —
        # retrying a permission/addressing problem for the whole poll
        # budget before giving up would be pure wasted time. Real
        # time.monotonic() is fine here specifically BECAUSE this must
        # raise on the FIRST attempt, before any deadline check matters.
        mock_session.get.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            tool._wait_for_task("node1:1", "threat-intel-indicators")
        self.assertEqual(mock_session.get.call_count, 1)
        mock_sleep.assert_not_called()

    @mock.patch("compact_threat_intel.time.monotonic")
    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_retries_a_transient_5xx_within_the_poll_budget_then_succeeds(
            self, mock_session, mock_sleep, mock_monotonic):
        # 503 IS transient — must be retried like "not yet complete", not
        # raised immediately, as long as the poll budget isn't exhausted.
        mock_session.get.side_effect = [
            _mock_response(503),
            _mock_response(200, {"completed": True, "response": {"deleted": 1, "total": 1}}),
        ]
        mock_monotonic.side_effect = [0, 100]  # deadline calc, then one (unexceeded) check
        result = tool._wait_for_task("node1:1", "threat-intel-indicators")
        self.assertEqual(result, {"deleted": 1, "total": 1})
        self.assertEqual(mock_session.get.call_count, 2)
        mock_sleep.assert_called_once()

    @mock.patch("compact_threat_intel.time.monotonic")
    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_raises_with_task_id_once_a_sustained_transient_outage_exceeds_the_budget(
            self, mock_session, mock_sleep, mock_monotonic):
        mock_session.get.side_effect = requests.ConnectionError("connection refused")
        mock_monotonic.side_effect = [0, 999999]
        with self.assertRaises(RuntimeError) as ctx:
            tool._wait_for_task("node1:7", "threat-intel-indicators")
        self.assertIn("node1:7", str(ctx.exception))
        self.assertIn("UNKNOWN", str(ctx.exception))
        self.assertIn("Do NOT re-run", str(ctx.exception))

    @mock.patch("compact_threat_intel.time.monotonic")
    @mock.patch("compact_threat_intel.time.sleep")
    @mock.patch.object(tool, "TASK_POLL_SESSION")
    def test_raises_with_the_task_id_once_the_poll_budget_elapses(
            self, mock_session, mock_sleep, mock_monotonic):
        # Never completes; the second monotonic() read (the deadline check)
        # reports past the deadline computed from the first read.
        mock_session.get.return_value = _mock_response(200, {"completed": False})
        mock_monotonic.side_effect = [0, 999999]
        with self.assertRaises(RuntimeError) as ctx:
            tool._wait_for_task("node1:99", "threat-intel-indicators")
        self.assertIn("node1:99", str(ctx.exception))
        self.assertIn("STILL RUNNING", str(ctx.exception))
        self.assertIn("Do NOT re-run", str(ctx.exception))
        # Must raise on the FIRST deadline check, not after sleeping/polling
        # again — the elapsed budget is discovered right after the poll that
        # revealed "not yet done", not on some later iteration.
        self.assertEqual(mock_session.get.call_count, 1)
        mock_sleep.assert_not_called()


class TransientPollErrorClassificationTests(unittest.TestCase):
    """#358 security-auditor finding: only 502/503/504 (and connection-level
    failures with no response at all) are worth _wait_for_task()'s own
    retry-until-deadline — anything else fails the same way every time."""

    def test_5xx_forcelist_is_transient(self):
        for status in (502, 503, 504):
            resp = mock.Mock(status_code=status)
            err = requests.HTTPError(response=resp)
            self.assertTrue(tool._is_transient_poll_error(err), f"{status} should be transient")

    def test_other_http_statuses_are_not_transient(self):
        for status in (400, 401, 403, 404, 500, 429):
            resp = mock.Mock(status_code=status)
            err = requests.HTTPError(response=resp)
            self.assertFalse(tool._is_transient_poll_error(err), f"{status} should NOT be transient")

    def test_connection_and_timeout_errors_are_transient(self):
        self.assertTrue(tool._is_transient_poll_error(requests.ConnectionError("refused")))
        self.assertTrue(tool._is_transient_poll_error(requests.Timeout("timed out")))

    def test_http_error_with_no_response_object_is_treated_as_transient(self):
        # Defensive: an HTTPError somehow raised without a bound response
        # (shouldn't happen via raise_for_status(), but the attribute isn't
        # guaranteed) must not crash this check itself.
        self.assertTrue(tool._is_transient_poll_error(requests.HTTPError()))


class CompactIndexLiveTests(unittest.TestCase):
    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_calls_delete_by_query_with_conflicts_proceed(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=3, total=10)
        mock_wait.return_value = _expected_delete_body(matched=3, delete_body={"deleted": 3, "total": 3})
        result = tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=False)
        self.assertEqual(result, 3)
        urls = [c[0][0] for c in mock_post.call_args_list]
        self.assertTrue(any("threat-intel-indicators/_delete_by_query" in u and "conflicts=proceed" in u
                            and "wait_for_completion=false" in u for u in urls))

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_skips_the_total_count_when_nothing_matched(self, mock_post, mock_wait):
        # matched=0 means there's nothing to delete and nothing that could
        # possibly exceed the blast-radius threshold — no reason to spend a
        # second _count call finding that out.
        mock_post.side_effect = _counts_then_delete(matched=0)
        mock_wait.return_value = _expected_delete_body(matched=0, delete_body={"deleted": 0, "total": 0})
        tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=False)
        count_calls = [c for c in mock_post.call_args_list if c[0][0].endswith("/_count")]
        self.assertEqual(1, len(count_calls))

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_raises_and_reports_failures_to_stderr(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=1, total=1)
        mock_wait.return_value = _expected_delete_body(matched=1, delete_body={
            "deleted": 1, "total": 2,
            "failures": [{"index": "x", "id": "y", "cause": {"reason": "boom"}}]})
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(RuntimeError):
            tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=False)
        self.assertIn("1 failure(s)", err.getvalue())
        self.assertIn("boom", err.getvalue())

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_raises_on_timed_out_response(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=5, total=10)
        mock_wait.return_value = _expected_delete_body(
            matched=5, delete_body={"deleted": 5, "total": 500, "timed_out": True})
        with self.assertRaises(RuntimeError):
            tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=False)

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_does_not_raise_on_version_conflicts_alone(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=3, total=10)
        mock_wait.return_value = _expected_delete_body(
            matched=3, delete_body={"deleted": 3, "total": 4, "version_conflicts": 1})
        result = tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=False)
        self.assertEqual(result, 3)

    @mock.patch("compact_threat_intel.requests.post")
    def test_live_run_raises_on_es_server_error(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=False)


class BlastRadiusGuardTests(unittest.TestCase):
    """#271 security-auditor review: unlike compact_agent_checkpoints.py's
    multi-clause phase filter, this script's delete query has a single
    predicate — a mis-mapped date field, a dead writer, or a direct
    compact_index() call with a bad retention value could each make EVERY
    document in an index match at once. These tests pin the guard that
    catches that shape."""

    @mock.patch("compact_threat_intel.requests.post")
    def test_refuses_when_matched_exceeds_the_threshold_fraction(self, mock_post):
        # 15/20 = 75%, over the 50% default threshold, at/above the
        # MIN_DOCS_FOR_BLAST_RADIUS_CHECK floor.
        mock_post.side_effect = _counts_then_delete(matched=15, total=20)
        with self.assertRaises(RuntimeError) as ctx:
            tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=False)
        self.assertIn("refusing to delete", str(ctx.exception))
        self.assertIn("75%", str(ctx.exception))
        # And the delete must never actually have been attempted.
        for call in mock_post.call_args_list:
            self.assertNotIn("_delete_by_query", call[0][0])

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_allows_a_match_at_or_below_the_threshold_fraction(self, mock_post, mock_wait):
        # 10/20 = 50%, not OVER the threshold (strictly-greater comparison).
        mock_post.side_effect = _counts_then_delete(matched=10, total=20)
        mock_wait.return_value = _expected_delete_body(matched=10, delete_body={"deleted": 10, "total": 10})
        result = tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=False)
        self.assertEqual(result, 10)

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_force_bypasses_the_threshold_check_entirely(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=19, total=20)
        mock_wait.return_value = _expected_delete_body(matched=19, delete_body={"deleted": 19, "total": 19})
        result = tool.compact_index("threat-intel-indicators", "@timestamp", 7, dry_run=False, force=True)
        self.assertEqual(result, 19)
        # force=True must skip the total-count call entirely, not just
        # ignore its result.
        count_calls = [c for c in mock_post.call_args_list if c[0][0].endswith("/_count")]
        self.assertEqual(1, len(count_calls))

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_small_index_below_the_minimum_floor_is_exempt(self, mock_post, mock_wait):
        # 2/3 = 67%, over the fraction threshold, but total is below
        # MIN_DOCS_FOR_BLAST_RADIUS_CHECK — a nearly-empty index (e.g.
        # threat-intel-meta right after deploy) legitimately clears most of
        # its docs in one run without that being suspicious.
        mock_post.side_effect = _counts_then_delete(matched=2, total=3)
        mock_wait.return_value = _expected_delete_body(matched=2, delete_body={"deleted": 2, "total": 2})
        result = tool.compact_index("threat-intel-meta", "@timestamp", 7, dry_run=False)
        self.assertEqual(result, 2)

    @mock.patch("compact_threat_intel.requests.post")
    def test_the_floor_and_threshold_constants_are_the_documented_values(self, mock_post):
        # Guards the constants themselves against an accidental edit — the
        # tests above assert BEHAVIOR at specific numbers that only prove
        # what they claim if these match.
        self.assertEqual(0.5, tool.BLAST_RADIUS_FRACTION)
        self.assertEqual(20, tool.MIN_DOCS_FOR_BLAST_RADIUS_CHECK)


class CompactBothIndicesTests(unittest.TestCase):
    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_compact_runs_both_indices_and_returns_a_result_per_index(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=2, total=10)
        mock_wait.return_value = _expected_delete_body(matched=2, delete_body={"deleted": 2, "total": 2})
        result = tool.compact(retention_days=7, dry_run=False)
        self.assertEqual(result, {"threat-intel-indicators": 2, "threat-intel-meta": 2})
        urls = [c[0][0] for c in mock_post.call_args_list]
        self.assertTrue(any("threat-intel-indicators" in u for u in urls))
        self.assertTrue(any("threat-intel-meta" in u for u in urls))

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_one_index_failing_does_not_prevent_the_other_from_running(self, mock_post, mock_wait):
        # Partial progress over an all-or-nothing run: the two indices are
        # otherwise unrelated, so one's transient failure should not block
        # the other's cleanup — but the overall call must still surface the
        # failure (next test), not silently swallow it.
        mock_wait.return_value = _expected_delete_body(matched=4, delete_body={"deleted": 4, "total": 4})

        def side_effect(url, json=None, **kwargs):
            if "threat-intel-indicators" in url:
                return _mock_response(500)
            return _counts_then_delete(matched=4, total=10)(url, json=json, **kwargs)

        mock_post.side_effect = side_effect
        with self.assertRaises(requests.HTTPError):
            tool.compact(retention_days=7, dry_run=False)
        urls = [c[0][0] for c in mock_post.call_args_list]
        self.assertTrue(any("threat-intel-meta" in u for u in urls),
                         "threat-intel-meta should still have been attempted "
                         "even though threat-intel-indicators failed")

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_a_single_index_failure_preserves_the_original_exception_type(self, mock_post, mock_wait):
        # code-reviewer/security-auditor finding: wrapping every failure in
        # a bare RuntimeError made main()'s specific requests.HTTPError/
        # requests.RequestException handlers unreachable. When exactly one
        # index fails, compact() must re-raise the SAME exception type
        # (with an index-prefixed message), not a generic RuntimeError.
        mock_wait.return_value = _expected_delete_body(matched=0)

        def side_effect(url, json=None, **kwargs):
            if "threat-intel-indicators" in url:
                raise requests.ConnectionError("connection refused")
            return _counts_then_delete(matched=0)(url, json=json, **kwargs)

        mock_post.side_effect = side_effect
        with self.assertRaises(requests.ConnectionError) as ctx:
            tool.compact(retention_days=7, dry_run=False)
        self.assertIn("threat-intel-indicators", str(ctx.exception))

    @mock.patch("compact_threat_intel.requests.post")
    def test_both_indices_failing_combines_into_a_plain_runtime_error(self, mock_post):
        # No single original type to preserve when both fail — a combined
        # RuntimeError naming both is the honest result.
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(RuntimeError) as ctx:
            tool.compact(retention_days=7, dry_run=False)
        self.assertNotIsInstance(ctx.exception, requests.HTTPError)
        self.assertIn("threat-intel-indicators", str(ctx.exception))
        self.assertIn("threat-intel-meta", str(ctx.exception))

    @mock.patch("compact_threat_intel.requests.post")
    def test_compact_dry_run_never_calls_delete_by_query_for_either_index(self, mock_post):
        # The exact mutation caught live during review: hardcoding
        # dry_run=False in compact()'s call to compact_index() still passed
        # every other test in this file. Assert it here directly: with
        # dry_run=True, EVERY call compact() makes must hit _count, and
        # NONE may hit _delete_by_query, across both indices.
        mock_post.side_effect = _counts_then_delete(matched=0)
        tool.compact(retention_days=7, dry_run=True)
        urls = [c[0][0] for c in mock_post.call_args_list]
        self.assertGreaterEqual(len(urls), 2, "expected a call for both threat-intel-indicators and threat-intel-meta")
        for url in urls:
            self.assertIn("_count", url)
            self.assertNotIn("_delete_by_query", url)

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_force_is_threaded_through_to_both_indices(self, mock_post, mock_wait):
        # 19/20 would trip the blast-radius guard without force=True.
        mock_post.side_effect = _counts_then_delete(matched=19, total=20)
        mock_wait.return_value = _expected_delete_body(matched=19, delete_body={"deleted": 19, "total": 19})
        result = tool.compact(retention_days=7, dry_run=False, force=True)
        self.assertEqual(result, {"threat-intel-indicators": 19, "threat-intel-meta": 19})

    def test_rejects_a_non_positive_retention(self):
        with self.assertRaises(ValueError):
            tool.compact(retention_days=-5, dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact(retention_days=0, dry_run=True)

    def test_rejects_a_non_integer_retention(self):
        with self.assertRaises(ValueError):
            tool.compact(retention_days=7.5, dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact(retention_days=float("nan"), dry_run=True)

    def test_compact_index_itself_also_validates_retention_days(self):
        # security-auditor finding: compact()'s own validation is not
        # enough if compact_index() is ever called directly (e.g. a future
        # --indices flag, a REPL one-liner) — retention_days=0 renders
        # "now-0d", valid ES date-math meaning "now", matching everything.
        # The guard must live at the point that actually issues the
        # request, not just one layer up.
        with self.assertRaises(ValueError):
            tool.compact_index("threat-intel-indicators", "@timestamp", 0, dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact_index("threat-intel-indicators", "@timestamp", -1, dry_run=True)


class MainCliTests(unittest.TestCase):
    @mock.patch("compact_threat_intel.requests.post")
    def test_main_defaults_to_thirty_day_retention(self, mock_post):
        # security-auditor review: 30d (not #271's original 7d suggestion)
        # to clear the "Threat Intel Feed Health" dashboard's own `now-7d`
        # saved-search window (configs/server/intel_feed_health.ndjson).
        mock_post.side_effect = _counts_then_delete(matched=0)
        with mock.patch("sys.argv", ["compact_threat_intel.py", "--dry-run"]):
            tool.main()
        for call in mock_post.call_args_list:
            self.assertEqual(call[1]["json"]["query"]["range"]["@timestamp"]["lt"], "now-30d")

    @mock.patch("compact_threat_intel.requests.post")
    def test_main_passes_through_explicit_retention(self, mock_post):
        mock_post.side_effect = _counts_then_delete(matched=0)
        with mock.patch("sys.argv", ["compact_threat_intel.py",
                                     "--retention-days", "30", "--dry-run"]):
            tool.main()
        for call in mock_post.call_args_list:
            self.assertEqual(call[1]["json"]["query"]["range"]["@timestamp"]["lt"], "now-30d")

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_main_passes_through_force(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=19, total=20)
        mock_wait.return_value = _expected_delete_body(matched=19, delete_body={"deleted": 19, "total": 19})
        with mock.patch("sys.argv", ["compact_threat_intel.py", "--force"]):
            tool.main()  # would raise (blast-radius refusal -> SystemExit) if --force weren't threaded through
        urls = [c[0][0] for c in mock_post.call_args_list]
        self.assertTrue(any("_delete_by_query" in u for u in urls))

    @mock.patch("compact_threat_intel.requests.post")
    def test_main_without_force_reports_the_blast_radius_refusal(self, mock_post):
        mock_post.side_effect = _counts_then_delete(matched=19, total=20)
        with mock.patch("sys.argv", ["compact_threat_intel.py"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    def test_main_cli_rejects_a_non_integer_retention_days(self):
        # argparse's type=int itself refuses "7.5" — confirms the CLI
        # surface, not just compact(), rejects a fractional value cleanly.
        with mock.patch("sys.argv", ["compact_threat_intel.py",
                                     "--retention-days", "7.5", "--dry-run"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)

    @mock.patch("compact_threat_intel.requests.post")
    def test_main_reports_a_clean_error_for_an_es_rejection_not_a_traceback(self, mock_post):
        # Only ONE index fails (both failing combines into a plain
        # RuntimeError instead — see CompactBothIndicesTests — which would
        # defeat the point of this test: proving main()'s HTTPError-specific
        # message actually fires via the single-failure type-preserving path).
        def side_effect(url, json=None, **kwargs):
            if "threat-intel-indicators" in url:
                return _mock_response(500)
            return _counts_then_delete(matched=0)(url, json=json, **kwargs)

        mock_post.side_effect = side_effect
        err = io.StringIO()
        with mock.patch("sys.argv", ["compact_threat_intel.py", "--dry-run"]), \
             redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)
        # code-reviewer/security-auditor finding: this test previously only
        # asserted the exit code, which passed identically whether or not
        # main()'s ES-rejection-specific message ever printed. Assert the
        # actual differentiated message now that compact() preserves the
        # original exception type for a single-index failure.
        self.assertIn("Elasticsearch rejected the request", err.getvalue())

    @mock.patch("compact_threat_intel.requests.post")
    def test_main_reports_a_clean_error_when_es_is_unreachable(self, mock_post):
        # code-reviewer round 1: HTTPError alone (raised only by
        # raise_for_status() on a 4xx/5xx response) misses connection-level
        # failures — ES down/unreachable is a realistic scheduled-job
        # failure mode and must not surface as a raw traceback either.
        # Only ONE index fails, same reasoning as the test above.
        def side_effect(url, json=None, **kwargs):
            if "threat-intel-indicators" in url:
                raise requests.ConnectionError("connection refused")
            return _counts_then_delete(matched=0)(url, json=json, **kwargs)

        mock_post.side_effect = side_effect
        err = io.StringIO()
        with mock.patch("sys.argv", ["compact_threat_intel.py", "--dry-run"]), \
             redirect_stderr(err), self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("could not reach Elasticsearch", err.getvalue())

    @mock.patch("compact_threat_intel._wait_for_task")
    @mock.patch("compact_threat_intel.requests.post")
    def test_main_reports_a_clean_error_for_a_dirty_delete_run_not_a_traceback(self, mock_post, mock_wait):
        mock_post.side_effect = _counts_then_delete(matched=1, total=1)
        mock_wait.return_value = _expected_delete_body(matched=1, delete_body={
            "deleted": 1, "total": 2,
            "failures": [{"index": "x", "id": "y", "cause": {"reason": "boom"}}]})
        with mock.patch("sys.argv", ["compact_threat_intel.py"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)


class RefreshIntelStampsLastSeenTests(unittest.TestCase):
    """threat.indicator.last_seen is no longer what retention keys on
    (see ConstantsTests), but refresh_intel.sh should still stamp it — it's
    the properly-named ECS field for anyone querying "when was this
    indicator last confirmed live" directly."""

    def test_refresh_intel_sh_stamps_last_seen_on_the_indicator_bulk_body(self):
        self.assertIn('"last_seen":"%s"', REFRESH_INTEL_SH)

    def test_refresh_intel_sh_uses_the_index_action_not_create(self):
        # "index" (full replace on an existing _id) is what makes both
        # @timestamp and last_seen actually refresh on every run; "create"
        # would 409 on every re-appearance of an already-known indicator.
        self.assertIn('{"index":{"_index":"threat-intel-indicators"', REFRESH_INTEL_SH)
        self.assertNotIn('{"create":{"_index":"threat-intel-indicators"', REFRESH_INTEL_SH)


class CompactorCredentialProvisioningTests(unittest.TestCase):
    """#271: the compactor needs its OWN delete-capable credential, kept
    strictly separate from intel_writer (whose entire purpose, #222, is
    holding no read/delete privilege) — these lock in that it's actually
    provisioned least-privilege, not just referenced by name. Mirrors
    test_compact_agent_checkpoints.py's CompactorCredentialProvisioningTests."""

    def test_role_file_exists_and_grants_read_and_delete_only(self):
        self.assertTrue(ROLE_PATH.exists(), f"missing {ROLE_PATH}")
        role = json.loads(ROLE_PATH.read_text(encoding="utf-8"))
        indices = role["indices"]
        self.assertEqual(len(indices), 1)
        self.assertEqual(set(indices[0]["names"]), {"threat-intel-indicators", "threat-intel-meta"})
        self.assertEqual(set(indices[0]["privileges"]), {"read", "delete"})

    def test_role_file_grants_cluster_monitor_for_task_polling(self):
        # #358 security-auditor finding: GET _tasks/<id> (_wait_for_task(),
        # called after every async _delete_by_query kickoff) is
        # cluster:monitor/task/get, covered by the "monitor" CLUSTER
        # privilege — index-level read/delete grants above don't cover it.
        # Without this, every scheduled compaction run 403s on its very
        # first task poll, after the delete has already been kicked off
        # server-side.
        role = json.loads(ROLE_PATH.read_text(encoding="utf-8"))
        self.assertIn("monitor", role.get("cluster", []))

    def test_docker_compose_provisions_a_separate_role_from_intel_writer(self):
        self.assertIn("threat_intel_compactor", DOCKER_COMPOSE)
        self.assertIn("/_security/user/threat_intel_compactor", DOCKER_COMPOSE)
        self.assertIn(r'\"roles\":[\"threat_intel_compactor\"]', DOCKER_COMPOSE)

    def test_intel_writer_authoritative_role_file_still_has_no_delete(self):
        # Parse the actual role file (authoritative, re-applied by
        # apply_roles.sh) directly — don't just trust that the correct
        # NEW privilege string was added without ALSO widening the old one.
        role = json.loads(INTEL_WRITER_ROLE_PATH.read_text(encoding="utf-8"))
        for entry in role["indices"]:
            self.assertNotIn("delete", entry["privileges"])
            self.assertNotIn("read", entry["privileges"])

    def test_docker_compose_intel_writer_role_line_has_no_delete(self):
        # Same check against the inline bootstrap copy specifically — the
        # role-file test above doesn't catch drift between the two.
        for line in DOCKER_COMPOSE.splitlines():
            if "_security/role/intel_writer " in line:  # trailing space excludes _compactor
                self.assertNotIn("delete", line)
                return
        self.fail("could not find the intel_writer role provisioning line")

    def test_docker_compose_password_is_never_spliced_into_container_argv(self):
        self.assertIn("$${THREAT_INTEL_COMPACTOR_PASSWORD}", DOCKER_COMPOSE)

    def test_env_example_documents_the_new_password(self):
        self.assertIn("THREAT_INTEL_COMPACTOR_PASSWORD=", ENV_EXAMPLE)

    def test_setup_service_placeholder_rejection_covers_the_new_password(self):
        # security-auditor HIGH finding: THREAT_INTEL_COMPACTOR_PASSWORD
        # (and, pre-existing, AGENT_CHECKPOINTS_COMPACTOR_PASSWORD /
        # LOGSTASH_ENRICH_PASSWORD) bypassed the `setup` service's
        # changeme*-rejection gate entirely — a delete-capable ES user
        # would be provisioned with the literal published placeholder
        # password if an operator only filled in the "REQUIRED" vars.
        # "Blank = fails closed" (the reasoning documented everywhere else
        # for these optional identities) only covers the BLANK case; a
        # non-blank placeholder is not blank.
        self.assertIn('case "$${THREAT_INTEL_COMPACTOR_PASSWORD}" in changeme*', DOCKER_COMPOSE)

    def test_every_changeme_placeholder_in_env_example_has_a_matching_gate(self):
        # Generalized regression test (security-auditor recommendation):
        # the specific check above only proves THIS var is covered: this
        # one proves no var can silently join the club that
        # AGENT_CHECKPOINTS_COMPACTOR_PASSWORD/LOGSTASH_ENRICH_PASSWORD/
        # THREAT_INTEL_COMPACTOR_PASSWORD were found in.
        placeholder_vars = set(re.findall(r"^([A-Z_]+)=changeme", ENV_EXAMPLE, re.MULTILINE))
        # ELASTIC_PASSWORD/KIBANA_PASSWORD/LOGSTASH_PASSWORD are gated via a
        # single-$ Compose-time reference (docker-compose.yml's own comment
        # explains why: those three stay Compose-time to match every OTHER
        # use of them in this service script); every other var uses the
        # runtime-shell $$ form. Match both.
        gated_vars = set(re.findall(r'case "\$\$?\{([A-Z_]+)\}" in changeme\*', DOCKER_COMPOSE))
        missing = placeholder_vars - gated_vars
        self.assertEqual(set(), missing,
                          f"{missing} ship a changeme_* placeholder in .env.example but have no "
                          f"changeme*-rejection gate in docker-compose.yml's setup service")

    def test_systemd_service_uses_the_compactor_credential_not_intel_writer(self):
        self.assertIn("THREAT_INTEL_COMPACTOR_ES_USER=threat_intel_compactor", SERVICE_FILE)
        self.assertIn("compact_threat_intel.py", SERVICE_FILE)

    def test_systemd_service_does_not_use_the_broken_environment_expansion_pattern(self):
        # security-auditor MEDIUM finding, empirically confirmed live via
        # `systemd-run --user` against a throwaway unit on this host:
        # systemd's Environment= directive does NOT expand ${VAR}
        # references — per systemd.exec(5), "$" has no special meaning
        # there. This is the exact bug class #259 already fixed once for
        # slo-metrics.service; pin the fixed shape here so it can't
        # silently regress back to the broken one-liner. Scans only
        # non-comment lines — the unit's own explanatory comment quotes the
        # broken pattern verbatim as documentation of what NOT to do, which
        # a blanket substring search would misread as a live regression.
        active_lines = [line for line in SERVICE_FILE.splitlines() if not line.strip().startswith("#")]
        for line in active_lines:
            self.assertNotIn("Environment=THREAT_INTEL_COMPACTOR_ES_PASS=${THREAT_INTEL_COMPACTOR_PASSWORD}", line)
        # security-auditor round 2 (#357): the assertion below previously
        # scanned the WHOLE file, including the explanatory comment above
        # (which quotes "THREAT_INTEL_COMPACTOR_ES_PASS=" verbatim as part
        # of documenting the broken pattern) — it would have passed even if
        # every functional reference were deleted. Scan active_lines only.
        self.assertTrue(any("THREAT_INTEL_COMPACTOR_ES_PASS=" in line for line in active_lines))
        self.assertIn("EnvironmentFile=-/run/suburban-soc-threat-intel-compact/"
                      "threat_intel_compactor_password.env", SERVICE_FILE)

    def test_systemd_execstartpre_actually_extracts_the_secret_before_execstart(self):
        # security-auditor round 2 MEDIUM (#357): the tests above pin that
        # the broken line is gone and the EnvironmentFile= consumer is
        # present, but neither ever asserted the ExecStartPre that actually
        # PRODUCES the scratch file exists at all — deleting that one line
        # leaves EnvironmentFile=- silently tolerating a missing file (by
        # design, for the separate "blank .env is fine" case), so every ES
        # call would 401 daily with the full test suite still green. Pin
        # its content and its position ahead of ExecStart directly,
        # mirroring tests/pipeline/test_capture_loss_monitoring.py's
        # test_systemd_check_runs_in_execstartpre_not_execstart precedent.
        execstartpre_match = re.search(
            r"ExecStartPre=/bin/sh -c 'grep \"\^THREAT_INTEL_COMPACTOR_PASSWORD=\".*"
            r"THREAT_INTEL_COMPACTOR_ES_PASS=.*"
            r"/run/suburban-soc-threat-intel-compact/threat_intel_compactor_password\.env.*"
            r"grep -Eq \"\^THREAT_INTEL_COMPACTOR_ES_PASS=\.\{8,\}\"",
            SERVICE_FILE)
        self.assertIsNotNone(
            execstartpre_match,
            "expected an ExecStartPre extracting THREAT_INTEL_COMPACTOR_PASSWORD into the "
            "scratch file EnvironmentFile= reads, with a non-empty-value guard")
        execstart_pos = SERVICE_FILE.index("\nExecStart=/usr/bin/python3")
        self.assertLess(execstartpre_match.start(), execstart_pos)


class TimeoutStartSecCoversPollBudgetTests(unittest.TestCase):
    """#358 code-reviewer follow-up: nothing previously pinned the
    relationship between TASK_POLL_TIMEOUT_SECONDS (the module's own poll
    budget PER INDEX) and TimeoutStartSec (the systemd unit's overall
    budget for BOTH indices run sequentially, plus ExecStartPre overhead)
    — if the module constant is ever bumped without remembering the
    systemd file, the unit gets silently killed mid-poll (which, per
    _wait_for_task()'s own docstring, does not cancel the ES-side task
    either)."""

    def test_timeout_start_sec_covers_two_full_poll_budgets_with_margin(self):
        match = re.search(r"^TimeoutStartSec=(\d+)$", SERVICE_FILE, re.MULTILINE)
        self.assertIsNotNone(match, "expected a TimeoutStartSec= line in the service file")
        timeout_start_sec = int(match.group(1))
        # Two sequential indices, each up to TASK_POLL_TIMEOUT_SECONDS, plus
        # a 60s margin per index for the count/kickoff calls and the
        # deadline check firing only after a poll returns.
        minimum_required = 2 * (tool.TASK_POLL_TIMEOUT_SECONDS + 60)
        self.assertGreaterEqual(
            timeout_start_sec, minimum_required,
            f"TimeoutStartSec={timeout_start_sec} no longer covers 2x "
            f"TASK_POLL_TIMEOUT_SECONDS({tool.TASK_POLL_TIMEOUT_SECONDS:g}) + margin "
            f"({minimum_required:g}) — bump configs/systemd/threat-intel-compact.service")


if __name__ == "__main__":
    unittest.main()

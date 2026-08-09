"""
manage_stuck_claims.py — the #276 operator CLI for resolving approval claims
stuck in phase=CLAIMED. Tests the command handlers directly (not via
subprocess) against a mocked checkpoints module, matching this repo's
existing unittest.mock conventions.
"""
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from unittest import mock

import requests

import manage_stuck_claims as tool


def _args(**kwargs):
    ns = mock.Mock()
    for k, v in kwargs.items():
        setattr(ns, k, v)
    return ns


class PositiveFloatTests(unittest.TestCase):
    """code-reviewer nitpick: only the negative case was exercised through
    argparse; unit-test the boundary cases directly."""

    def test_rejects_zero(self):
        with self.assertRaises(Exception):
            tool._positive_float("0")

    def test_rejects_nan(self):
        with self.assertRaises(Exception):
            tool._positive_float("nan")

    def test_rejects_inf(self):
        with self.assertRaises(Exception):
            tool._positive_float("inf")

    def test_accepts_a_normal_positive_value(self):
        self.assertEqual(tool._positive_float("30"), 30.0)


class CmdListTests(unittest.TestCase):
    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_reports_nothing_stuck(self, mock_search):
        mock_search.return_value = ([], 0)
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.cmd_list(_args(tenant=None, max_age_min=30.0))
        self.assertEqual(code, 0)
        self.assertIn("No claims stuck", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_prints_each_stuck_claim(self, mock_search):
        mock_search.return_value = ([
            {"tenant": {"id": "home-smith"}, "alert_id": "alert-1", "approver": "human",
             "@timestamp": "2020-01-01T00:00:00+00:00"},
        ], 1)
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.cmd_list(_args(tenant=None, max_age_min=30.0))
        self.assertEqual(code, 0)
        self.assertIn("home-smith", out.getvalue())
        self.assertIn("alert-1", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_passes_tenant_and_max_age_through(self, mock_search):
        mock_search.return_value = ([], 0)
        tool.cmd_list(_args(tenant="home-smith", max_age_min=45.0))
        mock_search.assert_called_once_with(max_age_minutes=45.0, tenant_id="home-smith")

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_defaults_to_wildcard_tenant(self, mock_search):
        mock_search.return_value = ([], 0)
        tool.cmd_list(_args(tenant=None, max_age_min=30.0))
        mock_search.assert_called_once_with(max_age_minutes=30.0, tenant_id="*")

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_warns_when_results_are_truncated(self, mock_search):
        claim = {"tenant": {"id": "home-smith"}, "alert_id": "alert-1", "approver": "human",
                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        mock_search.return_value = ([claim], 250)
        out = io.StringIO()
        with redirect_stdout(out):
            tool.cmd_list(_args(tenant=None, max_age_min=30.0))
        self.assertIn("Showing the oldest 1 of 250", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_list_does_not_warn_when_results_are_complete(self, mock_search):
        claim = {"tenant": {"id": "home-smith"}, "alert_id": "alert-1", "approver": "human",
                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        mock_search.return_value = ([claim], 1)
        out = io.StringIO()
        with redirect_stdout(out):
            tool.cmd_list(_args(tenant=None, max_age_min=30.0))
        self.assertNotIn("Showing the oldest", out.getvalue())


class CmdShowTests(unittest.TestCase):
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_show_reports_missing_claim(self, mock_get):
        mock_get.return_value = None
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.cmd_show(_args(tenant="home-smith", alert_id="alert-1"))
        self.assertEqual(code, 1)
        self.assertIn("No claim doc found", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_show_prints_claim_detail(self, mock_get):
        mock_get.return_value = {"tenant": {"id": "home-smith"}, "alert_id": "alert-1",
                                 "phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.cmd_show(_args(tenant="home-smith", alert_id="alert-1"))
        self.assertEqual(code, 0)
        self.assertIn("CLAIMED", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_show_notes_when_not_actually_stuck(self, mock_get):
        mock_get.return_value = {"tenant": {"id": "home-smith"}, "alert_id": "alert-1",
                                 "phase": "RESOLVED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        out = io.StringIO()
        with redirect_stdout(out):
            tool.cmd_show(_args(tenant="home-smith", alert_id="alert-1"))
        self.assertIn("not currently stuck", out.getvalue())

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_show_displays_manual_resolution_attribution_when_present(self, mock_get):
        # security-auditor round-2 LOW: the #276 attribution fields were
        # write-only from this tool's own perspective — an operator asking
        # "who resolved this and why" had no way to see the answer here.
        mock_get.return_value = {"tenant": {"id": "home-smith"}, "alert_id": "alert-1",
                                 "phase": "RELEASED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "resolved_by": "agent_checkpoints:jdoe@sochost",
                                 "resolution_actor_claimed": "jdoe",
                                 "resolved_at": "2020-01-02T00:00:00+00:00",
                                 "resolution_reason": "confirmed via SSH",
                                 "resolution_source": "manual"}
        out = io.StringIO()
        with redirect_stdout(out):
            tool.cmd_show(_args(tenant="home-smith", alert_id="alert-1"))
        text = out.getvalue()
        self.assertIn("agent_checkpoints:jdoe@sochost", text)
        self.assertIn("jdoe", text)
        self.assertIn("confirmed via SSH", text)
        self.assertIn("manual", text)


def _resolve_args(**overrides):
    """CmdResolveTests default args — a claim old enough (2020) to clear the
    default 30-minute staleness gate, with actor/reason always present since
    argparse now requires them (real CLI runs can't omit these)."""
    defaults = dict(tenant="home-smith", alert_id="alert-1", outcome="released",
                     actor="jdoe", reason="confirmed via SSH", max_age_min=30.0,
                     force=False, yes=True)
    defaults.update(overrides)
    return _args(**defaults)


class CmdResolveTests(unittest.TestCase):
    """#276 acceptance criterion: the tool never grants/uses delete privilege
    on agent-checkpoints-* — enforced here by asserting only release_claim()/
    resolve_claim() (checkpoints.py's own _update-based transitions) are ever
    called, never anything delete-shaped."""

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_refuses_when_claim_does_not_exist(self, mock_get):
        mock_get.return_value = None
        code = tool.cmd_resolve(_resolve_args())
        self.assertEqual(code, 1)

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_refuses_when_claim_is_not_currently_claimed(self, mock_get):
        # Someone else already resolved it — must not be re-transitioned.
        mock_get.return_value = {"phase": "RESOLVED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        code = tool.cmd_resolve(_resolve_args())
        self.assertEqual(code, 1)

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_without_yes_is_a_dry_run(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        out = io.StringIO()
        with redirect_stdout(out):
            code = tool.cmd_resolve(_resolve_args(yes=False))
        self.assertEqual(code, 0)
        self.assertIn("No changes made (dry run)", out.getvalue())
        mock_release.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_released_calls_release_claim_with_yes(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "_seq_no": 3, "_primary_term": 1}
        mock_release.return_value = True
        code = tool.cmd_resolve(_resolve_args(outcome="released"))
        self.assertEqual(code, 0)
        mock_release.assert_called_once_with("home-smith", "alert-1", actor="jdoe",
                                             reason="confirmed via SSH",
                                             if_seq_no=3, if_primary_term=1)

    @mock.patch("manage_stuck_claims.checkpoints.resolve_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_resolved_calls_resolve_claim_with_yes(self, mock_get, mock_resolve):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "_seq_no": 3, "_primary_term": 1}
        mock_resolve.return_value = True
        code = tool.cmd_resolve(_resolve_args(outcome="resolved"))
        self.assertEqual(code, 0)
        mock_resolve.assert_called_once_with("home-smith", "alert-1", actor="jdoe",
                                             reason="confirmed via SSH",
                                             if_seq_no=3, if_primary_term=1)

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_passes_seq_no_and_primary_term_through_for_optimistic_concurrency(
            self, mock_get, mock_release):
        # #276 security-auditor MEDIUM (read-then-write race): whatever
        # get_claim() observed must ride along on the write so a concurrent
        # modification is detected rather than silently overwritten.
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "_seq_no": 7, "_primary_term": 2}
        mock_release.return_value = True
        tool.cmd_resolve(_resolve_args())
        mock_release.assert_called_once_with("home-smith", "alert-1", actor="jdoe",
                                             reason="confirmed via SSH",
                                             if_seq_no=7, if_primary_term=2)

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_reports_failure_when_transition_does_not_confirm(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "_seq_no": 3, "_primary_term": 1}
        mock_release.return_value = False
        code = tool.cmd_resolve(_resolve_args())
        self.assertEqual(code, 1)
        mock_release.assert_called_once()  # reached the transition, didn't get refused earlier

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_refuses_a_claim_younger_than_max_age_min(self, mock_get, mock_release):
        # security-auditor MEDIUM (#276): `resolve` used to gate only on
        # phase==CLAIMED, so a claim seconds old with a dispatch actively in
        # flight passed just as readily as a genuinely stuck one.
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": datetime.now(timezone.utc).isoformat()}
        code = tool.cmd_resolve(_resolve_args(max_age_min=30.0, force=False))
        self.assertEqual(code, 1)
        mock_release.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_force_overrides_the_staleness_gate(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": datetime.now(timezone.utc).isoformat(),
                                 "_seq_no": 3, "_primary_term": 1}
        mock_release.return_value = True
        code = tool.cmd_resolve(_resolve_args(max_age_min=30.0, force=True))
        self.assertEqual(code, 0)
        mock_release.assert_called_once()

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_refuses_when_seq_no_or_primary_term_is_missing(self, mock_get, mock_release):
        # security-auditor LOW: get_claim() should always carry both from a
        # real ES GET response — but if it somehow didn't, this must refuse
        # rather than silently fall back to an unconditional (unguarded)
        # write, which would drop the read-then-write race protection
        # exactly when the tool can't prove it isn't racing something.
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00"}
        code = tool.cmd_resolve(_resolve_args())
        self.assertEqual(code, 1)
        mock_release.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_resolve_refuses_when_claimed_timestamp_is_unparseable(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human", "@timestamp": "not-a-date"}
        code = tool.cmd_resolve(_resolve_args())
        self.assertEqual(code, 1)
        mock_release.assert_not_called()

    def test_checkpoints_module_exposes_no_delete_function_at_all(self):
        # #276 acceptance criterion, enforced structurally rather than by
        # mocking: this tool's only interface to agent-checkpoints-* is the
        # checkpoints module, and that module has no delete-shaped function
        # for this script to ever call, mistakenly or otherwise — the same
        # guarantee agent_checkpoints's ES role provides at the privilege
        # layer (#245: no delete grant), checked here at the code layer too.
        import checkpoints as real_checkpoints
        public_names = [n for n in dir(real_checkpoints) if not n.startswith("_")]
        self.assertFalse([n for n in public_names if "delete" in n.lower()])


class ArgparseWiringTests(unittest.TestCase):
    """#276 code-reviewer review: the cmd_* tests above pass a hand-built
    Mock in place of argparse.Namespace, which exercises the handler
    functions but never the actual argparse setup (subparsers, `required`,
    `choices`) in main(). These drive the real CLI entry point instead, so
    a broken --outcome choices= or a missing required=True on the
    subparsers would actually fail one of these."""

    def test_main_requires_a_subcommand(self):
        with mock.patch("sys.argv", ["manage_stuck_claims.py"]), \
             self.assertRaises(SystemExit):
            tool.main()

    def test_main_rejects_unknown_outcome_choice(self):
        with mock.patch("sys.argv",
                        ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1",
                         "--outcome", "bogus"]), \
             self.assertRaises(SystemExit):
            tool.main()

    @mock.patch("manage_stuck_claims.checkpoints.search_stuck_claims")
    def test_main_list_reaches_cmd_list(self, mock_search):
        mock_search.return_value = ([], 0)
        with mock.patch("sys.argv", ["manage_stuck_claims.py", "list"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 0)
        mock_search.assert_called_once()

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_resolve_requires_outcome_and_actor_and_reason(self, mock_get):
        # --outcome/--actor/--reason all have required=True — omitting them
        # must be an argparse error (exit 2), not fall through to
        # cmd_resolve with any of them None.
        with mock.patch("sys.argv", ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)
        mock_get.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_resolve_requires_actor_even_with_outcome_and_reason_present(self, mock_get):
        with mock.patch("sys.argv",
                        ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1",
                         "--outcome", "released", "--reason", "confirmed via SSH"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)
        mock_get.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_rejects_an_oversized_reason(self, mock_get):
        # security-auditor LOW: an oversized --reason would otherwise reach
        # ES and be rejected with a generic 400 instead of a clear CLI error.
        with mock.patch("sys.argv",
                        ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1",
                         "--outcome", "released", "--actor", "jdoe",
                         "--reason", "x" * 1025]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)
        mock_get.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_rejects_a_non_positive_max_age_min(self, mock_get):
        with mock.patch("sys.argv",
                        ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1",
                         "--outcome", "released", "--actor", "jdoe", "--reason", "r",
                         "--max-age-min", "-5"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)
        mock_get.assert_not_called()

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_reports_a_clean_error_for_an_es_rejection_not_a_traceback(self, mock_get):
        # security-auditor MEDIUM: an ES-side rejection (e.g. a pre-existing
        # index whose mapping wasn't migrated for the #276 attribution
        # fields) must be an actionable message, not a raw traceback.
        mock_get.side_effect = requests.HTTPError("400 strict_dynamic_mapping_exception")
        with mock.patch("sys.argv", ["manage_stuck_claims.py", "show", "home-smith", "alert-1"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_reports_a_clean_error_for_an_invalid_tenant_not_a_traceback(self, mock_get):
        # code-reviewer Should-Fix: checkpoints._validate_tenant_id raises a
        # bare ValueError on a malformed tenant, which used to propagate as
        # an unhandled traceback — a real usability gap for an operator
        # tool meant to be run under incident-response time pressure.
        mock_get.side_effect = ValueError("invalid tenant_id: 'bad tenant!'")
        with mock.patch("sys.argv", ["manage_stuck_claims.py", "show", "bad tenant!", "alert-1"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("manage_stuck_claims.checkpoints.release_claim")
    @mock.patch("manage_stuck_claims.checkpoints.get_claim")
    def test_main_resolve_reaches_cmd_resolve_with_real_argparse_values(self, mock_get, mock_release):
        mock_get.return_value = {"phase": "CLAIMED", "approver": "human",
                                 "@timestamp": "2020-01-01T00:00:00+00:00",
                                 "_seq_no": 3, "_primary_term": 1}
        mock_release.return_value = True
        with mock.patch("sys.argv",
                        ["manage_stuck_claims.py", "resolve", "home-smith", "alert-1",
                         "--outcome", "released", "--actor", "jdoe",
                         "--reason", "confirmed via SSH", "--yes"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 0)
        mock_release.assert_called_once_with("home-smith", "alert-1", actor="jdoe",
                                             reason="confirmed via SSH",
                                             if_seq_no=3, if_primary_term=1)


if __name__ == "__main__":
    unittest.main()

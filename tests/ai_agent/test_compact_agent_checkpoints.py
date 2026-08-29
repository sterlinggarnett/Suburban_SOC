"""
compact_agent_checkpoints.py — #256's per-document TTL retention for
agent-checkpoints-<tenant>. Tests the module's compact()/CLI surface
against a mocked `requests` module, matching this repo's existing
unittest.mock conventions (see test_checkpoints_claim.py / test_manage_stuck_claims.py,
the latter from #276's PR #311, unmerged as of this writing).
"""
import io
import json
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import requests

import compact_agent_checkpoints as tool

ROOT = Path(__file__).resolve().parents[2]
ROLE_PATH = ROOT / "configs" / "elasticsearch" / "roles" / "agent_checkpoints_compactor.json"
DOCKER_COMPOSE = (ROOT / "scripts" / "setup" / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / "scripts" / "setup" / ".env.example").read_text(encoding="utf-8")
SERVICE_FILE = (ROOT / "configs" / "systemd" / "checkpoints-compact.service").read_text(encoding="utf-8")


def _mock_response(status_code=200, json_body=None):
    resp = mock.Mock()
    resp.status_code = status_code
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code} error")
    else:
        resp.raise_for_status.return_value = None
    resp.json.return_value = json_body or {}
    return resp


class InvariantTests(unittest.TestCase):
    """The single most important property of this module: CLAIMED must
    never be reachable as a terminal/deletable phase, under any
    circumstance — asserted at import time in the module itself, and
    re-checked here so a future edit that silently added it back would
    fail a test even if the import-time assert were ever removed."""

    def test_claimed_is_never_in_the_terminal_phase_sets(self):
        self.assertNotIn("CLAIMED", tool.TERMINAL_CHECKPOINT_PHASES)
        self.assertNotIn("CLAIMED", tool.TERMINAL_CLAIM_PHASES)
        self.assertNotIn("CLAIMED", tool.ALL_TERMINAL_PHASES)

    def test_resolved_is_never_in_the_terminal_phase_sets(self):
        # security-auditor round 1 MEDIUM: a RESOLVED claim's @timestamp
        # reflects claim time, not resolution time, and its paired phase
        # checkpoint can still be PENDING_APPROVAL (an IsolationOutcomeUnknown
        # execution) — deleting it can let a later /approve win a fresh
        # claim and dispatch a real second containment action. Only
        # RELEASED is safe to delete.
        self.assertNotIn("RESOLVED", tool.TERMINAL_CLAIM_PHASES)
        self.assertNotIn("RESOLVED", tool.ALL_TERMINAL_PHASES)

    def test_non_terminal_checkpoint_phases_are_never_included(self):
        for phase in ("PERCEIVING", "PENDING_APPROVAL"):
            self.assertNotIn(phase, tool.ALL_TERMINAL_PHASES)

    def test_known_terminal_phases_are_all_present(self):
        # Guards against a silent drop (e.g. a typo'd rename) leaving a real
        # terminal phase out of the set, which would just make old resolved
        # documents pile up forever rather than error loudly.
        for phase in ("NO_ACTION_PROTECTED_ASSET", "AUTO_ISOLATED",
                      "EXECUTED", "ISOLATION_FAILED", "RELEASED"):
            self.assertIn(phase, tool.ALL_TERMINAL_PHASES)


class BuildQueryTests(unittest.TestCase):
    def test_query_requires_phase_field_to_exist(self):
        # suppress: docs (#220) have no `phase` field at all — this is what
        # keeps them out of scope for this script without an explicit
        # exclusion; asserted directly since it's load-bearing.
        query = tool._build_query(90)
        filters = query["query"]["bool"]["filter"]
        self.assertIn({"exists": {"field": "phase"}}, filters)

    def test_query_filters_on_terminal_phases_only(self):
        query = tool._build_query(90)
        filters = query["query"]["bool"]["filter"]
        terms_filter = next(f for f in filters if "terms" in f)
        self.assertEqual(set(terms_filter["terms"]["phase"]), tool.ALL_TERMINAL_PHASES)
        self.assertNotIn("CLAIMED", terms_filter["terms"]["phase"])

    def test_query_uses_the_given_retention_window(self):
        query = tool._build_query(45)
        filters = query["query"]["bool"]["filter"]
        range_filter = next(f for f in filters if "range" in f)
        self.assertEqual(range_filter["range"]["@timestamp"]["lt"], "now-45d")


class TenantValidationTests(unittest.TestCase):
    def test_accepts_the_wildcard_sentinel(self):
        self.assertEqual(tool._validate_tenant_id("*"), "*")

    def test_accepts_a_real_tenant_slug(self):
        self.assertEqual(tool._validate_tenant_id("home-smith"), "home-smith")

    def test_rejects_an_invalid_tenant_id(self):
        with self.assertRaises(ValueError):
            tool._validate_tenant_id("Not Valid!")

    def test_rejects_a_comma_separated_value(self):
        with self.assertRaises(ValueError):
            tool._validate_tenant_id("home-smith,other-tenant")


class CompactDryRunTests(unittest.TestCase):
    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_dry_run_uses_count_not_delete_by_query(self, mock_post):
        mock_post.return_value = _mock_response(200, {"count": 7})
        out = io.StringIO()
        with redirect_stdout(out):
            result = tool.compact("home-smith", retention_days=90, dry_run=True)
        self.assertEqual(result, 7)
        self.assertIn("[dry-run]", out.getvalue())
        url = mock_post.call_args[0][0]
        self.assertIn("_count", url)
        self.assertNotIn("_delete_by_query", url)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_dry_run_never_calls_delete_by_query_at_all(self, mock_post):
        mock_post.return_value = _mock_response(200, {"count": 0})
        tool.compact("home-smith", retention_days=90, dry_run=True)
        for call in mock_post.call_args_list:
            self.assertNotIn("_delete_by_query", call[0][0])


class CompactLiveTests(unittest.TestCase):
    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_calls_delete_by_query_with_conflicts_proceed(self, mock_post):
        mock_post.return_value = _mock_response(200, {"deleted": 3})
        result = tool.compact("home-smith", retention_days=90, dry_run=False)
        self.assertEqual(result, 3)
        url = mock_post.call_args[0][0]
        self.assertIn("_delete_by_query", url)
        self.assertIn("conflicts=proceed", url)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_targets_the_given_tenant_index(self, mock_post):
        mock_post.return_value = _mock_response(200, {"deleted": 0})
        tool.compact("home-smith", retention_days=90, dry_run=False)
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-home-smith", url)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_defaults_to_wildcard_tenant(self, mock_post):
        mock_post.return_value = _mock_response(200, {"deleted": 0})
        tool.compact(dry_run=False)
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-*", url)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_raises_and_reports_failures_to_stderr(self, mock_post):
        # security-auditor round 1 MEDIUM: a run with any failures must not
        # report clean success — the scheduler needs a non-zero signal, not
        # just a printed line nothing reads. Also actually inspect stderr
        # (code-reviewer round 1 nitpick: the old version of this test never
        # captured it, so deleting the print entirely would have stayed green).
        mock_post.return_value = _mock_response(
            200, {"deleted": 1, "total": 2,
                  "failures": [{"index": "x", "id": "y", "cause": {"reason": "boom"}}]})
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(RuntimeError):
            tool.compact("home-smith", retention_days=90, dry_run=False)
        self.assertIn("1 failure(s)", err.getvalue())
        self.assertIn("boom", err.getvalue())

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_raises_on_timed_out_response(self, mock_post):
        # A timed-out delete_by_query reports a PARTIAL deleted count as if
        # it were complete — must not be trusted as a clean success either.
        mock_post.return_value = _mock_response(
            200, {"deleted": 5, "total": 500, "timed_out": True})
        with self.assertRaises(RuntimeError):
            tool.compact("home-smith", retention_days=90, dry_run=False)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_does_not_raise_on_version_conflicts_alone(self, mock_post):
        # version_conflicts (a doc that changed mid-query, e.g. RELEASED
        # re-CLAIMED by a legitimate retry) is the SAFE, expected outcome
        # conflicts=proceed exists for — must not be treated as a failure.
        mock_post.return_value = _mock_response(
            200, {"deleted": 3, "total": 4, "version_conflicts": 1})
        result = tool.compact("home-smith", retention_days=90, dry_run=False)
        self.assertEqual(result, 3)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_live_run_raises_on_es_server_error(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with self.assertRaises(requests.HTTPError):
            tool.compact("home-smith", retention_days=90, dry_run=False)

    def test_rejects_a_non_positive_retention(self):
        with self.assertRaises(ValueError):
            tool.compact("home-smith", retention_days=-5, dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact("home-smith", retention_days=0, dry_run=True)

    def test_rejects_a_non_integer_retention(self):
        # code-reviewer round 1: ES date-math ("now-Nd") has no fractional-
        # day syntax — a value like 45.5 would build "now-45.5d", which is
        # not valid date-math and 400s. Reject before it ever reaches ES.
        with self.assertRaises(ValueError):
            tool.compact("home-smith", retention_days=45.5, dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact("home-smith", retention_days=float("nan"), dry_run=True)
        with self.assertRaises(ValueError):
            tool.compact("home-smith", retention_days=float("inf"), dry_run=True)

    def test_main_cli_rejects_a_non_integer_retention_days(self):
        # argparse's type=int itself refuses "45.5" (int("45.5") raises) —
        # confirms the CLI surface, not just the compact() function, rejects
        # a fractional value cleanly (exit 2, argparse's own usage error).
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py",
                                     "--retention-days", "45.5", "--dry-run"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_rejects_an_invalid_tenant(self):
        with self.assertRaises(ValueError):
            tool.compact("Not Valid!", retention_days=90, dry_run=True)


class MainCliTests(unittest.TestCase):
    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_main_defaults_to_wildcard_tenant_and_default_retention(self, mock_post):
        mock_post.return_value = _mock_response(200, {"deleted": 0})
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py"]):
            tool.main()
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-*", url)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_main_passes_through_explicit_tenant_and_retention(self, mock_post):
        mock_post.return_value = _mock_response(200, {"count": 0})
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py",
                                     "--tenant", "home-smith",
                                     "--retention-days", "30", "--dry-run"]):
            tool.main()
        url = mock_post.call_args[0][0]
        self.assertIn("agent-checkpoints-home-smith", url)
        body = mock_post.call_args[1]["json"]
        self.assertEqual(body["query"]["bool"]["filter"][-1]["range"]["@timestamp"]["lt"], "now-30d")

    def test_main_reports_a_clean_error_for_an_invalid_tenant_not_a_traceback(self):
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py",
                                     "--tenant", "Not Valid!", "--dry-run"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_main_reports_a_clean_error_for_an_es_rejection_not_a_traceback(self, mock_post):
        mock_post.return_value = _mock_response(500)
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py", "--dry-run"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_main_reports_a_clean_error_when_es_is_unreachable(self, mock_post):
        # code-reviewer round 1: HTTPError alone (raised only by
        # raise_for_status() on a 4xx/5xx response) misses connection-level
        # failures — ES down/unreachable is a realistic scheduled-job
        # failure mode and must not surface as a raw traceback either.
        mock_post.side_effect = requests.ConnectionError("connection refused")
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py", "--dry-run"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)

    @mock.patch("compact_agent_checkpoints.requests.post")
    def test_main_reports_a_clean_error_for_a_dirty_delete_run_not_a_traceback(self, mock_post):
        mock_post.return_value = _mock_response(
            200, {"deleted": 1, "total": 2,
                  "failures": [{"index": "x", "id": "y", "cause": {"reason": "boom"}}]})
        with mock.patch("sys.argv", ["compact_agent_checkpoints.py"]), \
             self.assertRaises(SystemExit) as ctx:
            tool.main()
        self.assertEqual(ctx.exception.code, 1)


class CompactorCredentialProvisioningTests(unittest.TestCase):
    """#256: the compactor needs its OWN delete-capable credential, kept
    strictly separate from agent_checkpoints (whose entire purpose, #245,
    is holding no delete privilege) — these lock in that it's actually
    provisioned least-privilege, not just referenced by name."""

    def test_role_file_exists_and_grants_read_and_delete_only(self):
        self.assertTrue(ROLE_PATH.exists(), f"missing {ROLE_PATH}")
        role = json.loads(ROLE_PATH.read_text(encoding="utf-8"))
        indices = role["indices"]
        self.assertEqual(len(indices), 1)
        self.assertEqual(indices[0]["names"], ["agent-checkpoints-*"])
        self.assertEqual(set(indices[0]["privileges"]), {"read", "delete"})

    def test_docker_compose_provisions_a_separate_role_from_agent_checkpoints(self):
        self.assertIn("agent_checkpoints_compactor", DOCKER_COMPOSE)
        self.assertIn("/_security/user/agent_checkpoints_compactor", DOCKER_COMPOSE)
        self.assertIn(r'\"roles\":[\"agent_checkpoints_compactor\"]', DOCKER_COMPOSE)
        # The live agent/CLI role's own grant must be untouched by this
        # change — still no "delete" anywhere in its privilege list.
        self.assertIn(
            r'\"privileges\":[\"auto_configure\",\"create_index\",\"index\",\"read\"]',
            DOCKER_COMPOSE)

    def test_agent_checkpoints_authoritative_role_file_still_has_no_delete(self):
        # security-auditor round 1 LOW: the credential-provisioning tests
        # above only assert the CORRECT privilege string is present, never
        # that "delete" wasn't ALSO added — parse the actual role file (the
        # authoritative source, re-applied by apply_roles.sh) directly.
        agent_checkpoints_role_path = ROOT / "configs" / "elasticsearch" / "roles" / "agent_checkpoints.json"
        role = json.loads(agent_checkpoints_role_path.read_text(encoding="utf-8"))
        for entry in role["indices"]:
            self.assertNotIn("delete", entry["privileges"])

    def test_docker_compose_agent_checkpoints_role_line_has_no_delete(self):
        # Same check against the inline bootstrap copy specifically — the
        # role-file test above doesn't catch drift between the two.
        # #318 switched provision's inline PUTs from an unquoted URL (curl
        # ... .../_security/role/agent_checkpoints -d "...") to a shared
        # put() helper call (put "/_security/role/agent_checkpoints" "...")
        # -- match the closing quote right after the role name, which still
        # excludes the _compactor line the same way the old trailing space did.
        for line in DOCKER_COMPOSE.splitlines():
            if '"/_security/role/agent_checkpoints"' in line:
                self.assertNotIn("delete", line)
                return
        self.fail("could not find the agent_checkpoints role provisioning line")

    def test_docker_compose_password_is_never_spliced_into_container_argv(self):
        self.assertIn("$${AGENT_CHECKPOINTS_COMPACTOR_PASSWORD}", DOCKER_COMPOSE)

    def test_env_example_documents_the_new_password(self):
        self.assertIn("AGENT_CHECKPOINTS_COMPACTOR_PASSWORD=", ENV_EXAMPLE)

    def test_systemd_service_uses_the_compactor_credential_not_agent_checkpoints(self):
        # code-reviewer round 1: the exact key=value pair, not just presence
        # of the variable name, so a right-name-wrong-value mistake (e.g.
        # missing the _compactor suffix) is actually caught.
        self.assertIn("AGENT_CHECKPOINTS_COMPACTOR_ES_USER=agent_checkpoints_compactor", SERVICE_FILE)
        self.assertIn("compact_agent_checkpoints.py", SERVICE_FILE)

    def test_systemd_service_does_not_use_the_broken_environment_expansion_pattern(self):
        # #357 (security-auditor finding from #271's review, empirically
        # confirmed live via `systemd-run --user` against a throwaway unit):
        # systemd's Environment= directive does NOT expand ${VAR}
        # references — per systemd.exec(5), "$" has no special meaning
        # there. This unit originally shipped
        # `Environment=AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=${AGENT_CHECKPOINTS_COMPACTOR_PASSWORD}`,
        # which resolved to that literal string, not the real password —
        # the same bug class #259 already fixed once for
        # slo-metrics.service. Scans only non-comment lines — the unit's
        # own explanatory comment quotes the broken pattern verbatim as
        # documentation of what NOT to do, which a blanket substring
        # search would misread as a live regression.
        active_lines = [line for line in SERVICE_FILE.splitlines() if not line.strip().startswith("#")]
        for line in active_lines:
            self.assertNotIn(
                "Environment=AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=${AGENT_CHECKPOINTS_COMPACTOR_PASSWORD}", line)
        # security-auditor round 2: the assertion below previously scanned
        # the WHOLE file, including the explanatory comment above (which
        # quotes "AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=" verbatim as part of
        # documenting the broken pattern) — it would have passed even if
        # every functional reference were deleted. Scan active_lines only.
        self.assertTrue(any("AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=" in line for line in active_lines))
        self.assertIn("EnvironmentFile=-/run/suburban-soc-checkpoints-compact/"
                      "agent_checkpoints_compactor_password.env", SERVICE_FILE)

    def test_systemd_execstartpre_actually_extracts_the_secret_before_execstart(self):
        # security-auditor round 2 MEDIUM: the two tests above pin that the
        # broken line is gone and the EnvironmentFile= consumer is present,
        # but neither ever asserted the ExecStartPre that actually PRODUCES
        # the scratch file exists at all — deleting that one line leaves
        # EnvironmentFile=- silently tolerating a missing file (by design,
        # for the separate "blank .env is fine" case), so every ES call
        # would 401 daily with the full test suite still green. Pin its
        # content and its position ahead of ExecStart directly, mirroring
        # tests/pipeline/test_capture_loss_monitoring.py's
        # test_systemd_check_runs_in_execstartpre_not_execstart precedent.
        execstartpre_match = re.search(
            r"ExecStartPre=/bin/sh -c 'grep \"\^AGENT_CHECKPOINTS_COMPACTOR_PASSWORD=\".*"
            r"AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=.*"
            r"/run/suburban-soc-checkpoints-compact/agent_checkpoints_compactor_password\.env.*"
            r"grep -Eq \"\^AGENT_CHECKPOINTS_COMPACTOR_ES_PASS=\.\{8,\}\"",
            SERVICE_FILE)
        self.assertIsNotNone(
            execstartpre_match,
            "expected an ExecStartPre extracting AGENT_CHECKPOINTS_COMPACTOR_PASSWORD into the "
            "scratch file EnvironmentFile= reads, with a non-empty-value guard")
        execstart_pos = SERVICE_FILE.index("\nExecStart=/usr/bin/python3")
        self.assertLess(execstartpre_match.start(), execstart_pos)


if __name__ == "__main__":
    unittest.main()

"""setup_branch_protection.sh — the PUT it sends must only ever tighten `main`.

Runs the real script with a fake ``gh`` on PATH that serves a canned live
policy for the pre-PUT GET, records the PUT payload, and synthesises the
read-back GET from that payload. Asserts the properties #539's fix and the
follow-up hardening promise:

* live required checks are unioned in and keep their ``app_id`` pin; checks
  the script adds are pinned to the GitHub Actions app; no ``null`` app_id
  is ever sent (an unpinned check is not bound to the workflow app that
  produces it);
* a live review gate is preserved unless ``ALLOW_REVIEW_DOWNGRADE=1``;
  ``REQUIRE_REVIEW=1`` enables one (>=1 approval, stale dismissal) without
  lowering a stricter live count;
* push restrictions and the boolean sub-policies a full PUT would reset are
  carried forward from the live object;
* only an HTTP 404 bootstraps from nothing — any other read failure aborts
  before the PUT; flag values and the branch name are validated; a read-back
  that lost a required check is a failure, not a success banner.

Needs ``bash`` and ``jq`` on PATH (both present on ubuntu-latest and the
lab hosts); the test skips itself otherwise.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "setup" / "setup_branch_protection.sh"
ACTIONS_APP = 15368

SCRIPT_CHECKS = [
    "detections",
    "SOAR auth / exclusion / approval / tenant-scoping",
    "ruff (python)",
    "mypy (python)",
    "shellcheck (bash)",
    "yamllint (configs)",
    "pytest-cov >= 70% (slo_metrics / run_hunts / weekly_ciso_report)",
    "gitleaks",
    "Analyze (python)",
]

FAKE_GH = r"""#!/usr/bin/env bash
# Fake `gh` for tests. Records every call; PUT payloads are written to
# $FAKE_GH_PUT; GETs serve $FAKE_GH_LIVE until a PUT has happened, then a
# read-back synthesised from the PUT payload.
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GH_CALLS"
if [[ "${1:-}" == "api" && "${2:-}" == "-X" && "${3:-}" == "PUT" ]]; then
  cat > "$FAKE_GH_PUT"; echo '{}'; exit 0
fi
if [[ "${1:-}" == "api" ]]; then
  if [[ -s "$FAKE_GH_PUT" ]]; then
    jq --argjson drop "${FAKE_GH_READBACK_DROP:-0}" '{
      required_status_checks: {strict: .required_status_checks.strict,
        checks: (.required_status_checks.checks | if $drop == 1 then .[:-1] else . end)},
      enforce_admins: {enabled: .enforce_admins},
      required_pull_request_reviews: .required_pull_request_reviews,
      restrictions: (if .restrictions == null then null else
        {users: [.restrictions.users[] | {login: .}], teams: [.restrictions.teams[] | {slug: .}], apps: [.restrictions.apps[] | {slug: .}]} end),
      required_linear_history: {enabled: .required_linear_history}}' "$FAKE_GH_PUT"
    exit 0
  fi
  case "${FAKE_GH_GET_MODE:-ok}" in
    404)   echo '{"message":"Branch not protected","status":"404"}'
           echo "gh: Branch not protected (HTTP 404)" >&2; exit 1 ;;
    error) echo "gh: error connecting to api.github.com" >&2; exit 1 ;;
    *)     cat "$FAKE_GH_LIVE" ;;
  esac
  exit 0
fi
echo "fake gh: unexpected invocation: $*" >&2; exit 99
"""


def _tools_present() -> bool:
    return all(shutil.which(t) for t in ("bash", "jq"))


pytestmark = pytest.mark.skipif(not _tools_present(), reason="needs bash + jq on PATH")


def _live(**overrides):
    """A live-policy GET body in GitHub's shape (objects for users/teams/apps)."""
    base = {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": c, "app_id": ACTIONS_APP} for c in SCRIPT_CHECKS],
        },
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": None,
        "restrictions": None,
        "required_linear_history": {"enabled": False},
        "required_conversation_resolution": {"enabled": False},
        "block_creations": {"enabled": False},
        "lock_branch": {"enabled": False},
        "allow_fork_syncing": {"enabled": False},
    }
    base.update(overrides)
    return base


def run(tmp_path: Path, live=None, env=None, mode="ok", branch="main", readback_drop=False):
    shim = tmp_path / "bin"
    shim.mkdir()
    gh = shim / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    live_file = tmp_path / "live.json"
    live_file.write_text(json.dumps(live if live is not None else _live()))
    put_file = tmp_path / "put.json"
    calls = tmp_path / "calls.log"
    calls.write_text("")
    e = {
        **os.environ,
        "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
        "FAKE_GH_LIVE": str(live_file),
        "FAKE_GH_PUT": str(put_file),
        "FAKE_GH_CALLS": str(calls),
        "FAKE_GH_GET_MODE": mode,
        "FAKE_GH_READBACK_DROP": "1" if readback_drop else "0",
        "GH_REPO": "example/repo",
        "SKIP_CHANGELOG": "1",
    }
    for k in ("REQUIRE_REVIEW", "ALLOW_REVIEW_DOWNGRADE"):
        e.pop(k, None)
    e.update(env or {})
    proc = subprocess.run(
        ["bash", str(SCRIPT), branch], env=e, capture_output=True, text=True, timeout=60
    )
    payload = json.loads(put_file.read_text()) if put_file.exists() and put_file.stat().st_size else None
    return proc, payload, calls.read_text()


def _contexts(payload):
    return {c["context"] for c in payload["required_status_checks"]["checks"]}


class TestUnionAndPinning:
    def test_live_checks_are_kept_with_their_pin_and_new_ones_pinned_to_actions(self, tmp_path):
        live = _live()
        live["required_status_checks"]["checks"] = [
            {"context": "detections", "app_id": ACTIONS_APP},
            {"context": "third-party scanner", "app_id": 4242},
            {"context": "legacy-unpinned", "app_id": None},
        ]
        proc, payload, _ = run(tmp_path, live)
        assert proc.returncode == 0, proc.stderr
        checks = {c["context"]: c for c in payload["required_status_checks"]["checks"]}
        assert set(checks) == set(SCRIPT_CHECKS) | {"third-party scanner", "legacy-unpinned"}
        assert checks["third-party scanner"]["app_id"] == 4242, "live pin must survive"
        assert "app_id" not in checks["legacy-unpinned"], "never send app_id: null"
        for name in SCRIPT_CHECKS:
            if name != "detections":
                assert checks[name]["app_id"] == ACTIONS_APP, name
        assert payload["required_status_checks"]["strict"] is True
        assert payload["enforce_admins"] is True
        assert payload["allow_force_pushes"] is False and payload["allow_deletions"] is False

    def test_rerun_against_matching_live_policy_is_a_no_op_on_checks(self, tmp_path):
        proc, payload, _ = run(tmp_path, _live())
        assert proc.returncode == 0, proc.stderr
        assert _contexts(payload) == set(SCRIPT_CHECKS)
        assert all(c["app_id"] == ACTIONS_APP for c in payload["required_status_checks"]["checks"])

    def test_404_bootstraps_from_required_checks_only(self, tmp_path):
        proc, payload, _ = run(tmp_path, mode="404")
        assert proc.returncode == 0, proc.stderr
        assert "bootstrapping" in proc.stdout
        assert _contexts(payload) == set(SCRIPT_CHECKS)
        assert payload["required_pull_request_reviews"] is None
        assert payload["restrictions"] is None
        assert payload["required_linear_history"] is False


class TestReviewGate:
    LIVE_GATE = {
        "dismiss_stale_reviews": False,
        "require_code_owner_reviews": True,
        "required_approving_review_count": 2,
        "require_last_push_approval": False,
        "dismissal_restrictions": {"users": [{"login": "alice"}], "teams": [], "apps": []},
    }

    def test_live_review_gate_is_preserved_by_default(self, tmp_path):
        proc, payload, _ = run(tmp_path, _live(required_pull_request_reviews=self.LIVE_GATE))
        assert proc.returncode == 0, proc.stderr
        rev = payload["required_pull_request_reviews"]
        assert rev["required_approving_review_count"] == 2
        assert rev["require_code_owner_reviews"] is True
        assert rev["dismissal_restrictions"] == {"users": ["alice"], "teams": [], "apps": []}

    def test_live_review_gate_removed_only_with_explicit_downgrade(self, tmp_path):
        proc, payload, _ = run(
            tmp_path, _live(required_pull_request_reviews=self.LIVE_GATE),
            env={"ALLOW_REVIEW_DOWNGRADE": "1"},
        )
        assert proc.returncode == 0, proc.stderr
        assert payload["required_pull_request_reviews"] is None
        assert "removing the live review gate" in proc.stdout

    def test_require_review_enables_gate_without_lowering_a_stricter_live_count(self, tmp_path):
        proc, payload, _ = run(tmp_path, _live(), env={"REQUIRE_REVIEW": "yes"})
        assert proc.returncode == 0, proc.stderr
        rev = payload["required_pull_request_reviews"]
        assert rev["required_approving_review_count"] == 1 and rev["dismiss_stale_reviews"] is True

        second = tmp_path / "second"
        second.mkdir()
        proc, payload, _ = run(
            second, _live(required_pull_request_reviews=self.LIVE_GATE), env={"REQUIRE_REVIEW": "1"}
        )
        assert proc.returncode == 0, proc.stderr
        rev = payload["required_pull_request_reviews"]
        assert rev["required_approving_review_count"] == 2, "must not lower the live count"
        assert rev["dismiss_stale_reviews"] is True
        assert rev["require_code_owner_reviews"] is True


class TestCarryForward:
    def test_restrictions_and_boolean_subpolicies_survive_the_full_put(self, tmp_path):
        live = _live(
            restrictions={"users": [{"login": "release-bot"}], "teams": [{"slug": "soc-admins"}], "apps": []},
            required_linear_history={"enabled": True},
            required_conversation_resolution={"enabled": True},
            lock_branch={"enabled": True},
        )
        proc, payload, _ = run(tmp_path, live)
        assert proc.returncode == 0, proc.stderr
        assert payload["restrictions"] == {"users": ["release-bot"], "teams": ["soc-admins"], "apps": []}
        assert payload["required_linear_history"] is True
        assert payload["required_conversation_resolution"] is True
        assert payload["lock_branch"] is True
        assert payload["block_creations"] is False


class TestFailClosed:
    def test_non_404_read_failure_aborts_before_any_put(self, tmp_path):
        proc, payload, calls = run(tmp_path, mode="error")
        assert proc.returncode == 1
        assert payload is None
        assert "aborting" in proc.stderr and "PUT" not in calls

    def test_readback_missing_a_required_check_is_a_failure(self, tmp_path):
        proc, payload, _ = run(tmp_path, _live(), readback_drop=True)
        assert proc.returncode == 1
        assert "read-back after PUT is missing required checks" in proc.stderr
        assert "Done." not in proc.stdout

    @pytest.mark.parametrize("value", ["maybe", "01", "1 ", "yes\r"])
    def test_non_boolean_flag_values_are_rejected_not_treated_as_off(self, tmp_path, value):
        proc, payload, calls = run(tmp_path, env={"REQUIRE_REVIEW": value})
        assert proc.returncode == 2, proc.stderr
        assert payload is None and calls == ""

    @pytest.mark.parametrize("branch", ["main?x=1", "../other", "a b", "main#frag"])
    def test_unsafe_branch_names_are_rejected_before_any_api_call(self, tmp_path, branch):
        proc, payload, calls = run(tmp_path, branch=branch)
        assert proc.returncode == 2
        assert payload is None and calls == ""

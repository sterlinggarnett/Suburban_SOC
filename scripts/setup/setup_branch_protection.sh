#!/usr/bin/env bash
# =============================================================================
# setup_branch_protection.sh — WS3.5: enforce change management on main.
#
# Requires a repo ADMIN token (gh auth login as an admin). Enforces, on `main`:
#   * CI must pass: REQUIRED_CHECKS below, UNIONED with whatever is already
#     required live — a re-run can only add checks, never drop one (#539).
#   * enforce_admins: required checks bind admins too (owner decision, #509,
#     2026-09-03).
#   * branch up to date before merge; no force-push / deletion.
#   * PR review gate: OFF by default — owner decision in #509 (single
#     maintainer; a required approval would need a second GitHub account for
#     every merge). Set REQUIRE_REVIEW=1 to request 1 approval + stale-review
#     dismissal when a second reviewer exists.
# Idempotent toward the stricter state — safe to re-run.
#
# Verify the live policy before/after:
#   gh api repos/:owner/:repo/branches/main/protection \
#     --jq '{checks: .required_status_checks.contexts, admins: .enforce_admins.enabled, reviews: .required_pull_request_reviews}'
# =============================================================================
set -euo pipefail
BRANCH="${1:-main}"
REQUIRE_REVIEW="${REQUIRE_REVIEW:-0}"

# Required checks, by the job `name:` GitHub reports (see .github/workflows/).
# Not listed on purpose: "Python dependency audit (pip-audit)" (security-scan.yml
# does not run on every PR, so requiring it would block merges that never
# trigger it) and "CodeQL" (the per-language "Analyze (python)" job is the one
# that carries results).
REQUIRED_CHECKS=(
  "detections"                                                        # detections.yml
  "SOAR auth / exclusion / approval / tenant-scoping"                  # soar-tests.yml
  "ruff (python)"                                                     # lint.yml
  "mypy (python)"                                                     # lint.yml
  "shellcheck (bash)"                                                 # lint.yml
  "yamllint (configs)"                                                # lint.yml
  "pytest-cov >= 70% (slo_metrics / run_hunts / weekly_ciso_report)"  # reporting-coverage.yml
  "gitleaks"                                                          # secret-scan.yml
  "Analyze (python)"                                                  # codeql.yml
)

echo "==> Enforcing branch protection on '$BRANCH' (requires admin)"

# Union with the live required list so a stale copy of this script can never
# weaken the policy. Only a 404 (branch not yet protected) yields an empty
# list; any other read failure (auth, rate limit, network) aborts rather than
# being mistaken for "first run".
errf=$(mktemp); trap 'rm -f "$errf"' EXIT
if ! live_contexts=$(gh api "repos/:owner/:repo/branches/$BRANCH/protection" \
    --jq '.required_status_checks.contexts // []' 2>"$errf"); then
  if grep -q 'HTTP 404' "$errf"; then
    live_contexts='[]'
  else
    echo "!! could not read the live policy for '$BRANCH' — aborting so a transient" >&2
    echo "   error is not mistaken for an unprotected branch:" >&2
    cat "$errf" >&2
    exit 1
  fi
fi
contexts=$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . \
  | jq -s --argjson live "$live_contexts" '. + $live | unique')

if [[ "$REQUIRE_REVIEW" == "1" ]]; then
  reviews='{ "required_approving_review_count": 1, "dismiss_stale_reviews": true }'
else
  reviews='null'
fi

jq -n --argjson contexts "$contexts" --argjson reviews "$reviews" '{
  required_status_checks: { strict: true, contexts: $contexts },
  enforce_admins: true,
  required_pull_request_reviews: $reviews,
  restrictions: null,
  allow_force_pushes: false,
  allow_deletions: false
}' | gh api -X PUT "repos/:owner/:repo/branches/$BRANCH/protection" \
  -H 'Accept: application/vnd.github+json' --input - >/dev/null

echo "==> Done. '$BRANCH' now requires a CI-passed, up-to-date PR (admins included)."
echo "    required checks: $(jq -r 'join(", ")' <<<"$contexts")"
if [[ "$REQUIRE_REVIEW" == "1" ]]; then
  echo "    review gate: ON (1 approval, stale reviews dismissed)"
else
  echo "    review gate: OFF (owner decision, #509 — set REQUIRE_REVIEW=1 to enable)"
fi

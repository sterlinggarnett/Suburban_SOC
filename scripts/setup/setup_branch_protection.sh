#!/usr/bin/env bash
# =============================================================================
# setup_branch_protection.sh — WS3.5: enforce change management on main.
#
# Requires a repo ADMIN token (gh auth login as an admin). Applies, on `main`:
#   * CI must pass: REQUIRED_CHECKS below, UNIONED with the live required set.
#     Each live check keeps its app_id pin; checks this script adds are pinned
#     to the GitHub Actions app, so only that app's own runs count toward
#     them. A re-run can only add checks, never drop or un-pin one (#539).
#   * enforce_admins: required checks bind admins too (owner decision, #509).
#   * strict (branch up to date before merge); no force-push / deletion.
#   * PR review gate: OFF by default (owner decision, #509 — single
#     maintainer). REQUIRE_REVIEW=1 turns it on (>=1 approval, stale reviews
#     dismissed; any live settings such as code-owner review or dismissal
#     restrictions are kept). A review gate that is already live is PRESERVED
#     on re-run; removing it needs an explicit ALLOW_REVIEW_DOWNGRADE=1.
#   * Everything else a full PUT would otherwise reset — push restrictions,
#     linear history, conversation resolution, block_creations, lock_branch,
#     fork syncing — is read from the live policy and carried forward.
# Idempotent toward the stricter state — safe to re-run. A successful run
# reads the policy back, refuses to report success if any required check is
# missing from it, prints the live summary, and records a deploy-changelog
# entry (docs/deploy-changelog.md via deploy_changelog.sh).
#
# Env:  GH_REPO=owner/repo (default voltron-1/Suburban_SOC)   REQUIRE_REVIEW=1
#       ALLOW_REVIEW_DOWNGRADE=1   SKIP_CHANGELOG=1 (tests / dry environments)
# Verify at any time:
#   gh api repos/voltron-1/Suburban_SOC/branches/main/protection \
#     --jq '{checks: .required_status_checks.checks, admins: .enforce_admins.enabled, reviews: .required_pull_request_reviews}'
# =============================================================================
set -euo pipefail

BRANCH="${1:-main}"
REPO="${GH_REPO:-voltron-1/Suburban_SOC}"
GITHUB_ACTIONS_APP_ID=15368   # every check in REQUIRED_CHECKS is an Actions job
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Both values are interpolated into the API path — allow only ref-safe chars.
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]{1,244}$ && "$BRANCH" != *..* && "$BRANCH" != /* && "$BRANCH" != -* ]] \
  || { echo "!! invalid branch name: '$BRANCH'" >&2; exit 2; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$REPO" != *..* ]] || { echo "!! invalid GH_REPO: '$REPO'" >&2; exit 2; }

bool_flag() {  # <name> <value> -> prints 1/0; anything else is an error, not "off"
  case "${2,,}" in
    1|true|yes|on) echo 1 ;;
    0|false|no|off|"") echo 0 ;;
    *) echo "!! $1='$2' is not a boolean (use 1 or 0)" >&2; exit 2 ;;
  esac
}
# NB: keep these as bare assignments — `local`/`export`/`declare` would mask the
# subshell's exit 2 and turn a bad value into "off".
want_review=$(bool_flag REQUIRE_REVIEW "${REQUIRE_REVIEW:-0}")
allow_downgrade=$(bool_flag ALLOW_REVIEW_DOWNGRADE "${ALLOW_REVIEW_DOWNGRADE:-0}")
skip_changelog=$(bool_flag SKIP_CHANGELOG "${SKIP_CHANGELOG:-0}")

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

echo "==> Enforcing branch protection on $REPO@$BRANCH (requires admin)"

# --- 1. Read the live policy. Only an HTTP 404 (branch not yet protected) means
#        "start from nothing"; any other failure (auth, rate limit, network)
#        aborts so it cannot be mistaken for a first run.
errf=$(mktemp); trap 'rm -f "$errf"' EXIT
if ! live=$(gh api "repos/$REPO/branches/$BRANCH/protection" 2>"$errf"); then
  if grep -q 'HTTP 404' "$errf"; then
    live='{}'
    echo "    no protection on '$BRANCH' yet — bootstrapping from REQUIRED_CHECKS"
  else
    echo "!! could not read the live policy for $REPO@$BRANCH — aborting so a" >&2
    echo "   transient error is not mistaken for an unprotected branch:" >&2
    cat "$errf" >&2
    exit 1
  fi
fi
jq -e 'type == "object"' <<<"$live" >/dev/null 2>&1 \
  || { echo "!! live policy response is not a JSON object — aborting" >&2; exit 1; }

# --- 2. Build the payload: union checks, preserve everything else.
payload=$(printf '%s\n' "${REQUIRED_CHECKS[@]}" | jq -R . | jq -s \
  --argjson live "$live" --argjson want_review "$want_review" \
  --argjson allow_downgrade "$allow_downgrade" --argjson actions_app "$GITHUB_ACTIONS_APP_ID" '
  def slugs(o): {users: [(o.users // [])[] | .login], teams: [(o.teams // [])[] | .slug], apps: [(o.apps // [])[] | .slug]};
  def nonempty(o): (o != null) and (((o.users // []) + (o.teams // []) + (o.apps // [])) | length > 0);
  def review_payload(r):
      { dismiss_stale_reviews:          (r.dismiss_stale_reviews // false),
        require_code_owner_reviews:     (r.require_code_owner_reviews // false),
        required_approving_review_count:(r.required_approving_review_count // 0),
        require_last_push_approval:     (r.require_last_push_approval // false) }
      + (if nonempty(r.dismissal_restrictions) then {dismissal_restrictions: slugs(r.dismissal_restrictions)} else {} end)
      + (if nonempty(r.bypass_pull_request_allowances) then {bypass_pull_request_allowances: slugs(r.bypass_pull_request_allowances)} else {} end);

  . as $mine
  | ($live.required_status_checks.checks // []) as $live_checks
  | ($live_checks | map(.context)) as $live_names
  # older response shape: `contexts` only, no `checks` — keep those too, unpinned as they were
  | (($live.required_status_checks.contexts // []) - $live_names) as $legacy_only
  # live checks keep their pin; an unpinned live check that is one of ours gets the Actions
  # pin (tightening); unknown unpinned ones stay as they were; new ones are pinned to Actions
  | ( ($live_checks | map(if .app_id != null then {context: .context, app_id: .app_id}
                          elif (. as $c | $mine | index($c.context)) != null then {context: .context, app_id: $actions_app}
                          else {context: .context} end))
      + ($legacy_only | map(if (. as $c | $mine | index($c)) != null then {context: ., app_id: $actions_app} else {context: .} end))
      + ([$mine[] | select(. as $c | (($live_names + $legacy_only) | index($c)) == null)] | map({context: ., app_id: $actions_app}))
    ) as $checks
  | ($live.required_pull_request_reviews) as $live_rev
  | ( if $want_review == 1 then
        review_payload($live_rev // {})
          + { required_approving_review_count: ([ (($live_rev // {}).required_approving_review_count // 0), 1 ] | max),
              dismiss_stale_reviews: true }
      elif ($live_rev != null) and ($allow_downgrade == 0) then review_payload($live_rev)
      else null end
    ) as $reviews
  | {
      required_status_checks: { strict: true, checks: ($checks | sort_by(.context)) },
      enforce_admins: true,
      required_pull_request_reviews: $reviews,
      # presence-based on purpose: a restrictions object with empty actor lists is a
      # valid (stricter) policy, unlike dismissal/bypass lists where empty means off
      restrictions: (if $live.restrictions != null then slugs($live.restrictions) else null end),
      required_linear_history:          ($live.required_linear_history.enabled // false),
      required_conversation_resolution: ($live.required_conversation_resolution.enabled // false),
      block_creations:                  ($live.block_creations.enabled // false),
      lock_branch:                      ($live.lock_branch.enabled // false),
      allow_fork_syncing:               ($live.allow_fork_syncing.enabled // false),
      allow_force_pushes: false,
      allow_deletions: false
    }')

if [[ "$want_review" == 0 ]] && jq -e '.required_pull_request_reviews == null' <<<"$payload" >/dev/null \
   && jq -e '.required_pull_request_reviews != null' <<<"$live" >/dev/null 2>&1; then
  echo "    !! removing the live review gate (ALLOW_REVIEW_DOWNGRADE=1 given)"
fi

# --- 3. Apply.
gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
  -H 'Accept: application/vnd.github+json' --input - <<<"$payload" >/dev/null

# --- 4. Read back and compare the applied policy with the intent — not just the
#        check names: strict, enforce_admins, force-push/deletion, review gate,
#        restrictions, the carried booleans, and each pin we sent.
after=$(gh api "repos/$REPO/branches/$BRANCH/protection")
intent=$(jq -c '{
    checks: (.required_status_checks.checks | map({context: .context, app_id: (.app_id // "any")}) | sort_by(.context)),
    strict: .required_status_checks.strict, enforce_admins: .enforce_admins,
    allow_force_pushes: .allow_force_pushes, allow_deletions: .allow_deletions,
    review_count: (if .required_pull_request_reviews == null then null else .required_pull_request_reviews.required_approving_review_count end),
    restrictions: (if .restrictions == null then null else {users: (.restrictions.users | sort), teams: (.restrictions.teams | sort), apps: (.restrictions.apps | sort)} end),
    required_linear_history: .required_linear_history, required_conversation_resolution: .required_conversation_resolution,
    block_creations: .block_creations, lock_branch: .lock_branch, allow_fork_syncing: .allow_fork_syncing }' <<<"$payload")
drift=$(jq -r --argjson want "$intent" '
  { checks: ((.required_status_checks.checks // []) | map({context: .context, app_id: (.app_id // "any")})),
    strict: .required_status_checks.strict, enforce_admins: .enforce_admins.enabled,
    allow_force_pushes: (.allow_force_pushes.enabled // false), allow_deletions: (.allow_deletions.enabled // false),
    review_count: (if .required_pull_request_reviews == null then null else .required_pull_request_reviews.required_approving_review_count end),
    restrictions: (if .restrictions == null then null else {users: ([.restrictions.users[]? | .login] | sort), teams: ([.restrictions.teams[]? | .slug] | sort), apps: ([.restrictions.apps[]? | .slug] | sort)} end),
    required_linear_history: (.required_linear_history.enabled // false), required_conversation_resolution: (.required_conversation_resolution.enabled // false),
    block_creations: (.block_creations.enabled // false), lock_branch: (.lock_branch.enabled // false), allow_fork_syncing: (.allow_fork_syncing.enabled // false) } as $after
  | ([ $want | to_entries[] | select(.key != "checks") | select(.value != $after[.key]) | .key ]) as $fields
  | (($want.checks | map(.context)) - ($after.checks | map(.context))) as $missing
  | ([ $want.checks[] | select(.app_id != "any") | . as $w
       | select(([$after.checks[] | select(.context == $w.context) | .app_id] | first) != $w.app_id) | .context ]) as $unpinned
  | (if ($fields | length) > 0 then "fields not applied: " + ($fields | join(", ")) else empty end),
    (if ($missing | length) > 0 then "required checks missing: " + ($missing | join(", ")) else empty end),
    (if ($unpinned | length) > 0 then "app pin not applied: " + ($unpinned | join(", ")) else empty end)' <<<"$after")
if [[ -n "$drift" ]]; then
  echo "!! read-back after PUT does not match the intended policy:" >&2
  while IFS= read -r line; do echo "   $line" >&2; done <<<"$drift"
  exit 1
fi
summary=$(jq -r '
    "checks=" + ((.required_status_checks.checks // []) | map(.context) | sort | join(", "))
  + " | strict=" + (.required_status_checks.strict | tostring)
  + " | enforce_admins=" + (.enforce_admins.enabled | tostring)
  + " | review_gate=" + (if .required_pull_request_reviews == null then "off"
                         else "on (" + (.required_pull_request_reviews.required_approving_review_count | tostring) + " approval)" end)
  + " | restrictions=" + (if .restrictions == null then "none" else "set" end)
  + " | linear_history=" + ((.required_linear_history.enabled // false) | tostring)' <<<"$after")

echo "==> Done. Live policy on $REPO@$BRANCH:"
echo "    $summary"
if [[ "$want_review" == 0 ]]; then
  echo "    (review gate not requested — owner decision #509; REQUIRE_REVIEW=1 to enable)"
fi

# --- 5. Change-management evidence (SOP-007).
if [[ "$skip_changelog" == 0 && -x "$HERE/deploy_changelog.sh" ]]; then
  "$HERE/deploy_changelog.sh" "branch-protection ($REPO@$BRANCH)" "$summary" \
    || echo "    (deploy-changelog entry failed — the policy IS applied; record it by hand)" >&2
fi

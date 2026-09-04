# Executive Summary
This Standard Operating Procedure (SOP) ensures nothing that affects detection or response reaches production without a reviewed, CI-passed, and recorded change. It enforces GitHub branch protection, mandatory CI checks, and immutable deployment logs.

## Name
SOP-007 — Change Management on Detections & Config

## Problem Statement
Uncontrolled changes to detection rules, configurations, or response scripts can silently break the SOC pipeline, blind analysts, or introduce false positives. All changes must be traceable and reviewed.

## Objectives
- Enforce pull-request reviews via GitHub branch protection.
- Block bad changes automatically via CI gates (detections, gitleaks).
- Keep an immutable, auditable record of all deployments.

## Compliance
- **NIST CSF**: PR.IP-3 (Configuration Change Control).
- **SOC 2**: Security (Change Management).

## MITRE ATT&CK Framework
- Mitigates TA0005 Defense Evasion (e.g., T1562 Impair Defenses) by preventing unauthorized or unreviewed rule deletion.

## Assumptions and Limitations
- The repository is hosted on GitHub and utilizes GitHub Actions for CI.
- Deployments happen via authorized `deploy_detections.sh` and `deploy_dashboards.sh` scripts.

# Analysis
Change control acts as the gatekeeper for the SOC. It relies on GitHub's native branch protections combined with custom scripts that record deployments directly into an Elasticsearch index (`soc-deploys`).

## Monitoring and Notifications
CI gates provide immediate pass/fail notifications on PRs. The `deploy_changelog.sh` script logs successful deployments locally and to Elasticsearch.

## Playbook Verification
To verify the change management controls are active:
1. Verify branch protection: check `main` branch rules in GitHub.
2. Verify CI gates: check GitHub Actions runs for `detections` and `Security Scan`.
3. Verify deploy logs: check the `soc-deploys` index in Kibana and `docs/deploy-changelog.md`.

## Recommended Response Action(s)

### Identification
To verify if an unauthorized or unreviewed change occurred:
- Check `docs/deploy-changelog.md` or search the `soc-deploys` index for recent deployments.
- Cross-reference the commit hash with the merged PRs in GitHub.

### Containment
If a bad change reaches production:
- Revert the offending commit in git (`git revert <commit>`).
- Open a high-priority PR with the revert and fast-track the review.

### Eradication & Recovery
To restore proper change management controls if tampered with:
1. Check the live policy first, then re-apply it (repo admin only):
   `gh api repos/voltron-1/Suburban_SOC/branches/main/protection --jq '{checks: .required_status_checks.contexts, admins: .enforce_admins.enabled, reviews: .required_pull_request_reviews}'`
   then `./scripts/setup/setup_branch_protection.sh main`. The script unions its
   check list with whatever is already required, so a re-run can only tighten
   the policy (#539). Required checks bind admins too (`enforce_admins`, #509).
   The PR review gate is intentionally off while the repo has a single
   maintainer (owner decision, #509); pass `REQUIRE_REVIEW=1` to turn it on
   once a second reviewer exists.
2. Ensure `.github/CODEOWNERS` is intact.
3. Deploy the reverted state via `deploy_detections.sh` (or appropriate script), which will automatically log the recovery deploy.

# References and Resources
- `.github/workflows/detections.yml`
- `.github/workflows/lint.yml`
- `scripts/setup/deploy_changelog.sh`
- `docs/deploy-changelog.md`

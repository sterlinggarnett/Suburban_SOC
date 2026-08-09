# AGENTS.md

## Project Overview
Suburban-SOC is a mesh-network security monitoring pipeline: an OpenWrt router captures boundary traffic, Zeek parses it into structured JSON, Filebeat/Logstash enrich and route it into Elasticsearch, and Kibana visualizes it across four dashboards. A Flask-based SOC AI agent triages Kibana Watcher alerts (MITRE ATT&CK mapping) and drafts containment to a human-approval queue; a FastAPI "hive-mind broker" dispatches approved, HMAC-signed block requests to OpenWrt routers. The stack is multi-tenant (tenant.id on every event, per-tenant indices/roles/routing).

## Setup
- Copy `scripts/setup/.env.example` to `scripts/setup/.env` and set real values for `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, `LOGSTASH_PASSWORD`, `KIBANA_ENCRYPTION_KEY` (32+ chars).
- From `scripts/setup/`, run `docker compose up -d`.
- Known issue (#303): a fresh `docker compose up` currently fails to provision roles/service users because the `provision` service's `command:` is a plain string that Compose shell-word-splits, and it contains literal apostrophes that break tokenization. Check whether this is fixed before assuming a clean bring-up works.

## Testing
- Run `pytest` from the repo root (pythonpath is configured in `pyproject.toml`, no `sys.path` hacks needed).
- Key suites: `tests/ai_agent/`, `tests/detections/` (Sigma rule logic plus limited live-fire against real Elasticsearch), `tests/pipeline/` (Zeek/Sigma enrichment sync), and `tests/anomaly_simulation/` (manual, real-technique end-to-end validation, no mock data).
- Known flaky spot: `tests/ai_agent/test_slo_metrics.py::MainExitCodeTests` can fail locally if your `scripts/setup/.env` has a real `SLO_COVERAGE_MIN` override, since it isn't isolated from the mocked test run.

## Lint / Static Analysis
- CI runs an always-on gate: ruff, mypy, shellcheck, and yamllint (no path filters).
- Secret scanning via `.gitleaks.toml`. Never commit real secrets; escaped Compose variables like double-dollar VAR are intentional and allow-listed.

## Security-Sensitive Areas - Handle With Care
- The SOAR response flow is human-in-the-loop by default: the exclusion list is checked before anything else, and autonomous isolation only runs if an operator opts in via `AUTONOMOUS_ISOLATION=true`. Do not weaken the exclusion check or the atomic create-if-absent claim that guarantees `/approve` executes an isolation action at most once.
- `/approve` and `/pending` are HMAC-authenticated with separate credentials from `/alert`. Keep them separate, and fail closed (401) on unsigned or invalid requests.
- Every response action (isolation, notification) must stay scoped to the alerting tenant. Never broadcast across tenants.
- Secrets belong only in `.env`, never hardcoded; the Elastic stack runs with TLS + RBAC.

## Git / PR Workflow
- Always work on a branch and open a PR. Never push directly to `main`. A past direct merge to main skipped the pull-request-only CI security gate and silently reintroduced a double-execution race in the approval flow - do not repeat that.
- Use conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`, etc.).
- After a PR merges, close the linked GitHub issue(s) and update the project board before reporting the task complete.

## Known Gotchas to Check Before Starting Work
- Threat-intel feed (`configs/intel/intel.dat`) ships only placeholder indicators until `refresh_intel.sh` runs.
- Elasticsearch runs single-node, so there is no replica fault tolerance.
- HTTPS payload inspection is out of scope without a decryption proxy.

## Further Reading
- `docs/` (SOPs), `COMPLIANCE_MATRIX.md`, the GitHub Wiki, and the milestone table in `README.md` for current project status.

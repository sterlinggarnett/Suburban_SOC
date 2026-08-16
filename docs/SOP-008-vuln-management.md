# Executive Summary
This Standard Operating Procedure (SOP) governs the vulnerability management of the SOC platform itself. It ensures container images and Python dependencies are pinned, scanned, and patched on a defined cadence.

## Name
SOP-008 — Vulnerability Management of the SOC Stack

## Problem Statement
The SOC platform must not be the weak link. Unpatched dependencies or vulnerable container images can be exploited by an adversary to pivot into the SOC network or tamper with evidence.

## Objectives
- Pin exact versions of all dependencies for reproducible and auditable builds.
- Block the merge of critical vulnerabilities via automated image scanning (Trivy).
- Enforce a weekly patch cadence for dependencies via pip-audit.

## Compliance
- **NIST CSF**: ID.RA-1 (Vulnerabilities are identified), PR.IP-12 (Vulnerability management plan).
- **SOC 2**: Security (Vulnerability Management).

## MITRE ATT&CK Framework
- Mitigates TA0001 Initial Access (T1190 Exploit Public-Facing Application).

## Assumptions and Limitations
- The `Security Scan` CI workflow is active in GitHub Actions.
- Exception tracking is required for unpatchable upstream vulnerabilities.

# Analysis
The SOC stack relies on Docker containers (agent, broker, ELK) and Python dependencies. Vulnerability scans are automated in CI but require a human-in-the-loop weekly patch cycle to update dependency pins.

## Monitoring and Notifications
Trivy and pip-audit failures will block PRs with a red CI status. The weekly scheduled CI run (Mondays 06:00 UTC) will alert the repository owner of new vulnerabilities.

## Playbook Verification
To verify vulnerability management controls:
1. Inspect `scripts/setup/ai_agent/requirements.txt` to ensure exact version pins (`==`).
2. Verify the `Security Scan` workflow runs Trivy with `severity: CRITICAL, exit-code: 1`.
3. Verify the third-party `zeek/zeek` image (#293's tag+digest pin — the one
   image this SOC depends on that isn't built from this repo's own
   Dockerfiles) is covered by the same gate: the `zeek-image` job resolves
   its scan target directly from `tests/pipeline/test_zeek_image_pin.py`'s
   `EXPECTED_TAG`/`EXPECTED_DIGEST`, so it can never silently scan a stale
   reference (#355).

## Recommended Response Action(s)

### Identification
When a vulnerability is identified by CI (either on a PR or the weekly run):
- Review the Trivy or pip-audit findings in the GitHub Actions log.
- Determine if an updated, patched version of the dependency exists.

### Containment
If a critical vulnerability is found in a deployed image:
- Restrict network access to the affected service if patching is delayed.
- If no fix is available, evaluate if the vulnerable component can be temporarily disabled or if an exception is warranted.

### Eradication & Recovery
To remediate dependencies:
1. Bump the version in `requirements.txt` to the patched version.
2. Re-run the test suites to ensure no breaking changes.
3. If patching is impossible (e.g., upstream blocker), log the exception in the "Tracked Exceptions" section of this document.

**Tracked Exceptions:**
| Advisory | Package | Reason | Review |
|---|---|---|---|
| PYSEC-2026-161 | starlette | Fix is 1.0.1; FastAPI caps starlette `< 0.50`. Medium severity. | Re-check weekly; remove `--ignore-vuln` once FastAPI supports starlette ≥ 1.0. |

# References and Resources
- `.github/workflows/security-scan.yml`
- `scripts/setup/ai_agent/requirements.txt`
- `scripts/hive-mind-broker/requirements.txt`
- `tests/pipeline/test_zeek_image_pin.py` — authoritative source for the
  `zeek/zeek` image reference the `zeek-image` Trivy job scans; bumping
  the pin (see `configs/systemd/zeek-host-capture.service`'s own header
  comment for the full process) automatically changes what this job scans

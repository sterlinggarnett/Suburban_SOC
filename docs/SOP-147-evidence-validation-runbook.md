# Executive Summary
This Standard Operating Procedure (SOP) serves as the evidence validation runbook to replace mock data with real, attributable telemetry. It guarantees every dashboard panel and detection works end-to-end, logging undeniable proof (SHA-256 hashes of screenshots) of SOC operations.

## Name
SOP-147 — Evidence Validation Runbook

## Problem Statement
Relying on fabricated or mock data for SOC dashboards provides false confidence. Auditors require proof that the pipeline processes real telemetry and correctly triggers response actions.

## Objectives
- Purge all fabricated indices and documents.
- Generate real telemetry using the simulation harness or actual boundary capture.
- Log tamper-evident screenshots (SHA-256, UTC window, Source IP) for every validated technique.

## Compliance
- **NIST CSF**: DE.DP-4 (Detection processes are tested), PR.IP-10 (Response plans tested).
- **SOC 2**: Security (Continuous Monitoring & Evidence Collection).

## MITRE ATT&CK Framework
- Validates the entire ATT&CK matrix coverage mapped in `configs/detections/emulation_telemetry.map`.

## Assumptions and Limitations
- Requires a fully healthy stack (`stack_health.sh` passes).
- Real boundary capture (Path B) requires an OpenWrt mesh and careful L2 routing verification to ensure traffic crosses the captured interface.

# Analysis
This runbook builds on SOP-022. It formalizes the execution into a strict compliance exercise where every step must be documented, hashed, and tracked in `evidence/README.md`.

## Monitoring and Notifications
Evidence collection is manual but relies on the automated logging of the AI Agent and Kibana Watcher to produce the required alerts and audit trails.

## Playbook Verification
To verify the system is ready for an evidence run:
1. Run `python tests/validate_emulation_map.py` to ensure 22/22 techniques map correctly.
2. Confirm the stack is green and mock indices (`.alerts-security.alerts-mock`, `logstash-dynamic-*`) are deleted.

## Recommended Response Action(s)

### Identification
Define the testing path and record the UTC window:
- **Path A:** Use the local simulation harness (`run_all.sh`).
- **Path B:** Use real boundary capture (`stream_capture.sh bat0`), ensuring traffic physically crosses the interface.
- Record `WINDOW_START` and `WINDOW_END`.

### Containment
Execute the simulation loops and collect evidence per technique:
1. **Port scan:** `./sim_portscan.sh` → Screenshot `Scan::Port_Scan`.
2. **SSH brute force:** `./sim_brute_ssh.sh` → Screenshot 5+ `auth_success=false`.
3. **Malware download:** `./sim_malware_download.sh` → Screenshot `application/zip` in `files.log`.
   **#383/#413: telemetry only** — `application/zip` is not in
   `net_zeek_executable_download.yml`'s `mime_type` list, so this does not
   validate the T1105 detection rule (see `docs/SOP-147-evidence-validation-procedure.md` Step A.3).
4. **Live Intel:** `./sim_intel_match.sh` → Screenshot `threat.indicator.ip` hit.

### Eradication & Recovery
To finalize the evidence package:
1. Hash every screenshot: `sha256sum evidence/screenshots/<name>.png`.
2. Record the hash, UTC window, source IP, and index in `evidence/README.md` and the GitHub Wiki.
3. Verify the OpenWrt quarantine was executed and subsequently remove the test firewall rules (as per SOP-022).

# References and Resources
- [Detailed Procedure](./SOP-147-evidence-validation-procedure.md) — Section 0 prerequisites (including the Path B mesh capture recipe), Sections A–E, Definition of Done (#215)
- `evidence/README.md`
- `tests/validate_emulation_map.py`
- `tests/anomaly_simulation/run_all.sh`

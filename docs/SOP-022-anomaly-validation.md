# Executive Summary
This Standard Operating Procedure (SOP) defines the end-to-end procedure for validating that the Suburban-SOC pipeline correctly detects three canonical attack scenarios and that the SOAR layer responds at machine-speed by quarantining the offending device's MAC address.

## Name
SOP-022 — Anomaly Validation via Attack Simulation

## Problem Statement
A SOC without validated detections is a black box. Operators must routinely prove that the entire pipeline—from Zeek capture through Elasticsearch indexing to SOAR response—functions as expected against known attack patterns.

## Objectives
- Simulate network reconnaissance (port scanning), SSH brute-forcing, and suspicious downloads (EICAR).
- Verify these events are correctly indexed and parsed.
- Validate that the AI Agent and SOAR isolation scripts successfully quarantine the simulated attacker.

## Compliance
- **NIST CSF**: DE.DP-4 (Detection processes are tested), PR.IP-10 (Response plans tested).
- **CIS Controls**: Control 13 (Network Monitoring and Defense).

## MITRE ATT&CK Framework
- Validates detection for TA0007 Discovery (T1046 Network Service Discovery), TA0006 Credential Access (T1110 Brute Force), and TA0009 Collection.

## Assumptions and Limitations
- The simulation harness `tests/anomaly_simulation` requires a reachable Elasticsearch cluster and an active AI agent.
- **SAFETY WARNING:** These scripts generate real attack traffic. They must only target `127.0.0.1` or explicitly authorized lab equipment.

# Analysis
The validation relies on python-based simulation scripts generating traffic, Zeek capturing it, and Kibana Watcher / AI Agent triggering the response. End-to-end success means the target MAC is dropped by OpenWrt's firewall.

## Monitoring and Notifications
The `run_all.sh` harness outputs terminal status. The AI Agent pushes `ntfy` and Discord alerts upon quarantine execution.

## Playbook Verification
To verify the harness is ready:
1. Run `./preflight.sh` inside `tests/anomaly_simulation`.
2. Ensure every prerequisite is green.

## Recommended Response Action(s)

### Identification
To run the attack simulations and verify detections:
- `cd tests/anomaly_simulation`
- Ensure `.env` is configured (defaulting to localhost).
- Execute `./run_all.sh`

Expected output will confirm detections for Port Scan, Brute Force, and Malware Download.

### Containment
To trigger and validate the SOAR quarantine path:
1. Ensure the Kibana Watcher (`soar_quarantine_alert.json`) is installed.
2. POST a synthetic alert to the AI Agent (`http://localhost:5000/alert`).
3. Run `./verify_quarantine.sh <TARGET_MAC>` to confirm the OpenWrt `uci` rule is active.

### Eradication & Recovery
To recover the router state after the drill:
1. Tear down the test rule on OpenWrt to restore connectivity.
2. `ssh root@192.168.1.1 "uci show firewall | grep -oE '@rule\[[0-9]+\]' | head -1 | xargs -I{} sh -c 'uci delete firewall.{} && uci commit firewall && /etc/init.d/firewall restart'"`
*(Caution: Verify the rule index manually before automated deletion in production).*

# References and Resources
- [Detailed Procedure](./SOP-022-anomaly-validation-procedure.md) — prerequisites table, numbered steps, detection-mapping table, troubleshooting matrix, evidence-capture checklist (#215)
- `tests/anomaly_simulation/run_all.sh`
- `tests/anomaly_simulation/preflight.sh`
- `rules/elastic_watcher/soar_quarantine_alert.json`

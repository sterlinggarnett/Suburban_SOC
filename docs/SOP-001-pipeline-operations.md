# Executive Summary
This Standard Operating Procedure (SOP) defines the step-by-step procedures for operating the Suburban-SOC network monitoring pipeline. It covers traffic capture from the OpenWrt mesh router, log parsing via Zeek, log shipping via Filebeat/Logstash, and visualization in Kibana.

## Name
SOP-001 — Pipeline Operations

## Problem Statement
A standardized process is required to ensure consistent and reliable operation of the SOC monitoring pipeline. Without clear instructions, operators may fail to capture traffic correctly or misconfigure log shipping, leading to blind spots.

## Objectives
- Provide clear procedures for capturing live and offline network traffic.
- Standardize the installation and configuration of Filebeat and Logstash.
- Detail the end-to-end pipeline startup sequence and troubleshooting steps.

## Compliance
- **NIST CSF**: PR.PT-4, DE.AE-3 (Continuous monitoring and log collection).
- **CIS Controls**: Control 8 (Audit Log Management).

## MITRE ATT&CK Framework
- TA0007 Discovery (Network sniffing and traffic capture).
- TA0009 Collection.

## Assumptions and Limitations
- The ELK stack (Elasticsearch, Logstash, Kibana) must be deployed and reachable.
- SSH access to the mesh router (`10.18.81.1`) is available.
- Docker must be running on the host system.

# Analysis
The pipeline operations cover capturing traffic on specific interfaces (bat0, br-lan, eth0), configuring Filebeat to watch Zeek logs, and routing them through Logstash to Elasticsearch.

## Monitoring and Notifications
Logstash and Filebeat provide logs for pipeline operations. Output data should visibly populate Kibana dashboards (e.g., `logstash-*` data view).

## Playbook Verification
To verify the pipeline is fully operational:
1. Ensure Elasticsearch is healthy (`curl -k -u "elastic:$ELASTIC_PASSWORD" https://localhost:9200`).
2. Verify Filebeat service is running (`sudo systemctl status filebeat`).
3. Check for new `.log` files in `/storage/PCAP/zeek_logs/`.

## Recommended Response Action(s)

### Identification
Use the following procedures depending on the required capture source:

- **SOP-001-A (bat0):** `scripts/setup/stream_capture.sh bat0` (mesh node-to-node)
- **SOP-001-B (br-lan):** `scripts/setup/stream_capture.sh br-lan` (standard wired/wireless)
- **SOP-001-C (eth0):** `sudo scripts/setup/stream_capture.sh raw` (local host traffic)
- **SOP-001-D (Offline PCAP):** `scripts/setup/zeek_run_pcap.sh` for static files.

### Containment
If the pipeline must be halted or reset:
- Stop captures via `Ctrl+C` in the running terminal.
- Run `sudo ./scripts/setup/clear_logs.sh` to permanently clear the Zeek logs directory (destructive).

This is pipeline-halt containment (stopping capture/ingest), not device-level
containment. **Device quarantine (SOAR)** is a separate path this SOP does not
cover: a detection dispatches an HMAC-signed request to the Hive-Mind Broker,
which holds it in a human-approval queue (`POST /approve`) before an OpenWrt
`uci` firewall rule isolates the target device — see
[README's Architecture section](../README.md#architecture) for the full flow
and `docs/SOP-022-anomaly-validation.md` for how to exercise it end-to-end.

### Eradication & Recovery
To recover or start the pipeline from scratch:
1. Start Docker and the ELK stack (`docker compose up -d`).
2. Verify Elasticsearch and Kibana are accessible.
3. Start Filebeat (`sudo systemctl start filebeat`).
4. Begin traffic capture using the scripts above.
5. Confirm logs are flowing into Elasticsearch.

Troubleshooting common issues:
- **SSH connection refused**: Verify router IP (`10.18.81.1`).
- **Filebeat TLS handshake fails**: Re-provision host Filebeat CA + client cert if the `certs` volume was reset.
- **No data in Kibana**: Ensure the capture script targets the correct active interface (if the interface is correct and the fix above doesn't apply, check the time-range cause in `docs/master_pipeline_guide.md`'s troubleshooting table instead).

For issues beyond capture/interface scope (ES cluster-red, Logstash crash-loops, a silently dead Zeek sensor, failing detection CI, etc.), see `docs/master_pipeline_guide.md`'s "Troubleshooting Quick Reference" table — the canonical troubleshooting reference for this pipeline.

# References and Resources
- [Architecture Diagram](../docs/architecture-diagram.png)
- [Logstash Config](../configs/logstash.conf)
- [Zeek ELK Pipeline Docs](../docs/Zeek_ELK_Pipeline.md)
- [Network Topology](../docs/network_topology.md)
- [Wiki: Architecture](https://github.com/voltron-1/Suburban_SOC/wiki/Architecture)

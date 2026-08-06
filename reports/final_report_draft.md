# Suburban-SOC Final Report

> **Note:** The canonical version of this report lives on the [GitHub Wiki](../../wiki/Final-Report). This file is a repo-tracked mirror for PR review and offline reference.

## Executive Summary
The Suburban-SOC project addresses the growing need for enhanced cybersecurity in residential environments. By establishing a mesh-based wireless network with centralized Security Operations Center (SOC) management, it replaces insecure home networks with a unified, enterprise-grade security system. The pipeline captures and analyzes boundary network traffic, automatically detects threats, and closes the detect-and-respond loop via a SOAR layer that can quarantine offending devices at the router level — with LLM-assisted triage, ntfy mobile push alerts, and Discord SOC-channel notifications delivered in parallel.

## Network Architecture & Scope
*   **Mesh Network Architecture:** Built around a single main gateway router acting as the mesh controller, distributing access through 6 remote wireless nodes.
*   **Targeted Monitoring:** We exclusively monitor and capture boundary traffic (HTTP, DNS, SSH, and other protocols) entering and exiting the main router.
*   **Security Justification:** This targeted approach ensures system efficiency by bypassing internal LAN noise (like local file sharing) and heavily encrypted tunnel traffic, avoiding unnecessary resource drain.
*   **Physical Flow:** ISP ➔ Main Gateway Router ➔ 6 Remote Wireless Nodes ➔ End-User Devices.

## Data Acquisition
*   **Implementation:** Using OpenWrt, we enabled remote packet capture directly on the gateway router. SSH tunneling (`tcpdump -i br-lan -w - -U`) streams the live packet feed to the host machine.
*   **Flow & Storage:** The router mirrors the targeted network traffic and securely forwards it to a centralized host computer. This ensures continuous storage of raw `.pcap` files without overwhelming the router's limited local storage.

## Processing Pipeline (Zeek & Filebeat)
*   **Zeek Integration:** Raw PCAPs and live streams are processed by Zeek (installed natively at `/opt/zeek/bin/zeek`), configured with `LogAscii::use_json=T` to output structured, human-readable JSON security logs.
*   **Layer-2 Enrichment (planned, not currently functional — [#286](https://github.com/voltron-1/Suburban_SOC/issues/286)):** The `policy/protocols/conn/mac-logging` Zeek policy would make every `conn.log` row carry `orig_l2_addr` and `resp_l2_addr` — the MAC addresses required for device-level (not just IP-level) quarantine response — but it was only ever loaded by a Zeek config file no real capture path reads, so `source.mac` has been empty in every SOAR case record to date.
*   **Log Shipping:** A Filebeat agent (`filebeat.yml`, using `type: filestream`) continuously monitors the Zeek output directory, harvesting the generated `.log` files and forwarding them to Logstash on port `5044`.
*   **Pipeline Flow:** OpenWrt Router (raw stream) ➔ Host Computer ➔ Zeek (JSON + MAC enrichment) ➔ Filebeat (Harvests & Ships).

## Visualization & ELK Integration
*   **Stack:** ELK 9.3.2 (Elasticsearch, Kibana, Logstash, Filebeat) deployed via Docker Compose (`scripts/setup/docker-compose.yml`), with xpack security and TLS enabled for all inter-service communication.
*   **Logstash Routing:** Filebeat streams logs into Logstash (port `5044`), which parses the data and applies GeoIP enrichment. A `source.mac`/`destination.mac` mapping exists in Logstash's config but lives in a branch real Filebeat-shipped Zeek data never reaches — tracked in [#286](https://github.com/voltron-1/Suburban_SOC/issues/286).
*   **Elasticsearch Storage:** Enriched logs are indexed daily (`logstash-security-%{+YYYY.MM.dd}`), enabling rapid and efficient queries.
*   **Three-Index Architecture:**
    *   `logstash-security-*` — raw telemetry data lake (Zeek network events, endpoint logs); powers all primary SOC dashboards.
    *   `.alerts-security.alerts-*` — high-fidelity SIEM alerts generated when detection rules (Sigma/EQL) match against raw telemetry.
    *   `soar-actions-*` — automated response audit trail; logs every SOAR action for MTTD tracking and accountability.
*   **Kibana Dashboard:** A user-friendly interface visualizes network trends and anomalies, allowing SOC analysts to monitor both real-time and historical security events.

## SOAR Response Layer
*   **Trigger:** Two complementary detection paths feed the AI agent's signed `/alert` webhook:
    *   **Live Intel / C2 (ingest-time)** — `configs/logstash.conf` signs and POSTs `/alert` the moment a Zeek **Intel-framework** match is enriched to `threat.indicator.value` (WS1.1). This replaces the legacy `threat.indicator.domain` path, which the pipeline never populates.
    *   **Kibana Watcher** (`soar_quarantine_alert`, `rules/elastic_watcher/soar_quarantine_alert.json`) polls every minute against `logstash-security-*` and fires on:
        *   **Port Scan** — `zeek.notice` events where `note = Scan::Port_Scan`.
        *   **SSH Brute Force** — 5 or more `auth_success=false` events from the same `source.ip` in `zeek.ssh` within the polling window (`min_doc_count: 5`).
    *   *(The watcher still carries a legacy `threat.indicator.domain` clause; because that field is unpopulated, live-intel detection runs through the Logstash path above — not the watcher.)*
*   **AI Triage:** The Flask-based `soc_ai_agent` service (port `5000`) receives the Watcher webhook, calls an LLM (`llama3.1` via local Ollama by default; hosted model gated behind `LLM_ALLOW_HOSTED=true`) to summarize the threat and map it to MITRE ATT&CK, and classifies severity.
*   **Human-Approval Queue:** Per CDP §12.3, the agent drafts an isolation action and enqueues it for a human-of-record to approve via `POST /approve`. Because `/approve` (and `/pending`) execute/disclose containment, both are HMAC-authenticated — the caller signs the request body (`x-elastic-signature`), and an unsigned call fails closed (401). Since #246, `/approve` and `/pending` verify against a SEPARATE secret (`SOC_APPROVER_HMAC_SECRET`) from `/alert`'s (`SOC_AGENT_HMAC_SECRET`, held by Logstash) — a Logstash compromise can no longer approve/view the isolation actions it can draft, and the recorded `approver` is derived from that credential's configured identity, not a caller-supplied request field. Autonomous execution is gated behind `AUTONOMOUS_ISOLATION=true`.
*   **Quarantine:** Upon approval (or the autonomous flag), the slim agent — which has no ssh/sudo — routes containment to the **Hive-Mind Broker** over an HMAC-signed, replay-protected webhook (#109). The broker applies an `nftables` DROP for the attacker IP (`nft add rule inet fw4 input ip saddr <ip> drop`) on the alerting tenant's OpenWrt router(s) from its per-tenant inventory; it never broadcasts across tenants. (The standalone `isolate.sh` MAC-based `uci` rule is the legacy single-router path it replaced.)
*   **Exclusion List:** The `governance/exclusion_list.txt` prevents the agent from ever isolating core infrastructure (e.g., the gateway itself).
*   **Notifications:** ntfy mobile push + Discord SOC channel embed delivered in parallel, both carrying device IP, MAC, reason, and the AI-generated analysis.
*   **Weekly CISO Report:** `POST /weekly-report` triggers an automated pipeline (`weekly_ciso_report.py`) that queries Elasticsearch for alert metrics, computes MTTD and NIST CSF distribution, generates an LLM executive summary, compiles a PDF via WeasyPrint, and delivers it to Slack + ntfy.

## Challenges & Limitations
1.  **Encrypted Traffic Blind Spot:** The pipeline monitors boundary traffic but cannot inspect deep HTTPS payloads without an active SSL/TLS proxy. SSL/TLS interception would require deploying a man-in-the-middle proxy (e.g., mitmproxy) and managing certificate trust for all client devices.
2.  **Human-in-the-Loop Quarantine (by Design):** Per CDP §12.3, the AI agent drafts isolation actions and enqueues them for a human-of-record to approve rather than executing autonomously. This is an intentional governance control, not a technical gap, but it means response time is bounded by analyst availability in the default configuration.
3.  **Unbenchmarked Stress Limits:** The OpenWrt gateway's continuous packet-streaming capability has not yet been stress-tested for stability under extreme network loads. It is unknown at what sustained throughput Zeek or Logstash begin dropping events.
4.  **Single-Node Elasticsearch:** The current deployment runs Elasticsearch on a single node, which means index health is permanently `yellow` (replica shards unassigned). This is acceptable for a lab environment but provides no redundancy.

## Future Enhancements
*   **SSL/TLS Decryption Proxy:** Implement an inspection proxy (e.g., mitmproxy) to analyze deep HTTPS payloads, eliminating the encrypted traffic blind spot.
*   **Live Threat Intelligence Feed:** Pipe continuously updated malicious-IP and file-hash lists directly into Zeek so unknown indicators light up the existing Watcher pathway already in production.
*   **Quarantine Auto-Rollback:** Add a 24-hour TTL to `SOAR_QUARANTINE_<MAC>` rules with a mandatory analyst-approval step before converting a temporary block into a permanent one.
*   **Stress Benchmarking:** Drive sustained high-volume packet streams from the OpenWrt gateway and chart Zeek/Logstash throughput vs. drop rate to establish operational capacity limits.
*   **Multi-Node Elasticsearch Cluster:** Add replica shards to achieve `green` index health and provide resilience against single-node failure.

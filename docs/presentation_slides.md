# Suburban-SOC Presentation Slides

![Title Slide](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_0_title_updated_1779896975035.png)

**Developed By:**
*   **Thomas Lammers** - System Architect and Lead Engineer
*   **Sterling Garnett** - Security Analyst and Engineer

This document contains the finalized content for the Suburban-SOC project presentation, fulfilling the requirements for Milestone 6.

---

### Slide 1: Network Topology & Monitoring Scope

![Slide 1 Topology](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_1_topology_1779894028060.png)

**Associated Milestone:** Milestone 1: Topology

*   **Mesh Network Architecture:** Built around 1 main gateway router acting as the mesh controller, with 6 remote wireless nodes distributing access.
*   **Traffic Scope:** We exclusively monitor and capture boundary HTTP traffic entering and exiting the main router.
*   **Security Justification:** This targeted approach avoids processing internal LAN noise (like local file sharing) and prevents resource drain from heavily encrypted tunnel traffic.
*   **Physical Flow:** ISP ➔ Main Gateway Router ➔ 6 Remote Wireless Nodes ➔ End-User Devices.

---

### Slide 2: Data Acquisition via OpenWrt

![Slide 2 Acquisition](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_2_acquisition_1779894040601.png)

**Associated Milestone:** Milestone 2: Data Acquisition (The Mesh capture)

*   **Objective:** Configure the physical mesh nodes to stream raw traffic directly to our host.
*   **Implementation:** Leveraged OpenWrt to enable remote packet capture on the gateway.
*   **The Flow:** The Router mirrors the targeted network traffic and forwards it to the Host computer.
*   **Outcome:** Secure, continuous storage of raw `.pcap` files on the centralized host for further processing, preventing the router's local storage from being overwhelmed.

---

### Slide 3: The Processing Pipeline (Zeek & Filebeat)

![Slide 3 Pipeline](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_3_pipeline_1779894053538.png)

**Associated Milestone:** Milestone 3: The Processing Pipeline (Zeek & Agent)

*   **Objective:** Automate the transformation of raw network packets into structured, human-readable security logs.
*   **Zeek Integration:** Processed raw PCAPs using a Zeek container natively configured (`LogAscii::use_json=T`) to output structured JSON logs.
*   **Layer-2 Enrichment:** Loaded the `policy/protocols/conn/mac-logging` policy so every `conn.log` row carries `orig_l2_addr` and `resp_l2_addr` — the foundation for device-level (not just IP-level) response.
*   **Log Shipping:** Configured a Filebeat agent (`filebeat.yml`) to actively monitor the Zeek output directory (`*.log`).
*   **The Flow:** Host Computer (Raw PCAP) ➔ Zeek (JSON Transformation) ➔ Filebeat (Harvests & Ships JSON files).

---

### Slide 4: Data Visualization & ELK Integration

![Slide 4 ELK](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_4_elk_1779894066461.png)

**Associated Milestone:** Milestone 4: Data Visualization (ELK Integration)

*   **Objective:** Finalize data ingestion to create a human-readable, centralized security dashboard.
*   **Logstash Routing:** Filebeat streams logs directly into Logstash (Port `5044`), which parses the data, applies GeoIP enrichment, and maps Zeek `orig_l2_addr` / `resp_l2_addr` to ECS `source.mac` / `destination.mac`.
*   **Elasticsearch Storage:** Enriched logs are indexed using a scalable daily categorization strategy (`logstash-security-%{+YYYY.MM.dd}`) for rapid searching.
*   **Kibana Dashboard:** Visualizes network trends and anomalies, allowing SOC analysts to monitor real-time and historical security events through an intuitive GUI.

---

### Slide 5: SOAR Response Layer — Automated Quarantine

![Slide 5 SOAR](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_5_soar_1779894082139.png)

**Associated Milestone:** Milestone 5: Advanced Features / Automation

*   **Objective:** Close the detect-and-respond loop. The earlier slides build the *detection* plane; M5 adds *response* at machine speed.
*   **Trigger:** A Kibana Watcher (`soar_quarantine_alert`) polls every minute for `zeek.conn` events that match high-confidence indicators (initial scope: `threat.indicator.domain`) and POSTs the offending device's IP **and MAC** to a Flask AI Agent on `:5000`.
*   **AI Triage:** The agent calls an LLM to summarize the alert against MITRE ATT&CK, classifies severity, and decides whether the event warrants automated quarantine.
*   **Quarantine:** For critical events, `isolate.sh` SSHes into the OpenWrt router and installs a persistent `uci` MAC-based DROP firewall rule (`SOAR_QUARANTINE_<MAC>`). The rule is idempotent — re-firing on the same MAC is a no-op.
*   **Why MAC over IP:** Survives DHCP rotation and is harder to spoof at Layer 2, so the offender stays quarantined even after rebooting and pulling a new lease.
*   **Notification:** ntfy mobile push + Discord SOC channel embed delivered in parallel; both carry device IP, MAC, reason, and the AI-generated analysis.

---

### Slide 6: Validation via Anomaly Simulation
**Associated Milestone:** Milestone 6: Presentation / Sprint 6 (Issue #22)

*   **Objective:** Prove the detection + response pipeline reacts correctly to real attack patterns — not just unit-tested code, but the live wire.
*   **Three Canonical Scenarios:**
    *   **Reconnaissance** — `nmap -sS` SYN scan → Zeek `notice.log` should fire `Scan::Port_Scan`.
    *   **Brute Force** — 5+ failed SSH auths via `sshpass` → `zeek.ssh` should record 5+ rows with `auth_success=F`.
    *   **Suspicious Download** — EICAR test ZIP via `curl` → `zeek.files` should record `mime_type=application/zip`.
*   **Test Harness (`tests/anomaly_simulation/`):** Three sim scripts, a Python verifier that asserts each detection landed in Elasticsearch within a lookback window, an OpenWrt verifier that confirms the `uci` quarantine rule was installed, and a `run_all.sh` orchestrator.
*   **Operator Gate:** `preflight.sh` validates every prereq (host bins, ES, agent, Watcher, OpenWrt SSH) before the live run — single PASS/FAIL per check, exits non-zero on the first failure.
*   **Documented:** Full procedure in [`docs/SOP-022-anomaly-validation.md`](./SOP-022-anomaly-validation.md) with detection-mapping table, troubleshooting matrix, and evidence-capture checklist.

---

### Slide 7: Known Limitations & Challenges

![Slide 7 Limitations](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_6_limitations_1779894094801.png)

*   **Encrypted Traffic Blind Spot:** The pipeline monitors boundary traffic but cannot inspect deep HTTPS payloads without an active SSL/TLS proxy.
*   **Narrow SOAR Trigger Scope:** The Watcher currently fires only on `threat.indicator.domain` matches. Port scans (`Scan::Port_Scan`) and SSH brute-force cascades are *detected and logged* but do not yet trigger automated quarantine — they require analyst review.
*   **Unbenchmarked Stress Limits:** The OpenWrt gateway's continuous packet-streaming capability has not yet been stress-tested for stability under extreme network loads.

---

### Slide 8: Future Improvements & Extensions

![Slide 8 Improvements](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_7_improvements_1779894113536.png)

*   **Widen SOAR Triggers:** Extend the Watcher to fire on `Scan::Port_Scan` and `zeek.ssh` brute-force cascades, closing the auto-response gap for the most common opportunistic attacks.
*   **SSL/TLS Decryption Proxy:** Implement an inspection proxy to analyze the deep payloads of HTTPS traffic, eliminating the encrypted blind spot.
*   **Live Threat Intelligence Feed:** Continuously updated lists of malicious IPs and file hashes piped directly into Zeek, so unknown indicators light up the same Watcher pathway already in production.
*   **Quarantine Auto-Rollback:** Time-bound `SOAR_QUARANTINE_<MAC>` rules with a 24-hour TTL plus an analyst-approval step before permanent placement.
*   **Stress Benchmarking:** Drive sustained high-volume packet streams from the OpenWrt gateway and chart Zeek/Logstash throughput vs. drop rate.

---

### Slide 9: Conclusion

![Slide 9 Conclusion](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_8_conclusion_1779894129531.png)

The Suburban-SOC project replaces insecure home environments with a unified, mesh-based network architecture that provides enterprise-grade security for suburban neighborhoods. Boundary traffic captured at the OpenWrt gateway is streamed to a centralized host, where Zeek (with MAC-address enrichment) transforms raw packets into structured JSON, and Filebeat + Logstash ship that data into Elasticsearch indexed as `logstash-security-*`. Kibana surfaces dashboards for human analysts, while a Kibana Watcher + Flask AI Agent + `isolate.sh` chain closes the detect-and-respond loop by quarantining infected devices on the OpenWrt router at machine-speed via persistent `uci` MAC-DROP rules — with parallel ntfy and Discord notifications to the SOC. An anomaly-simulation harness exercises the three canonical attack scenarios end-to-end, giving the team a repeatable regression test for every future change.

---

### Slide 10: Citations

![Slide 10 Citations](C:/Users/tjlam/.gemini/antigravity-ide/brain/8fdd09d8-3374-46a8-9374-b1b5f9bed6ce/slide_9_citations_updated_1779896536098.png)

*   Google DeepMind. (2026). *Antigravity* (Gemini 3.1 Pro) [Large language model]. https://deepmind.google/technologies/gemini/
*   Anthropic. (2026). *Claude Code* (Claude Opus 4.7) [Large language model]. https://claude.com/claude-code

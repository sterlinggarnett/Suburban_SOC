# Suburban-SOC Presentation Slides

This document contains the finalized content for the Suburban-SOC project presentation, fulfilling the requirements for Milestone 6.

---

### Slide 1: Network Topology & Monitoring Scope
**Associated Milestone:** Milestone 1: Topology

*   **Mesh Network Architecture:** Built around 1 main gateway router acting as the mesh controller, with 6 remote wireless nodes distributing access.
*   **Traffic Scope:** We exclusively monitor and capture boundary HTTP traffic entering and exiting the main router.
*   **Security Justification:** This targeted approach avoids processing internal LAN noise (like local file sharing) and prevents resource drain from heavily encrypted tunnel traffic.
*   **Physical Flow:** ISP ➔ Main Gateway Router ➔ 6 Remote Wireless Nodes ➔ End-User Devices.

---

### Slide 2: Data Acquisition via OpenWrt
**Associated Milestone:** Milestone 2: Data Acquisition (The Mesh capture)

*   **Objective:** Configure the physical mesh nodes to stream raw traffic directly to our host.
*   **Implementation:** Leveraged OpenWrt to enable remote packet capture on the gateway.
*   **The Flow:** The Router mirrors the targeted network traffic and forwards it to the Host computer.
*   **Outcome:** Secure, continuous storage of raw `.pcap` files on the centralized host for further processing, preventing the router's local storage from being overwhelmed.

---

### Slide 3: The Processing Pipeline (Zeek & Filebeat)
**Associated Milestone:** Milestone 3: The Processing Pipeline (Zeek & Agent)

*   **Objective:** Automate the transformation of raw network packets into structured, human-readable security logs.
*   **Zeek Integration:** Processed raw PCAPs using a Zeek container natively configured (`LogAscii::use_json=T`) to output structured JSON logs.
*   **Log Shipping:** Configured a Filebeat agent (`filebeat.yml`) to actively monitor the Zeek output directory (`*.log`).
*   **The Flow:** Host Computer (Raw PCAP) ➔ Zeek (JSON Transformation) ➔ Filebeat (Harvests & Ships JSON files).

---

### Slide 4: Data Visualization & ELK Integration
**Associated Milestone:** Milestone 4: Data Visualization (ELK Integration)

*   **Objective:** Finalize data ingestion to create a human-readable, centralized security dashboard.
*   **Logstash Routing:** Filebeat streams logs directly into Logstash (Port `5044`), which parses the data and will enrich it with ECS normalization and GeoIP lookups.
*   **Elasticsearch Storage:** Enriched logs are indexed using a scalable daily categorization strategy (`suburban-soc-%{+YYYY.MM.dd}`) for rapid searching.
*   **Kibana Dashboard:** Visualizes network trends and anomalies, allowing SOC analysts to monitor real-time and historical security events through an intuitive GUI.

---

### Slide 5: Known Limitations & Challenges
*   **Encrypted Traffic Blind Spot:** The pipeline monitors boundary traffic but cannot inspect deep HTTPS payloads without an active SSL/TLS proxy.
*   **Passive Identification Only:** The system is engineered strictly to identify and log threats. It does not yet feature automated remediation, real-time push alerts, or active attacker IP blocking.
*   **Unbenchmarked Stress Limits:** The OpenWrt gateway’s continuous packet-streaming capability has not yet been stress-tested for stability under extreme network loads.

---

### Slide 6: Future Improvements & Extensions
*   **Active Response (IPS):** Upgrade to an Intrusion Prevention System by scripting the router to automatically block malicious IPs or quarantine MACs upon detection.
*   **Real-Time Push Alerts:** Instantly push critical security alerts to SOC analysts via Slack, Discord, or email webhooks.
*   **SSL/TLS Decryption Proxy:** Implement an inspection proxy to analyze the deep payloads of HTTPS traffic, eliminating the encrypted blind spot.
*   **Live Threat Intelligence:** Pipe lists of known malicious IPs and file hashes directly into Zeek to automatically flag active threats on the wire.

---

### Slide 7: Conclusion
The Suburban-SOC project replaces insecure home environments with a unified, mesh-based network architecture that provides enterprise-grade security for suburban neighborhoods. It operates by capturing targeted boundary traffic directly from an OpenWrt gateway router and securely streaming those raw packets to a centralized host. A fully automated processing pipeline then utilizes Zeek to transform the raw data into structured JSON logs, which are rapidly harvested and shipped by Filebeat. Finally, the ELK stack ingests and enriches this data, providing a centralized Kibana dashboard that empowers analysts to visualize network trends and detect malicious anomalies in real-time.

---

### Slide 8: Citations
*   Google DeepMind. (2026). *Antigravity* (Gemini 3.1 Pro) [Large language model]. https://deepmind.google/technologies/gemini/

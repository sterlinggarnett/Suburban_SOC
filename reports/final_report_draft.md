# Suburban-SOC Final Report

> **Note:** The canonical version of this report lives on the [GitHub Wiki](../../wiki/Final-Report). This file is a repo-tracked mirror for PR review and offline reference.

## Executive Summary
The Suburban-SOC project addresses the growing need for enhanced cybersecurity in residential environments. By establishing a mesh-based wireless network with centralized Security Operations Center (SOC) management, it replaces insecure home networks with a unified system. This pipeline captures and analyzes network traffic to identify potential threats, delivering enterprise-grade security and simple, plug-and-play connectivity for homeowners.

## Network Architecture & Scope
*   **Mesh Network Architecture:** Built around a single main gateway router acting as the mesh controller, distributing access through 6 remote wireless nodes.
*   **Targeted Monitoring:** We exclusively monitor and capture boundary HTTP traffic entering and exiting the main router.
*   **Security Justification:** This targeted approach ensures system efficiency by bypassing internal LAN noise (like local file sharing) and heavily encrypted tunnel traffic, avoiding unnecessary resource drain.
*   **Physical Flow:** ISP ➔ Main Gateway Router ➔ 6 Remote Wireless Nodes ➔ End-User Devices.

## Data Acquisition
*   **Implementation:** Using OpenWrt, we enabled remote packet capture directly on the gateway router.
*   **Flow & Storage:** The router mirrors the targeted network traffic and securely forwards it to a centralized host computer. This ensures continuous storage of raw `.pcap` files without overwhelming the router's limited local storage.

## Processing Pipeline (Zeek & Filebeat)
*   **Zeek Integration:** Raw PCAPs are processed using a Zeek container, configured natively (`LogAscii::use_json=T`) to transform packets into structured, human-readable JSON security logs.
*   **Log Shipping:** A Filebeat agent (`filebeat.yml`) continuously monitors the Zeek output directory, actively harvesting the generated `.log` files.
*   **Pipeline Flow:** Host Computer (Raw PCAP) ➔ Zeek (JSON Transformation) ➔ Filebeat (Harvests & Ships).

## Visualization & ELK Integration
*   **Logstash Routing:** Filebeat streams the JSON logs directly into Logstash (Port `5044`), which parses and enriches the data (e.g., ECS normalization, GeoIP lookups).
*   **Elasticsearch Storage:** The enriched logs are indexed using a scalable daily categorization strategy (`logstash-%{+YYYY.MM.dd}`), enabling rapid and efficient queries.
*   **Kibana Dashboard:** A user-friendly interface visualizes network trends and anomalies, allowing SOC analysts to monitor both real-time and historical security events.

## Challenges & Limitations
1.  **Encrypted Traffic Blind Spot:** The pipeline monitors boundary traffic but cannot inspect deep HTTPS payloads without an active SSL/TLS proxy.
2.  **Passive Identification Only:** The current system is engineered strictly to identify and log threats. It lacks automated remediation, real-time push alerts, or active attacker IP blocking.
3.  **Unbenchmarked Stress Limits:** The OpenWrt gateway's ability to continuously stream massive packet volumes has not yet been stress-tested for stability under extreme network loads.

## Future Enhancements
*   **Active Response (IPS):** Evolve the system into an Intrusion Prevention System by scripting the router to automatically block malicious IPs or quarantine MAC addresses upon detection.
*   **Real-Time Push Alerts:** Configure instant delivery of critical security alerts to SOC analysts via Slack, Discord, or email webhooks.
*   **SSL/TLS Decryption Proxy:** Implement an inspection proxy to analyze deep HTTPS payloads, eliminating the encrypted traffic blind spot.
*   **Live Threat Intelligence:** Integrate lists of known malicious IPs and file hashes directly into Zeek to automatically flag active threats on the wire.
*   **AI-Assisted Triage:** The `soc_ai_agent` service (see `scripts/setup/ai_agent/`) provides LLM-powered Level 1 alert analysis and automated isolation for critical events.


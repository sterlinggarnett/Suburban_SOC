# Suburban-SOC Network Pipeline

## Table of Contents
- [Team Members](#team-members)
- [Course Modules](#course-modules)
- [Project Status](#project-status)
- [Architecture](#architecture)
- [Overview](#overview)
- [Scope: Suburban-SOC Network Pipeline](#scope-suburban-soc-network-pipeline)
  - [Systems & Applications Targeted for Scanning](#systems--applications-targeted-for-scanning)
  - [Core Components & Functionalities of the Developed Tool](#core-components--functionalities-of-the-developed-tool)
  - [Security Domain & Vulnerabilities Covered](#security-domain--vulnerabilities-covered)
  - [Explicitly Out of Scope for this Project](#explicitly-out-of-scope-for-this-project)
- [Deliverables](#deliverables)
- [Repository Structure](#repository-structure)
- [Setup & Installation](#setup--installation)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Installation Steps](#2-installation-steps)
  - [3. Usage](#3-usage)
- [Contribution Guidelines](#contribution-guidelines)
- [Testing & Validation](#testing--validation)
  - [1. Automated Testing](#1-automated-testing)
  - [2. Manual Testing](#2-manual-testing)
- [License](#license)
- [Additional Notes](#additional-notes)
  - [Project-Specific Considerations](#project-specific-considerations)
  - [Future Enhancements](#future-enhancements)
  - [Known Issues & Limitations](#known-issues--limitations)

## Team Members

| Name | GitHub Username | Role |
|---|---|---|
| Tommy Lammers | [@voltron-1](https://github.com/voltron-1) | Security Analyst / Manager |
| Sterling Garnett | [@sterlinggarnett](https://github.com/sterlinggarnett) | System Architect / Engineer / Project Lead |
| Maria Frausto | [@megifrausto](https://github.com/megifrausto) | Design / Docs Lead / Manager |

## Course Modules

This project directly covers the following course modules from CIS 3353 — Computer Systems Security:

| Module | Topic | Connection to Pipeline |
|---|---|---|
| **Module 2** | Network Fundamentals & Traffic Analysis | The core pipeline captures and analyzes raw boundary network traffic from our OpenWrt mesh router, applying the principles of packet inspection, protocol dissection, and traffic scoping covered in this module. |
| **Module 8** | Intrusion Detection Systems (IDS) | Zeek functions as our IDS engine, parsing PCAP captures into structured JSON logs and generating `notice.log` alerts for port scans, brute-force attempts, and anomalous file transfers — directly applying the detection methodology from this module. |
| **Module 9** | Security Operations & Incident Response | The ELK stack (Elasticsearch, Logstash, Kibana) forms our SOC dashboard layer, enabling log correlation, GeoIP enrichment, and real-time visualization of security events. Milestone 8 validates the full incident response lifecycle with simulated attack scenarios. |

## Project Status

| Milestone | Title | Status |
|---|---|---|
| M1 | Topology | ✅ Complete |
| M2 | Data Acquisition (Mesh Capture) | ✅ Complete |
| M3 | The Processing Pipeline (Zeek & Filebeat) | ✅ Complete |
| M4 | Data Visualization (ELK Integration) | ✅ Complete |
| M5 | Threat Intelligence Integration | 🔄 In Progress |
| M6 | Proactive Kibana Alerting | 🔄 In Progress |
| M7 | Custom Home Network Dashboards | 🔄 In Progress |
| M8 | Live Anomaly Simulation & SOC Response Testing | 🔄 In Progress |

## Architecture

![Architecture Diagram](docs/architecture-diagram.png)

The Suburban-SOC pipeline is a modular, end-to-end security monitoring system composed of the following components:

| Component | Runtime | Port | Role |
|---|---|---|---|
| **OpenWrt Router** | Hardware / Physical | — | Captures all boundary network traffic for the home mesh network |
| **Zeek** | WSL / Docker Container | File-based | Ingests raw PCAP via SSH/tcpdump and converts it into structured JSON logs |
| **Logstash** | Docker Container | 5044 in / 9200 out | Enriches, filters, and routes JSON logs with GeoIP data to Elasticsearch |
| **Elasticsearch** | Docker Container | 9200 | Indexes and stores all structured log data for fast querying |
| **Kibana** | Docker Container | 5601 | Visualizes network events, security notices, and threat dashboards |

> For a full breakdown see the [Architecture Wiki page](../../wiki/Architecture).

## Overview
**Suburban-SOC:** Mesh-based wireless network for suburban neighborhoods with centralized SOC management. Replaces insecure home networks with a unified system that captures and analyzes traffic for threats, delivering enterprise-grade security and simple, plug-and-play connectivity for homeowners.

The "Suburban-SOC Network Pipeline" is a software project developed by Tommy Lammers, Sterling Garnett, and Maria Frausto for the Computer Systems Security course.

**Objective:**
The primary objective of this project is to enhance organizational cybersecurity defenses by building an end-to-end Zeek and ELK network packet analysis pipeline for an openWrt SOC. 

**Background:**
Network environments are frequently targeted by malicious actors. Regular and thorough network monitoring is crucial for identifying and addressing security gaps proactively. This pipeline provides a streamlined solution for capturing, parsing, and visualizing live network traffic efficiently.

**Key Functionalities:**
The tool is designed with a modular architecture and includes the following core functionalities:

1.  **Automated Network Traffic Analysis:**
    * A custom-built pipeline to monitor traffic using Zeek to parse raw PCAP data into structured JSON logs.
2.  **Comprehensive Reporting & Visualization:**
    * Generation of detailed dashboards using Kibana to outline discovered anomalies.
    * Data visualization features to provide an intuitive understanding of the security posture.
3.  **Data Processing & Routing:**
    * Using Filebeat and Logstash to securely ship, parse, and route logs to Elasticsearch.
4.  **Agile Development & Extensibility:**
    * Developed using an Agile methodology, emphasizing iterative development cycles.

## Scope: Suburban-SOC Network Pipeline
This project encompasses the design, development, and testing of an advanced **network packet analysis pipeline**. 

### Systems & Applications Targeted for Scanning:
* The tool is engineered to analyze and identify anomalies in **network traffic**. This includes dynamic routing, wireless access points, and devices on the OpenWrt router network.

### Baseline Traffic Monitoring Scope (Boundary Rules):
* To ensure system efficiency and targeted threat detection, the pipeline is configured to capture **only boundary HTTP traffic** entering and exiting the main router. This rule avoids processing internal network noise (e.g., local LAN file-sharing) and bypasses encrypted traffic that cannot be deeply inspected without a decryption proxy.

### Core Components & Functionalities of the Developed Tool:
* **Zeek Processing Engine:** Parses raw network packets into categorized JSON logs.
* **Logstash & Filebeat Forwarders:** Aggregates, filters, and forwards logs robustly.
* **Elasticsearch Database:** Stores and indexes log data efficiently.
* **Kibana UI:** A user-friendly interface to visualize metrics, initiate queries, and view security dashboards.

### Security Domain & Vulnerabilities Covered:
* The primary focus is on **network security monitoring and threat detection** across the defined network segments monitored by the OpenWrt router.

### Explicitly Out of Scope for this Project:
* Scanning and vulnerability assessment of web applications directly.
* Automated exploitation or remediation of identified network vulnerabilities; the pipeline is strictly for identification and reporting.

## Deliverables
1.  **Group Project Presentation:**
    * A presentation showcasing the project's objectives, architecture, and outcomes.
2.  **Group Project Report (GitHub Wiki):**
    * For full project documentation, progress notes, and the final report, please visit our [Project Wiki](../../wiki). (Wiki authored by Maria Frausto)
3.  **GitHub Project with Agile Artifacts:**
    * A GitHub Project board utilized for Agile project management.
4.  **GitHub Repository:**
    * The complete source code and configurations for the Suburban-SOC Network Pipeline.

## Repository Structure
```
/ (root)
├── README.md                   # Project overview, setup, and documentation links
├── LICENSE                     # MIT License
├── validate_soc.sh             # SOC pipeline validation script
├── /configs                    # Pipeline and agent configurations
│   ├── /firewall               # OpenWrt firewall rules (placeholder)
│   ├── /intel                  # Zeek threat intelligence feed (intel.dat, config.zeek)
│   ├── /network                # Filebeat configuration (filebeat.yml)
│   ├── /server                 # Kibana dashboard exports (.ndjson)
│   └── /zeek_intel             # Zeek intel framework configs
├── /docs                       # Technical documentation
│   ├── SOP-001-pipeline-operations.md
│   ├── Zeek_ELK_Pipeline.md
│   ├── architecture-diagram.png
│   ├── logstash_validation.md
│   ├── master_pipeline_guide.md
│   ├── network_topology.md
│   ├── presentation_slides.md
│   └── /sprint-notes
├── /evidence                   # Pipeline proof — hashes and Kibana screenshots
│   └── /screenshots
├── /reports                    # Final project report (mirrors GitHub Wiki)
├── /scripts                    # All automation and setup scripts
│   ├── /agile                  # GitHub project board & issue management scripts
│   └── /setup                  # Pipeline setup, capture, and AI agent scripts
│       ├── /ai_agent           # SOC AI agent (Flask webhook, LLM triage, ntfy)
│       ├── /configs/logstash   # Logstash pipeline config (Docker source of truth)
│       ├── docker-compose.yml  # ELK + AI agent stack definition
│       └── soc_pipeline.sh     # Interactive SOP automation menu
└── /wiki-temp                  # GitHub Wiki source files (submodule)
```

## Setup & Installation
### 1. Prerequisites:
Before you begin, ensure you have the following:
* **Git:** For cloning the repository.
* **Docker / Docker Compose:** For running the ELK stack and Zeek containers.
* **OpenWrt Router:** properly configured with packet capture capabilities.

### 2. Installation Steps:
1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/tjlam/Suburban-SOC.git
    cd Suburban-SOC
    ```
2.  **Configure Agents:**
    Review and modify `/configs/filebeat.yml` and `/configs/logstash.conf` to match your environment.
3.  **Deploy Containers:**
    Ensure Elasticsearch, Logstash, Kibana, and Zeek containers are online and correctly networked.

### 3. Usage:
1.  **Architecture Flow:**
    `Raw PCAP ➔ Zeek (JSON logs) ➔ Filebeat ➔ Logstash ➔ Elasticsearch ➔ Kibana`
2.  **Running the Pipeline:**
    Execute the relevant bash scripts in `/scripts/setup/` to begin streaming raw PCAP data over SSH.
3.  **Viewing Reports:**
    Navigate to Kibana (e.g., `http://localhost:5601`) to view the real-time visualizations and log queries.

## Contribution Guidelines
Please see our Wiki for detailed procedures on contributing to this project. We follow Agile methodologies including sprint tracking and GitHub Issue Management.

**Commit Approach:** This team uses **Delegated Commits**. All commits are routed through the designated Project Lead before being merged to the main branch. See our [Wiki: Commit-Approach](../../wiki/Commit-Approach) page for full details.

## Testing & Validation
### 1. Automated Testing:
* Unit tests and validation checks will be implemented for custom parser rules in Zeek and Logstash logic.
### 2. Manual Testing:
* Generating sample PCAP files containing known traffic signatures and verifying their appearance in the Kibana dashboard accurately.

## License
This project is licensed under the MIT License. (Make sure you include a `LICENSE` file to accompany this).

## Additional Notes
### Project-Specific Considerations:
* This tool was developed as a group project for the Computer Systems Security course.

### Future Enhancements:
* Integrate threat intelligence feeds directly into Zeek.
* Set up real-time alerting using ElastAlert or native Kibana alerts for anomalous activity.

### Known Issues & Limitations:
* Performance for streaming very large packet volumes from the router hasn't been heavily benchmarked and may require interface optimization.

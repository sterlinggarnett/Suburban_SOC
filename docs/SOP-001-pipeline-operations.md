# SOP-001: Suburban-SOC Pipeline Operations
**Document Type:** Standard Operating Procedure  
**Version:** 1.0  
**Owner:** Tommy Lammers (@voltron-1) — Security Analyst / Manager  
**Last Updated:** 2026-04-29  
**Classification:** Internal — CIS 3353 Spring 2026

---

## Purpose

This SOP defines the step-by-step procedures for operating the Suburban-SOC network monitoring pipeline. It covers traffic capture from the OpenWrt mesh router, log parsing via Zeek, log shipping via Filebeat/Logstash, and visualization in Kibana.

---

## Prerequisites

Before executing any procedure, verify the following:

| Requirement | How to Verify |
|---|---|
| Docker is running | `docker ps` — should return a list (even if empty) |
| SSH access to router | `ssh root@10.18.81.1` — should drop into OpenWrt shell |
| `/storage/PCAP/zeek_logs/` exists | `ls /storage/PCAP/zeek_logs/` |
| Filebeat service running | `sudo systemctl status filebeat` |
| Logstash & Elasticsearch up | `curl http://localhost:9200` — should return cluster info |
| Kibana reachable | Open `http://localhost:5601` in browser |

---

## SOP-001-A: Live Capture — Mesh Interface (bat0)

**Script:** `scripts/setup/stream_bat0_data.sh`  
**Owner:** SA  
**Interface:** `bat0` (B.A.T.M.A.N. advanced mesh)  
**Use When:** Monitoring wireless mesh node-to-node traffic

### Steps

```bash
# 1. Navigate to the setup directory
cd /path/to/Suburban-SOC/scripts/setup

# 2. Make executable (first time only)
chmod +x stream_bat0_data.sh

# 3. Run the stream
./stream_bat0_data.sh
```

**What it does:**  
SSHs into the OpenWrt router (`root@10.18.81.1`), runs `tcpdump` on the `bat0` interface, pipes the raw packet stream directly into the Zeek Docker container, and outputs structured JSON logs to `/storage/PCAP/zeek_logs/`.

**Expected Output:**  
Zeek JSON log files appear in `/storage/PCAP/zeek_logs/` (`conn.log`, `http.log`, `dns.log`, etc.)

**Stop:** `Ctrl+C` — terminates the SSH tunnel and the Zeek container cleanly.

---

## SOP-001-B: Live Capture — Standard LAN Interface (br-lan)

**Script:** `scripts/setup/stream_br_lan_data.sh`  
**Owner:** SA  
**Interface:** `br-lan` (standard bridged LAN)  
**Use When:** Monitoring all traffic across the router's wired/wireless LAN bridge

### Steps

```bash
chmod +x stream_br_lan_data.sh
./stream_br_lan_data.sh
```

**What it does:**  
Identical to SOP-001-A but captures on `br-lan`. The `-C` flag disables IP checksum validation — required for mirrored/tunneled traffic that may have pre-computed checksums.

> ⚠️ **Note:** Use `br-lan` for general home network monitoring. Use `bat0` specifically for mesh routing traffic between nodes.

---

## SOP-001-C: Live Capture — Local Host Interface (eth0)

**Script:** `scripts/setup/stream_raw_data.sh`  
**Owner:** SA  
**Interface:** `eth0` (local WSL/host interface)  
**Use When:** Testing locally without the router (dev/debug use)

### Steps

```bash
chmod +x stream_raw_data.sh
sudo ./stream_raw_data.sh
```

**What it does:**  
Runs `tcpdump` locally on `eth0` and pipes the stream directly into the Zeek Docker container. Requires `sudo` for raw socket access.

---

## SOP-001-D: Offline PCAP Analysis

**Script:** `scripts/setup/zeek_run_pcap.sh`  
**Owner:** SA  
**Use When:** Analyzing a pre-captured `.pcap` file (offline/forensic mode)

### Steps

```bash
# 1. Place your PCAP file at:
#    /storage/PCAP/http.pcap

# 2. Run Zeek against the static file
chmod +x zeek_run_pcap.sh
./zeek_run_pcap.sh
```

**What it does:**  
Mounts `/storage/PCAP/` into the Zeek Docker container and runs Zeek against `http.pcap` in offline mode. JSON logs are written to `/storage/PCAP/zeek_logs/`.

> 💡 **Tip:** Rename your PCAP to `http.pcap` before running, or edit the script to change the filename.

---

## SOP-001-E: Live Host Network Monitor (Interactive Zeek)

**Script:** `scripts/setup/zeek_connect_host.sh`  
**Owner:** SA  
**Use When:** Running Zeek interactively bound to the host network stack

### Steps

```bash
chmod +x zeek_connect_host.sh
sudo ./zeek_connect_host.sh
```

**What it does:**  
Starts a Zeek Docker container in `--network host` mode with `NET_ADMIN` and `NET_RAW` capabilities, listening on `eth0`. Logs written to `/storage/PCAP/zeek_logs/`.

---

## SOP-002: Filebeat — Install & Configure

**Script:** `scripts/setup/install_filebeat.sh`  
**Owner:** SA  
**Run Once:** Yes — only needed on initial setup

### Steps

```bash
chmod +x install_filebeat.sh
sudo ./install_filebeat.sh
```

**What it does:**  
Adds the Elastic APT repository and installs Filebeat 8.x on Debian/Ubuntu (WSL).

### After Installation — Configure Filebeat

Edit `/etc/filebeat/filebeat.yml` and add the following input/output config:

```yaml
# Input: Watch Zeek log directory
filebeat.inputs:
  - type: filestream
    id: zeek-logs
    paths:
      - /storage/PCAP/zeek_logs/*.log
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true

# Output: Send to Logstash
output.logstash:
  hosts: ["localhost:5044"]
```

Start and enable Filebeat:

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

---

## SOP-003: Logstash Pipeline

**Config:** `configs/logstash.conf`  
**Owner:** SA / PL  
**Port:** Listens on `5044`, outputs to Elasticsearch on `9200`

### Pipeline Stages

| Stage | Action |
|---|---|
| **Input** | Receives Beats data from Filebeat on port 5044 |
| **Filter: JSON Parse** | Parses raw JSON strings if not already parsed |
| **Filter: ECS Rename** | Maps Zeek fields (`id.orig_h`) → ECS format (`source.ip`) |
| **Filter: GeoIP** | Enriches source and destination IPs with geographic metadata |
| **Output** | Sends enriched data to Elasticsearch index `logstash-YYYY.MM.dd` |

### Environment Variable

The Elasticsearch password is read from the environment:
```bash
export ELASTIC_PASSWORD=your_password_here
```
> ⚠️ **Never hardcode passwords.** Use the `.env` file or export the variable in your shell session.

---

## SOP-004: Clear Logs (Reset Environment)

**Script:** `scripts/setup/clear_logs.sh`  
**Owner:** SA  
**⚠️ DESTRUCTIVE** — permanently deletes all Zeek log files

### Steps

```bash
chmod +x clear_logs.sh
sudo ./clear_logs.sh
```

**Use When:**  
- Starting a fresh capture session  
- Disk space is running low  
- Resetting after a test run

> ⚠️ **Warning:** This deletes ALL files in `/storage/PCAP/zeek_logs/`. Ensure Filebeat has already shipped the logs to Elasticsearch before running.

---

## SOP-005: End-to-End Pipeline Startup Sequence

Follow this order when starting the full pipeline from scratch:

| Step | Action | Command / Location |
|---|---|---|
| 1 | Start Docker | Launch Docker Desktop or `sudo service docker start` |
| 2 | Start ELK stack | `docker compose up -d` (if using compose) |
| 3 | Verify Elasticsearch | `curl http://localhost:9200` |
| 4 | Verify Kibana | Open `http://localhost:5601` |
| 5 | Start Filebeat | `sudo systemctl start filebeat` |
| 6 | Begin traffic capture | Run appropriate SOP-001 script |
| 7 | Confirm logs flowing | Check `/storage/PCAP/zeek_logs/` for new `.log` files |
| 8 | Confirm data in Kibana | Open Discover → search index `logstash-*` |

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| SSH connection refused | Router unreachable | Verify you are on the mesh network and router IP is `10.18.81.1` |
| Zeek container exits immediately | Docker not running | Run `docker ps` and start Docker |
| No logs in Zeek output dir | Permissions issue | Run with `sudo` or check `/storage/PCAP/zeek_logs/` permissions |
| Filebeat not shipping | Config error or Logstash down | Check `sudo journalctl -u filebeat -f` and verify Logstash port 5044 |
| No data in Kibana | Wrong index pattern | Ensure index pattern is `logstash-*` in Kibana Data Views |
| Elasticsearch 401 error | Wrong password | Re-export `ELASTIC_PASSWORD` environment variable |

---

## Related Documents

- [Architecture Diagram](../docs/architecture-diagram.png)
- [Logstash Config](../configs/logstash.conf)
- [Zeek ELK Pipeline Docs](../docs/Zeek_ELK_Pipeline.md)
- [Network Topology](../docs/network_topology.md)
- [Wiki: Architecture](https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF/wiki/Architecture)

# Suburban-SOC Master Pipeline Guide

> **Version 2.0** | Ubuntu 24.04 LTS (noble) | ELK 9.3.2 | Zeek 6.x | May 2026  
> **Repo:** [voltron-1/Suburban-SOC](https://github.com/voltron-1/Suburban-SOC)  
> **Upstream:** [sterlinggarnett/cis3353_s26_TL_SG_MF](https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF)

This document contains every bash command needed to deploy and test the Suburban SOC pipeline — from a fresh machine through to verified live data in Kibana.

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS (noble) |
| ELK Stack | 9.3.2 (elasticsearch / kibana / logstash / filebeat) |
| Zeek Install Path | `/opt/zeek/bin/zeek` |
| Docker Network | `setup_soc-mesh-net` (Docker prepends folder name) |
| Config Source of Truth | `scripts/setup/configs/logstash/logstash.conf` |

---

## Phase 0 — Prerequisites

> One-time setup on a fresh machine. Skip any section already completed.

### P-A: Confirm System Requirements

```bash
# Check Ubuntu version — must be 24.04 LTS (noble)
lsb_release -a

# Check available RAM — Elasticsearch alone needs 2 GB free
free -h

# Check available disk — ELK stack images need ~5 GB
df -h /

# Check internet connectivity
curl -s https://google.com > /dev/null && echo 'Internet OK' || echo 'No internet'
```

**Expected:** Ubuntu 24.04.4 LTS (noble). Minimum 8 GB RAM, 20 GB free disk. Internet reachable.

---

### P-B: Install Docker Engine and Docker Compose V2

```bash
# Remove any old conflicting Docker packages first
sudo apt remove docker docker-engine docker.io containerd runc -y 2>/dev/null

# Install packages needed to add Docker's apt repository
sudo apt update
sudo apt install ca-certificates curl gnupg lsb-release -y

# Create the directory for apt keyrings
sudo install -m 0755 -d /etc/apt/keyrings

# Download and store Docker's official GPG signing key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker's apt repository for Ubuntu 24.04 (noble)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine, CLI, containerd, and the Compose plugin
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add your user to the docker group so you don't need sudo for every docker command
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

> [!WARNING]
> If `docker compose version` shows 'command not found', the Compose V2 plugin is missing. Run: `sudo apt install docker-compose-plugin -y`

---

### P-C: Install Zeek on Ubuntu 24.04 LTS

```bash
# Add Zeek's official apt repository for Ubuntu 24.04 noble
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

# Download and install the repo's GPG key
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
  | gpg --dearmor \
  | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

# Refresh apt and install Zeek
sudo apt update
sudo apt install zeek -y

# Add Zeek's bin directory to your PATH
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
zeek --version
which zeek
```

> [!WARNING]
> If `zeek --version` still says 'command not found' after sourcing, use the full path `/opt/zeek/bin/zeek` in all capture commands.

---

### P-D: Clone the Suburban-SOC Repository

```bash
# WSL: access Windows filesystem
cd /mnt/c/Users/<your-windows-username>/Documents/GitHub

# Clone YOUR fork
git clone https://github.com/voltron-1/Suburban-SOC.git
cd Suburban-SOC

# Add the upstream course repo as a remote
git remote add upstream https://github.com/sterlinggarnett/cis3353_s26_TL_SG_MF.git

# Confirm both remotes
git remote -v
```

> **Note:** To pull upstream updates later: `git fetch upstream && git merge upstream/main`

---

### P-E: Verify Project Structure and Config Files

```bash
# Confirm you are in the project root
pwd

# Check all critical files exist
ls scripts/setup/docker-compose.yml
ls scripts/setup/ai_agent/Dockerfile
ls scripts/setup/ai_agent/agent_app.py
ls scripts/setup/ai_agent/requirements.txt

# Check the logstash config — MOST important file
ls scripts/setup/configs/logstash/logstash.conf

# Verify logstash.conf is NOT empty
cat scripts/setup/configs/logstash/logstash.conf

# If logstash.conf is missing, create it from the root copy
mkdir -p scripts/setup/configs/logstash
cp configs/logstash.conf scripts/setup/configs/logstash/logstash.conf
wc -l scripts/setup/configs/logstash/logstash.conf
```

> [!CAUTION]
> If `logstash.conf` is empty, Logstash will start but have no pipeline — it silently discards all data. Always verify this file has content before proceeding.

---

## Phase 1 — Stack Startup

> Bring all four containers online and verify each service is healthy before proceeding.

### Step 1: Navigate to the Setup Directory

```bash
cd /mnt/c/Users/<your-username>/OneDrive/Documents/GitHub/Suburban-SOC/scripts/setup
```

> All `docker compose` commands must be run from this directory. All relative paths in `docker-compose.yml` resolve from here.

### Step 2: Start the Full Docker Stack

```bash
docker compose up -d
```

**Expected:** 4 containers with status `Running`. A warning about 'version' being obsolete is harmless.

### Step 3: Verify All Containers Are Running

```bash
docker ps
```

**Expected:** Four rows: `elasticsearch` (9200), `kibana` (5601), `logstash` (5044), `soc_ai_agent` (5000) — all `Up`.

> [!WARNING]
> If any container is missing, check its logs: `docker logs <container_name> --tail 30`

### Step 4: Verify Elasticsearch

```bash
curl -s http://localhost:9200/_cat/indices?v
```

**Expected:** A table of internal Elasticsearch system indices, all with health `green`. Wait 30 seconds and retry if you see 'connection refused'.

### Step 5: Verify Logstash Pipeline Started

```bash
docker logs logstash --tail 20
```

**Expected:** The line `Pipeline started successfully` appears.

> [!WARNING]
> If you see errors about an empty config, ensure the file exists at `scripts/setup/configs/logstash/logstash.conf` and restart: `docker restart logstash`

### Step 6: Send Initial Test Event

```bash
# Create the Filebeat config
cat > /tmp/filebeat-test.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    enabled: true
    paths:
      - /logs/*.log
    parsers:
      - ndjson:
          keys_under_root: true
          add_error_key: true
output.logstash:
  hosts: ["logstash:5044"]
logging.level: info
EOF

# Run Filebeat with a test message
docker run --rm -i \
  --network setup_soc-mesh-net \
  -v /tmp/filebeat-test.yml:/usr/share/filebeat/filebeat.yml \
  docker.elastic.co/beats/filebeat:9.3.2 \
  filebeat -e --strict.perms=false \
  <<< '{"message": "Suburban-SOC Pipeline Test", "source.ip": "192.168.1.100"}'
```

> **Note:** The network name is `setup_soc-mesh-net` — Docker prefixes the folder name `setup` to the network defined in `docker-compose.yml` as `soc-mesh-net`.

### Step 7: Confirm Test Event Reached Elasticsearch

```bash
curl -s http://localhost:9200/_cat/indices?v | grep logstash
```

**Expected:** One row: `logstash-YYYY.MM.DD` with health `yellow`, `docs.count: 1`, size ~14kb.

> [!WARNING]
> If nothing appears: `docker logs logstash --tail 30`. A common cause is `user`/`password` fields in `logstash.conf` when `xpack.security.enabled=false` — remove auth fields from the output block.

---

## Phase 2 — Live Traffic Capture

### Step 8: Identify Your Active Network Interface

```bash
ip route | grep default
```

**Expected:** Something like: `default via 172.21.112.1 dev eth0`. The word after `dev` is your interface name.

### Step 9: Verify Zeek Is Accessible

```bash
zeek --version
# If not found:
which zeek || find /opt /usr/local -name 'zeek' 2>/dev/null
echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc && source ~/.bashrc
```

### Step 10: Start Live Network Capture

```bash
# Replace eth0 with your interface from Step 8
sudo /opt/zeek/bin/zeek -i eth0 LogAscii::use_json=T
```

> Let it capture for at least 30–60 seconds. Generate traffic in a separate terminal: `curl http://example.com` or `ping 8.8.8.8 -c 5`.

> [!WARNING]
> Zeek requires `sudo` to open a raw network socket. Logs are written to the current working directory.

### Step 11: Stop and Verify Log Files

```bash
# Stop with Ctrl+C, then verify
ls -la *.log
head -3 conn.log
```

**Expected:** Multiple `.log` files. Each contains one JSON object per line (NDJSON format).

### Optional: Capture via OpenWrt Router

```bash
# Confirm router SSH access
ssh root@10.18.81.1

# Stream router traffic through Zeek on your local machine
ssh root@10.18.81.1 "tcpdump -i br-lan -w - -U" | sudo /opt/zeek/bin/zeek -r -
```

---

## Phase 3 — Shipping Logs Through the Pipeline

### Step 12: Create the Filebeat Configuration

```bash
cat > /tmp/filebeat-test.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    enabled: true
    paths:
      - /logs/*.log
    parsers:
      - ndjson:
          keys_under_root: true
          add_error_key: true
output.logstash:
  hosts: ["logstash:5044"]
logging.level: info
EOF
```

> [!IMPORTANT]
> `filestream` is required for Filebeat 9.x — the older `type: log` is deprecated and causes a **fatal error**. The `ndjson` parser reads Zeek's one-JSON-per-line format and promotes all fields to the document root.

### Step 13: Run Filebeat to Ship Logs

```bash
docker run --rm -i \
  --network setup_soc-mesh-net \
  -v /tmp/filebeat-test.yml:/usr/share/filebeat/filebeat.yml \
  -v $(pwd):/logs \
  docker.elastic.co/beats/filebeat:9.3.2 \
  filebeat -e --strict.perms=false
```

Watch for: `filebeat start running` → `Loading Inputs: 1` → `write: bytes:XXXX` → `filebeat stopped`.

> [!WARNING]
> Do **NOT** run this as a background job (`&`) — the process gets suspended by the shell. Run in the foreground and use Ctrl+C when done.

### Step 14: Confirm Logstash Received Events

```bash
docker logs logstash --tail 30
```

Look for: `source.ip`, `destination.ip`, `destination.geo`, `@timestamp` fields in the output.

---

## Phase 4 — Verification

### Step 15: Check Document Count in Elasticsearch

```bash
curl -s http://localhost:9200/logstash-*/_count?pretty
```

**Expected:** `"count": <N>` where N > 1. A typical 60-second capture produces 10–100+ documents.

### Step 16: Check Index Health and Size

```bash
curl -s http://localhost:9200/_cat/indices?v | grep logstash
```

**Expected:** `health=yellow, status=open`. Yellow is normal for single-node — replica shards are unassigned.

### Step 17: Inspect a Sample Document

```bash
curl -s "http://localhost:9200/logstash-*/_search?pretty&size=2" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}'
```

Look for: `@timestamp`, `source.ip`, `destination.ip`, `destination.geo`, `proto`, `service`.

### Step 18: Get Your WSL IP for Kibana

```bash
ip addr show eth0 | grep 'inet '
# Then open in your Windows browser: http://<WSL-IP>:5601
```

> On native Linux, use `http://localhost:5601` directly.

### Step 19: Create Kibana Data View

1. Hamburger menu → **Management** → **Stack Management**
2. Left sidebar under Kibana → **Data Views** → **Create data view**
3. Name: `Suburban SOC` | Index pattern: `logstash-*` | Timestamp: `@timestamp`
4. Click **Save data view to default space**

### Step 20: Confirm Data in Kibana Discover

1. Hamburger menu → **Discover**
2. Select `Suburban SOC` data view
3. Set time range to `Last 1 hour`
4. Try KQL: `source.ip: *`

**Expected:** A stream of network events with Zeek fields in the left panel.

> [!WARNING]
> If 'No results found', expand to `Last 24 hours`. Zeek logs carry the timestamp from when the PCAP was recorded, not when it was indexed.

---

## Troubleshooting Quick Reference

| Error / Symptom | Root Cause | Fix |
|---|---|---|
| `InvalidFrameProtocolException` beats protocol: 34 | Raw JSON sent to port 5044 via `nc` or `curl` | Port 5044 is Beats protocol only. Use Filebeat container. |
| `logstash.conf` is empty after stack restart | Config file not mounted — path mismatch | Ensure file exists at `scripts/setup/configs/logstash/logstash.conf` |
| `network soc-mesh-net not found` | Stack not running — network only exists when containers are up | Run `docker compose up -d` before using `--network` |
| `Log input is deprecated` error in Filebeat | Using `type: log` removed in Filebeat 9.x | Change to `type: filestream` |
| `count: 1` after Filebeat run | Filebeat container was backgrounded and suspended | Run Filebeat in foreground — do not append `&` |
| Authentication error in Logstash output | `user`/`password` in `logstash.conf` when security is disabled | Remove `user` and `password` from elasticsearch output block |
| Kibana `localhost:5601` not loading on Windows | WSL2 networking | Get WSL IP: `ip addr show eth0 \| grep inet` |
| No results in Kibana Discover | Time range too narrow for log timestamps | Expand to `Last 24 hours` |
| `zeek: command not found` | Zeek not added to PATH | `echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc && source ~/.bashrc` |

---

## Key Rules

- Always run `docker compose` from `scripts/setup/` — not from the repo root
- `scripts/setup/configs/logstash/logstash.conf` is the **only source of truth** for the pipeline config — never edit inside a running container
- Port 5044 uses Beats protocol — always use Filebeat, never `nc` or `curl`
- Docker network name is `setup_soc-mesh-net` (Docker prepends the folder name `setup`)
- Elasticsearch data persists in the `suburban_soc_data` Docker volume across restarts
- To fully reset including data: `docker compose down -v`
- Yellow index health is normal on single-node Elasticsearch — not an error
- Filebeat 9.x requires `type: filestream` — `type: log` causes a fatal startup error

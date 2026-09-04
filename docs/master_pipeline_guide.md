# Suburban-SOC Master Pipeline Guide

> **Version 2.0** | Ubuntu 24.04 LTS (noble) | ELK 9.3.2 | Zeek 6.x | May 2026  
> **Repo:** [voltron-1/Suburban-SOC](https://github.com/voltron-1/Suburban-SOC)  
> **Upstream:** [sterlinggarnett/Suburban_SOC](https://github.com/sterlinggarnett/Suburban_SOC)

This document contains every bash command needed to deploy and test the Suburban SOC pipeline — from a fresh machine through to verified live data in Kibana.

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS (noble) |
| ELK Stack | 9.3.2 (elasticsearch / kibana / logstash / filebeat) |
| Zeek Install Path | `/opt/zeek/bin/zeek` |
| Docker Network | `setup_soc-mesh-net` (Docker prepends folder name) |
| Config Source of Truth | `configs/logstash.conf` (bind-mounted directly into the container) |

---

> [!IMPORTANT]
> **Security is enabled (WS0.1).** Elasticsearch now runs with `xpack.security.enabled=true`
> and TLS, so it is reachable at **`https://localhost:9200`** and **requires authentication**.
> Before `docker compose up -d`, copy `scripts/setup/.env.example` → `scripts/setup/.env`
> and set strong `ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, `LOGSTASH_PASSWORD`, and a
> 32+ char `KIBANA_ENCRYPTION_KEY`. Kibana (`https://localhost:5601` — #177: TLS-only)
> now requires login as `elastic`.
>
> Any `curl http://localhost:9200/...` example below must be run as:
> ```bash
> curl -k -u "elastic:$ELASTIC_PASSWORD" https://localhost:9200/...
> ```
> (`-k` trusts the local self-signed CA; use `--cacert` with the exported `ca.crt` for strict verification.)

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
git remote add upstream https://github.com/sterlinggarnett/Suburban_SOC.git

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

# Check the logstash config — MOST important file.
# It is the single source of truth and is bind-mounted directly into the
# container by docker-compose.yml (../../configs/logstash.conf). No copy needed.
ls configs/logstash.conf

# Verify logstash.conf is NOT empty
wc -l configs/logstash.conf
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
> If you see errors about an empty config, ensure `configs/logstash.conf` exists and is non-empty (it is bind-mounted directly into the container), then restart: `docker restart logstash`

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
> If nothing appears: `docker logs logstash --tail 30`. With security enabled (WS0.1), the
> usual cause is bad ES credentials — confirm `LOGSTASH_PASSWORD` in `.env` matches the
> `logstash_internal` user the `setup` container created, and that Logstash can read the
> mounted CA at `/usr/share/logstash/config/certs/ca/ca.crt`.

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
# Then open in your Windows browser: https://<WSL-IP>:5601
```

> On native Linux, use `https://localhost:5601` directly. (#177: Kibana is TLS-only —
> your browser will warn about the self-signed stack CA; that's expected.)

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
| `logstash.conf` is empty after stack restart | Config file not mounted — path mismatch | Ensure `configs/logstash.conf` exists and is non-empty (bind-mounted via `../../configs/logstash.conf`) |
| `network soc-mesh-net not found` | Stack not running — network only exists when containers are up | Run `docker compose up -d` before using `--network` |
| `Log input is deprecated` error in Filebeat | Using `type: log` removed in Filebeat 9.x | Change to `type: filestream` |
| `count: 1` after Filebeat run | Filebeat container was backgrounded and suspended | Run Filebeat in foreground — do not append `&` |
| Authentication error in Logstash output | Wrong/missing ES credentials (security is ON) | Ensure `LOGSTASH_PASSWORD` in `.env` matches the `logstash_internal` user and the CA is mounted |
| Kibana `localhost:5601` not loading on Windows | WSL2 networking | Get WSL IP: `ip addr show eth0 \| grep inet` |
| No results in Kibana Discover | Time range too narrow for log timestamps | Expand to `Last 24 hours` (same root cause as SOP-001's "correct capture interface" entry when the interface itself is also wrong — check both) |
| `zeek: command not found` | Zeek not added to PATH | `echo 'export PATH=$PATH:/opt/zeek/bin' >> ~/.bashrc && source ~/.bashrc` |
| Elasticsearch cluster status `red`, writes rejected / index blocked read-only | Disk watermark breached (`flood_stage`) or `cluster.max_shards_per_node` exceeded on a single-node deployment | Check `GET _cat/allocation` and `GET _cluster/health` (SOP-005's cluster-health check). Free disk or raise the watermark; if blocked read-only, clear the block after freeing space (`PUT */_settings {"index.blocks.read_only_allow_delete": null}`). `configs/elasticsearch/apply-templates.sh`'s rollover step already warns to check allocation before a manual rollover for the same reason. |
| Logstash pipeline crashes / restarts in a loop on certain events | A filter (e.g. `geoip`) throws on a field that's organically absent from some events — e.g. a Zeek log with no destination IP — rather than skipping it | Guard the filter with an `if [field]` existence check instead of calling it unconditionally. Real incident + fix documented in `docs/logstash_validation.md` (GeoIP lookup wrapped in `if [destination][ip]` after this exact crash was reproduced against `logstash.conf`). |
| Zeek sensor (`zeek-host-capture.service`) silently dies — no logs written, no error surfaced anywhere else in the stack | A capability/permission gap between the systemd unit's `CapabilityBoundingSet=` and what an `ExecStartPre` step (or tcpdump's own privilege drop) actually needs — service exits or crash-loops without a visible pipeline-level symptom | Detect via the per-source liveness metric (`metric_zeek_ingest_lag_seconds()`, `scripts/setup/ai_agent/slo_metrics.py`) — breaches `SLO_ZEEK_INGEST_LAG_MAX_S` (default 300s) when no `event.module:"zeek"` documents have landed recently, which is exactly the "everything else is still writing, only this source went quiet" case a whole-pipeline health check misses. Diagnose with `sudo systemctl status zeek-host-capture.service` / `journalctl -u zeek-host-capture.service`; a real prior incident was a missing `CAP_CHOWN` (and later `CAP_SETUID`/`CAP_SETGID` for tcpdump's own privilege drop) in the unit's `CapabilityBoundingSet=` after an `ExecStartPre` `chown` step was added without the matching capability — see `planned_execution.md`'s "zeek-host-capture.service crash-loop" entry for the full root-cause history. |
| A detection PR fails CI on `.github/workflows/detections.yml` | Several independent gates live there — most commonly: a new/changed Sigma rule has no matching pcap/log fixture for the TP-fires/TN-regression promotion gate (`tests/detections/test_sigma_detections.py`), a threshold rule shipped without its paired companion (`tests/detections/test_threshold_rules.py`, issue #192), a Zeek rule is missing the `event.dataset` scoping condition (issue #291), or the rule simply fails to convert via `sigma convert` against `configs/detections/suburban-soc-ecs.yml` | Read the specific failing step name in the Actions log — each one names its own issue/purpose in the workflow file. A rule with no fixture stays `experimental` and cannot be enabled; that's the gate working as intended, not a bug to work around. |
| `remote error: tls: certificate required` from an endpoint Winlogbeat/Filebeat instance | Client cert missing or expired — the Logstash Beats input requires client auth (`ssl_certificate_authorities` is set), but `configs/endpoint/winlogbeat.yml`/`filebeat_endpoint.yml` don't yet mint/ship one (issue #265, tracked, not yet implemented). Distinct from the "Authentication error in Logstash output" row above, which is an ES credential problem, not a TLS handshake one. | Not yet fixable via config alone — #265 needs a dedicated session to design and live-verify the cert-minting/distribution path before a real Windows/Linux endpoint can onboard. Until then, only the network sensor's own Filebeat (`configs/network/filebeat.yml`, which already carries `${FILEBEAT_CERT}`/`${FILEBEAT_KEY}`) can complete this handshake. |
| A Zeek `dns.log` TXT answer (or any long Zeek string field) stops at exactly 8191 bytes — exactly 4096 on a stock image — with no marker in the record itself | Zeek 8.1+'s logging framework caps every string field at `Log::default_max_field_string_bytes` (4096 upstream; `configs/intel/config.zeek` pins it to 8191, the `dns.answers` index ceiling, #389) and records the cut only in `weird.log` (`log_string_field_truncated`, `addl` = the stream name) | Confirm the deployed `/storage/PCAP/intel/config.zeek` carries the exact `redef … = 8191;` line (every capture path's post-copy guard refuses to start without it); pivot on `slo_metrics.py`'s `dns_answer_truncated_by_zeek_count` (target 0) and `zeek_log_field_truncation_count` to find the affected records |

---

## Key Rules

- Always run `docker compose` from `scripts/setup/` — not from the repo root
- `configs/logstash.conf` is the **only source of truth** for the pipeline config (bind-mounted directly into the container) — never edit inside a running container, and never reintroduce a second copy under `scripts/setup/`
- Port 5044 uses Beats protocol — always use Filebeat, never `nc` or `curl`
- Docker network name is `setup_soc-mesh-net` (Docker prepends the folder name `setup`)
- Elasticsearch data persists in the `suburban_soc_data` Docker volume across restarts
- To fully reset including data: `docker compose down -v`
- Yellow index health is normal on single-node Elasticsearch — not an error
- Filebeat 9.x requires `type: filestream` — `type: log` causes a fatal startup error

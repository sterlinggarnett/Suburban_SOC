# Anomaly Simulation Harness

Validation suite for Issue #22 — exercises the Suburban-SOC detection pipeline
end-to-end and confirms the SOAR response (MAC quarantine on OpenWrt) executes
correctly against three canonical attack scenarios.

## Safety

**Lab use only.** These scripts generate traffic patterns that resemble real
attacks (port scans, SSH brute force, suspicious downloads). Run them only on
systems and networks where you have explicit authorization. The defaults target
`127.0.0.1` and a configurable lab attacker host — do not point them at
production or third-party infrastructure.

## Scenarios

| Sim | Script | Expected detection |
|---|---|---|
| Network recon | `sim_portscan.sh` | Zeek `notice.log` → `Scan::Port_Scan` |
| SSH brute force | `sim_brute_ssh.sh` | Zeek `ssh.log` → 5+ rows with `auth_success=F` |
| Suspicious download | `sim_malware_download.sh` | Zeek `files.log` → `mime_type=application/zip` |

## Setup

```bash
# 1. Copy and edit config
cp .env.example .env
$EDITOR .env

# 2. Install Python deps for the verifier
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Install host prereqs:
#    - nmap        (sudo apt install nmap)
#    - sshpass     (sudo apt install sshpass)
#    - curl        (always present)
```

## Usage

```bash
# Gate every prereq before the live run (host bins, ES, agent, watcher, router):
./preflight.sh

# Run a single scenario:
./sim_portscan.sh
./sim_brute_ssh.sh
./sim_malware_download.sh

# Verify detections landed in Elasticsearch (default: localhost:9200):
source .env && python3 verify_detections.py

# Confirm SOAR quarantine rule installed on OpenWrt:
./verify_quarantine.sh AA:BB:CC:DD:EE:FF

# End-to-end: run all sims, wait for indexing, then verify:
./run_all.sh
```

The full live-lab procedure (with troubleshooting and evidence capture) is in
[`docs/SOP-022-anomaly-validation.md`](../../docs/SOP-022-anomaly-validation.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All assertions passed |
| `1` | One or more detections missing from Elasticsearch |
| `2` | Prerequisite missing (nmap, sshpass, etc.) |
| `3` | OpenWrt SSH unreachable — quarantine verify only |

## Configuration

All knobs in `.env`. Defaults are lab-safe (localhost / RFC1918):

| Variable | Default | Purpose |
|---|---|---|
| `TARGET_HOST` | `127.0.0.1` | Box the sims point at (must be your lab) |
| `BRUTE_USER` | `bogususer` | Throwaway SSH user for brute attempts |
| `MALWARE_SAMPLE_URL` | EICAR test ZIP | Benign signature file inside a ZIP |
| `ES_URL` | `http://localhost:9200` | Elasticsearch read endpoint |
| `ES_INDEX` | `logstash-security-*` | Index pattern to query |
| `LOOKBACK_MIN` | `10` | Verifier search window |
| `OPENWRT_HOST` | `192.168.1.1` | Router for quarantine check |
| `OPENWRT_USER` | `root` | SSH user on router |
| `SSH_KEY` | `~/.ssh/id_ed25519_hivemind` | Key for OpenWrt SSH |

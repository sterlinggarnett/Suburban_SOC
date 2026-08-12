# SOP-022 — Detailed Procedure (companion to SOP-022-anomaly-validation.md)

> This is the step-by-step operational companion to
> [SOP-022 — Anomaly Validation via Attack Simulation](SOP-022-anomaly-validation.md).
> The top-level SOP covers purpose, scope, and compliance mapping; this
> document is the copy-pasteable runbook: prerequisites, numbered steps,
> expected detection mappings, troubleshooting, and evidence capture. Split
> out (#215) so the SOP itself stays a scannable playbook-template overview
> without losing this operational detail.

**Owner:** Tommy Lammers (@voltron-1) — Security Analyst / Manager
**Tracks:** Issue #22 (User Story — Validation via Anomaly Simulation)

---

## Safety

**This procedure generates real attack traffic patterns.** Port scans, SSH brute-force, and suspicious downloads must only be run against:

- Systems you personally own, OR
- Lab equipment with explicit written authorization

Defaults in `tests/anomaly_simulation/.env.example` point at `127.0.0.1` and the EICAR test file (a universally-recognized AV/IDS test signature — harmless but reliably triggers detection). Do **not** edit `.env` to target third-party hosts.

---

## Prerequisites

Run `tests/anomaly_simulation/preflight.sh` to validate all items below in one shot. Manual checks:

| Requirement | How to Verify | Fix |
|---|---|---|
| `nmap` installed | `command -v nmap` | `sudo apt install nmap` |
| `sshpass` installed | `command -v sshpass` | `sudo apt install sshpass` |
| `curl` installed | `command -v curl` | `sudo apt install curl` |
| Python 3.10+ | `python3 --version` | use system pkg manager |
| `elasticsearch` python pkg | `python3 -c "import elasticsearch"` | `pip install -r tests/anomaly_simulation/requirements.txt` |
| Elasticsearch reachable | `curl -k -u "elastic:$ELASTIC_PASSWORD" https://localhost:9200` | `docker compose up -d` |
| `logstash-security-*` index has data | check Kibana Discover | run a capture script per SOP-001 |
| AI Agent listening on :5000 | `curl http://localhost:5000/weekly-report/status` | start per Step 4 below |
| ~~Kibana Watcher `soar_quarantine_alert` installed~~ | retired (#267) — see Step 5 | N/A, skip Step 5 |
| OpenWrt SSH reachable | `ssh -i ~/.ssh/id_ed25519_hivemind root@192.168.1.1 'echo ok'` | check key + router |
| `DISCORD_WEBHOOK_URL` set (optional) | `echo $DISCORD_WEBHOOK_URL` | export from `.env` if you want Discord embeds |

---

## End-to-End Validation Procedure

### Step 1 — Configure the harness

```bash
cd tests/anomaly_simulation
cp .env.example .env
$EDITOR .env   # set TARGET_HOST, OPENWRT_HOST, SSH_KEY at minimum
```

### Step 2 — Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 3 — Run preflight

```bash
./preflight.sh
```

Expected: every line green; exit 0. Resolve any red items before proceeding — `preflight.sh` is a hard gate.

### Step 4 — Bring up the AI Agent

```bash
cd ../../scripts/setup/ai_agent
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."   # optional
flask --app agent_app run --host 0.0.0.0 --port 5000
```

Expected: `Running on http://0.0.0.0:5000`. Leave this terminal open.

### Step 5 — SKIP (retired, #267)

The `soar_quarantine_alert` Watcher was superseded by `configs/logstash.conf`'s
ingest-time HMAC-signed trigger (#220) — nothing to install. As of #267 that
live trigger covers 2 of the Watcher's original 3 conditions live (`zeek.intel`
IOC hits, SSH brute-force T1110 — both handshake-backed, not spoofable).
`Scan::Port_Scan` (T1046) stays dashboard-only, same as before #267: it fires
on a bare SYN with no completed handshake, so wiring it into live SOAR
dispatch without a source-spoofing defense would let a forged-source SYN
sweep trigger automated response against an attacker-chosen IP — deferred
until [#331](https://github.com/voltron-1/Suburban_SOC/issues/331). The
Watcher file itself has moved to
`rules/elastic_watcher/retired/soar_quarantine_alert.json` (historical
reference only, do not install) and is no longer picked up by
`deploy_dashboards.sh`. Proceed to Step 6.

### Step 6 — Run the three attack simulations

```bash
cd tests/anomaly_simulation
./run_all.sh
```

Expected output (truncated):

```
--- [1/3] Network reconnaissance ---
[*] Port scan sim: TCP SYN scan of 127.0.0.1, ports 1-1024
[+] Scan complete. Allow ~30s for Zeek + Logstash to index.

--- [2/3] SSH brute force ---
[*] Brute-force sim: 5 failed SSH attempts → bogususer@127.0.0.1
[+] Brute-force sim complete (5 attempts). Allow ~30s for indexing.

--- [3/3] Suspicious download ---
[*] Download sim: pulling https://secure.eicar.org/eicarcom2.zip
[+] Download complete: /tmp/anomaly_sim_sample.zip (308 bytes)

[*] Waiting 45s for Zeek + Logstash + Elasticsearch indexing...

--- Verifying detections in Elasticsearch ---
  [PASS] Port scan       (Scan::Port_Scan in zeek.notice) — hits=1 (need >= 1)
  [PASS] SSH brute force (5+ auth_success=F in zeek.ssh)  — hits=5 (need >= 5)
  [PASS] Malware download(application/zip in zeek.files)  — hits=1 (need >= 1)

[+] All expected detections present.
```

Exit code `0` = all three detection paths working end-to-end.

### Step 7 — Trigger the SOAR quarantine path

The default Watcher only fires on `threat.indicator.domain` hits. To validate the quarantine plumbing without waiting for a real IOC, POST a synthetic alert directly to the agent:

```bash
curl -X POST http://localhost:5000/alert \
  -H "Content-Type: application/json" \
  -d '{
        "severity": "critical",
        "source_ip": "192.168.1.42",
        "source_mac": "AA:BB:CC:DD:EE:FF",
        "technique": "T1046",
        "raw_log": {"test": "synthetic"}
      }'
```

`technique` (a MITRE ATT&CK ID, e.g. `T1046`) is optional — omit it to skip the
bounded sliding host+technique suppression window entirely (#220). If set and
this exact host+technique combination fired within the last 15 minutes, the
agent returns `{"status": "ignored", "message": "suppressed: ...", ...}`
instead of drafting a new case.

To see this specific path fire (not the older 5-minute tenant/IP/MAC/severity
dedup, which a byte-identical repeat within 5 minutes hits first and which
returns a different message, `"duplicate or in-progress alert"`): re-run the
command above **twice, more than 5 minutes but less than 15 minutes apart**,
keeping `severity`/`source_ip`/`source_mac`/`technique` identical — a
severity change on the second call is read as an escalation and
intentionally bypasses suppression rather than demonstrating it.

Expected:
- AI Agent log: `Quarantine by MAC address (persists across IP/DHCP changes)`
- ntfy push delivered to `$NTFY_TOPIC`
- Discord embed delivered to `$DISCORD_WEBHOOK_URL` (if set)

### Step 8 — Confirm the OpenWrt rule installed

```bash
./verify_quarantine.sh AA:BB:CC:DD:EE:FF
```

Expected:
```
[*] Verifying quarantine rule 'SOAR_QUARANTINE_AABBCCDDEEFF' on 192.168.1.1...
[+] PASS: Rule SOAR_QUARANTINE_AABBCCDDEEFF is installed and persistent.
```

Cross-check on the router:
```bash
ssh -i ~/.ssh/id_ed25519_hivemind root@192.168.1.1 \
  "uci show firewall | grep SOAR_QUARANTINE"
```

### Step 9 — Tear down the test rule

```bash
ssh -i ~/.ssh/id_ed25519_hivemind root@192.168.1.1 \
  "uci show firewall | grep -oE '@rule\[[0-9]+\]' | head -1 | \
   xargs -I{} sh -c 'uci delete firewall.{} && uci commit firewall && /etc/init.d/firewall restart'"
```

> ⚠️ Manually verify the rule index before deleting in a real environment — the example above deletes the first matching rule and assumes only the test rule is present.

---

## Expected Detection Mappings

| Sim | Zeek log | Elasticsearch field | Value |
|---|---|---|---|
| Port scan | `notice.log` | `note` | `Scan::Port_Scan` |
| Brute force | `ssh.log` | `auth_success` | `false` (5+ rows) |
| Suspicious download | `files.log` | `mime_type` | `application/zip` |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `[FAIL] Port scan — hits=0` | Zeek's Scan policy needs `Scan::analyzing_up_to_port` ≥ scanned range | check `local.zeek` for scan policy load |
| `[FAIL] SSH brute force — hits=N<5` | Target SSH service rate-limiting | wait 60s and rerun, or target a lab box without fail2ban |
| `[FAIL] Malware download` | Egress proxy stripping EICAR mid-transit | use an internal sample URL |
| `verify_quarantine.sh exit 3` | OpenWrt SSH key missing or wrong | check `SSH_KEY` env, regen with `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_hivemind` and copy to router |
| AI Agent doesn't invoke isolate.sh | `sudo` requires password | add NOPASSWD entry in sudoers for the isolate.sh path |
| Discord embed not delivered | `DISCORD_WEBHOOK_URL` not exported | `export DISCORD_WEBHOOK_URL=...` in the same shell that runs Flask |
| Live trigger never fires | `threat.indicator.domain` not present in `zeek.conn`, or a Zeek notice never made it past `event.dataset == "zeek.notice"` with a `T1110` tag (**T1046 does not dispatch — dashboard-tagged only, deliberately, until #331**) | enrich via the threat-intel feed, check `configs/logstash.conf`'s Category 5/6 blocks, or test by POSTing directly to `/alert` per Step 7 (the Watcher-based trigger is retired, #267 — this is the ingest-time trigger now) |

---

## Evidence Capture

Save the following to `evidence/sprint6/anomaly-validation-YYYY-MM-DD/`:

- `run_all.log` — full output of Step 6
- `kibana-portscan.png` — Discover screenshot showing the `Scan::Port_Scan` notice
- `kibana-bruteforce.png` — Discover screenshot showing 5+ `auth_success=false` rows
- `kibana-malware.png` — Discover screenshot showing the `application/zip` file event
- `quarantine-rule.txt` — output of `uci show firewall | grep SOAR_QUARANTINE`
- `discord-embed.png` — screenshot of the SOC channel notification

---

## Related Documents

- [SOP-022 — Anomaly Validation via Attack Simulation](SOP-022-anomaly-validation.md) (overview)
- [SOP-001 — Pipeline Operations](./SOP-001-pipeline-operations.md)
- [Architecture (wiki)](https://github.com/voltron-1/Suburban-SOC/wiki/Architecture)
- [Issue #22 — User Story](https://github.com/voltron-1/Suburban_SOC/issues/22)

# SOP-147 — Detailed Procedure (companion to SOP-147-evidence-validation-runbook.md)

> This is the step-by-step operational companion to
> [SOP-147 — Evidence Validation Runbook](SOP-147-evidence-validation-runbook.md).
> The top-level SOP covers purpose, scope, and compliance mapping; this
> document is the copy-pasteable procedure: Section 0 prerequisites
> (including the field-verified Path B mesh capture recipe), Sections A–E,
> and the Definition of Done. Split out (#215) so the SOP itself stays a
> scannable playbook-template overview without losing this operational
> detail — nothing here has been deleted, only relocated.

> **Tracks:** [Issue #147](https://github.com/voltron-1/Suburban_SOC/issues/147) — "Evidence real telemetry: replace mock-data evidence (audit P0-4) and validate all dashboards/detections end-to-end."
>
> **Goal:** produce reviewer-checkable evidence that every dashboard panel and detection works on **real, attributable telemetry**, and purge all mock data. Every screenshot must be logged in **both** `evidence/README.md` and the GitHub Wiki with: one-line description, **SHA-256**, **UTC capture window**, **source IP(s)/host(s)**, and **source index/data stream**.

This procedure expands each section of the issue into ordered, copy-pasteable steps. It builds on [SOP-022's procedure](SOP-022-anomaly-validation-procedure.md) (the simulation harness). Work top-to-bottom: **Prerequisites → A → B → C → Reviewer self-check → Definition of Done.**

---

## Conventions used below

```bash
# Run all ES/Kibana commands with the stack creds (auto-loaded from the setup .env).
cd scripts/setup && set -a && source .env && set +a
ES_URL="${ES_URL:-https://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"  # #177: Kibana is TLS-only now
AUTH="-u ${ES_USER:-elastic}:${ES_PASS:-$ELASTIC_PASSWORD}"
# TLS is on; use -k for the self-signed dev CA (or point --cacert at the CA).
ES() { curl -s -k $AUTH "$@"; }
```

**Record the run window once, up front, and reuse it everywhere:**

```bash
WINDOW_START="$(date -u +%FT%TZ)"   # capture BEFORE you start generating telemetry
# ... run sims / capture ...
WINDOW_END="$(date -u +%FT%TZ)"     # capture AFTER
echo "UTC window: $WINDOW_START → $WINDOW_END"
```

**Hash + log every screenshot the same way:**

```bash
sha256sum evidence/screenshots/<name>.png        # Linux/WSL
# Get-FileHash evidence\screenshots\<name>.png -Algorithm SHA256   # PowerShell
```
Then add a row to `evidence/README.md` **and** the Wiki: `desc | SHA-256 | UTC window | source IP/host | index/data stream`.

---

## Section 0 — Prerequisites (do first)

### Step 0.1 — Purge mock data
Delete every fabricated index/doc so no panel can read it, then confirm the count is 0 or the index is gone.

```bash
# Remove the known fabricated indices
ES -X DELETE "$ES_URL/.alerts-security.alerts-mock"
ES -X DELETE "$ES_URL/logstash-dynamic-2026"

# Delete any hand-injected docs from the real alerts stream (mock markers / fake .encrypted / NK-CN-RU strings)
ES -X POST "$ES_URL/.internal.alerts-security.alerts-default-*/_delete_by_query" \
  -H 'Content-Type: application/json' -d '{
    "query": { "query_string": { "query": "mock OR fabricat* OR *.encrypted OR \"North Korea\"" } }
  }'

# Verify nothing remains
ES "$ES_URL/.alerts-security.alerts-mock/_count"          # expect 404 / index_not_found
ES "$ES_URL/logstash-dynamic-2026/_count"                 # expect 404 / index_not_found
```
✅ **Done when:** both `_count` calls return 0 or `index_not_found_exception`.

### Step 0.2 — Quarantine the suspect evidence (don't delete yet)
In `evidence/README.md`, mark every existing `screenshots/*.png` row **"PENDING RE-CAPTURE"**. The header disclaimer is already present — keep each unverified row flagged until it is re-captured in Sections A/B.

### Step 0.3 — Stack up & healthy
```bash
cd scripts/setup && docker compose up -d
./stack_health.sh                                  # ES, Kibana, Logstash, agent, broker all UP
ES "$ES_URL/_cluster/health?pretty"                # status: green/yellow, no unassigned primaries
```
✅ **Done when:** `stack_health.sh` shows nothing DOWN and Kibana answers on `:5601`.

### Step 0.4 — Confirm the emulation→detection wiring (static precondition)
```bash
python tests/validate_emulation_map.py             # expect 24/24 green
```
This proves every sim, log-source config, and Sigma rule in `configs/detections/emulation_telemetry.map` exists and ATT&CK tags match — **before** you spend a capture window. It does NOT prove an emulation's actual telemetry output matches its paired rule's detection logic — check the `.map` file itself for `# BROKEN PAIRING`/caveat comments above a section before running that specific scenario (e.g. `EXPLOITATION`, #383: structurally green here, confirmed NOT to produce matching telemetry).
✅ **Done when:** 24/24 pass.

### Step 0.5 — Generate real telemetry (pick Path A or Path B)

**Path A — Simulation harness (default, no special hardware):**
```bash
cd "$(git rev-parse --show-toplevel)"/tests/anomaly_simulation   # repo-root-relative; safe to run from anywhere in the repo
cp -n .env.example .env && $EDITOR .env            # set TARGET_HOST, ES creds, agent URL
# One-time: create the venv (modern Debian/Ubuntu block system-wide pip — PEP 668).
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# IMPORTANT: source the venv in EVERY shell before running the sims, so the
# `python3` that run_all.sh / verify_detections.py invoke is the venv's.
source .venv/bin/activate
./preflight.sh                                     # every prereq must PASS
# refresh real intel (shipped feed is TEST placeholders) OR use seeded 198.51.100.66
# (bash, not direct execution — this repo's core.fileMode=false means no .sh
# file is git-tracked as executable, so ./refresh_intel.sh fails "Permission
# denied" on a fresh clone; caught while automating this via systemd, #222)
bash ../../configs/intel/refresh_intel.sh
WINDOW_START="$(date -u +%FT%TZ)"
./run_all.sh                                       # portscan + ssh brute + EICAR, then verify_detections.py
./sim_intel_match.sh                               # live intel → ingest-time alert → agent draft
WINDOW_END="$(date -u +%FT%TZ)"
```

**Path B — Real boundary capture (if an OpenWrt mesh / capture NIC is available):**
```bash
cd "$(git rev-parse --show-toplevel)"/scripts/setup   # repo-root-relative; safe to run from anywhere in the repo
WINDOW_START="$(date -u +%FT%TZ)"
./stream_capture.sh bat0    # or br-lan / raw (#173 — one script, mode = capture source)
# let it run a defined window, then drive traffic that ACTUALLY crosses the captured interface
WINDOW_END="$(date -u +%FT%TZ)"
```

> **Path B traffic must cross the captured interface — the local Path-A sims won't.**
> `stream_capture.sh bat0` captures `bat0` *on the router* (over SSH); the SOC host is not a
> mesh node, so `sim_portscan.sh` (which scans loopback/local) never appears. To exercise a
> port scan on `bat0`, run it **from a mesh node against another host reached over the mesh**:
> - **Pick a target across the mesh, then *prove* it crosses `bat0`.** The routing table is
>   misleading: `bat0` is bridged into `br-lan`, so `ip route get <host>` says `dev br-lan` for
>   *everything* — mesh and local alike. Confirm at L2 instead. Use the batman global
>   translation table to find clients behind the peer node:
>   `ssh root@<router> 'batctl tg; ip neigh'` — a client whose `Via` is the peer mesh MAC
>   traverses `bat0`. Then verify directly by sniffing while you probe (this is the only
>   reliable check):
>   ```bash
>   ssh root@<router> 'tcpdump -i bat0 -n -c 5 host <target> & sleep 1; nc <target> 22 </dev/null; wait'
>   ```
>   If `tcpdump` shows your SYNs, the target is good. (In our mesh, the peer AP's wireless
>   client `10.18.81.59` works; `10.18.81.190` is local to `br-lan` and never hits `bat0`.)
> - **Scan tooling on stock OpenWrt is minimal: no `nmap`, no `timeout`, and busybox `nc` has
>   no `-w` flag.** So a `nc -w1` sweep silently sends nothing. Background each `nc` (the SYN
>   leaves the instant it starts), collect PIDs, then `kill` them. 60 ports clears the policy's
>   (`configs/zeek/scan-detection.zeek`) **20-distinct-port / 5-min** threshold 3×:
>   ```bash
>   ssh root@<router> 'T=<target>; pids=""; for p in $(seq 1 60); do nc $T $p </dev/null >/dev/null 2>&1 & pids="$pids $!"; done; sleep 3; kill $pids 2>/dev/null'
>   ```
> - Verify the notice (`src` = the scanning node's IP, current `ts`):
>   `docker exec "$(docker ps --filter name=zeek- -q)" grep -i Scan::Port_Scan /data/zeek_logs/notice.log | tail -1`.
  (#364, security-auditor: `--filter ancestor=zeek/zeek:<tag>` — the previous form here — is
  live-confirmed unreliable: a container started from a `repo:tag@digest` reference doesn't
  always get that tag applied to the local image store, so the tagged filter can silently
  match nothing even with the exact right container running. `--filter name=zeek-` is
  deterministic instead — matches both `--name zeek-host-capture` (zeek-host-capture.service)
  and `--name zeek-stream` (stream_capture.sh, #364) regardless of which real capture path is
  active or what tag it's pinned to, so it never needs updating on a future bump.)
>
> **File-download detection (`files.log` mime type) needs cleartext HTTP, not browsing.**
> A client behind the peer AP gets its traffic onto `bat0`, but ordinary web traffic is HTTPS —
> Zeek logs `conn`/`ssl`/`dns` but **cannot type a file inside TLS**, so there is no `files.log`
> `mime_type`. Public sites (EICAR included) force HTTP→HTTPS, so serve the sample yourself over
> plain HTTP:
> - **Server and client must straddle `bat0`:** client **behind the peer AP** (e.g. a host on
>   `10.18.81.14`), HTTP server on the **main-router side** (the router itself, or a box wired to
>   it). Two hosts behind the *same* AP stay local and never cross `bat0`.
>   ```bash
>   # on a main-router-side host, in a dir holding eicar_com.zip:
>   python3 -m http.server 8000
>   # from the client behind the peer AP:
>   curl -o /tmp/x.zip http://<server-ip>:8000/eicar_com.zip
>   ```
> - The ZIP bytes cross `bat0` in cleartext → Zeek types them. The client logs with its own
>   `10.18.81.x` IP (bridged L2 mesh — no NAT, unlike a SOC-host-driven sim). Verify:
>   `docker exec "$(docker ps --filter name=zeek- -q)" grep -i application/zip /data/zeek_logs/files.log | tail -1`.
  (Same #364 name-filter note as the port-scan verification command above.)
> - Quick path-only sanity check (cleartext, but `text/html` not zip):
>   `curl http://testmynids.org/uid/index.html` from the client → appears in `http.log` on `bat0`.
>
> NB: `sim_malware_download.sh` itself stays Path-A-only — it fetches EICAR over HTTPS to the
> internet, which neither crosses `bat0` nor exposes the file to Zeek.

✅ **Done when:** you have recorded `WINDOW_START`, `WINDOW_END`, the **source IP(s)/host(s)**, and (Path B) the **capture interface**.

---

## Section A — Detection → SOAR loop (one screenshot set per technique)

For each item: generate the event → confirm the raw Zeek doc indexed → confirm the SOAR action → screenshot the Kibana Case + the append-only audit record. Log all in `evidence/README.md` + Wiki.

### Step A.1 — Port scan (T1046)
```bash
cd tests/anomaly_simulation && ./sim_portscan.sh
```
Evidence to capture:
1. The `zeek.notice` `Scan::Port_Scan` doc — `ES "$ES_URL/logstash-security-*/_search?q=note:Scan::Port_Scan"`.
2. The pipeline-tagged `threat.technique.id: T1046` on that same doc
   (`configs/logstash.conf` Category 5) — dashboard/metric evidence.

**No SOAR draft is expected for this scenario.** T1046 is deliberately NOT
wired into the live `/alert` dispatch (`configs/logstash.conf` Category 6,
#267) — `scan-detection.zeek` fires on a bare SYN with no completed
handshake, so a source-spoofed sweep could otherwise trigger automated
containment against an attacker-chosen IP.
[#331](https://github.com/voltron-1/Suburban_SOC/issues/331) investigated
two sensor-side fixes for the resulting metric-gaming impact and rejected
both after live security review (neither actually defended against
spoofing at this deployment's capture vantage point without losing real
detection recall or introducing a silent denial-of-detection gap).
`scan-detection.zeek` is unchanged; #331's actual fix is a distinct-source
signal added to `slo_metrics.py`'s `raw_alert_volume` metric instead. T1046
stays dashboard-only indefinitely — no source-authenticity signal exists
for this notice at all.
**Known limitation:** the distinct-source signal only separates a *wide*
flood (many forged sources) from real activity — a small, fixed number of
forged sources sustained over the metric's window can push `zeek_notices`
high while `zeek_notices_distinct_sources` stays low, reading like a few
real repeat scanners. A high count paired with a low distinct-source count
is **ambiguous**, not confirmed-benign. Steps 3/4 (approve → broker DROP →
Case/audit) do not apply to this scenario today; see Step A.2 for a
scenario that does exercise the full SOAR chain.

### Step A.2 — SSH brute force (T1110)
```bash
./sim_brute_ssh.sh
```
Evidence: ≥5 `zeek.ssh` sessions from one source → SOAR draft → Case → `soc-audit-*`. (Note: per `verify_detections.py`, the check is the **cadence** of 5+ sessions, not Zeek's per-conn auth inference.)

### Step A.3 — Malware download (T1105-ish, EICAR)
```bash
./sim_malware_download.sh
```
Evidence: the `zeek.files` doc with `application/zip` MIME indexed. Screenshot the file doc.

### Step A.4 — Live intel match
```bash
./sim_intel_match.sh          # uses refreshed feed OR seeded 198.51.100.66
```
Evidence: ES doc with `threat.indicator.ip` set → ingest-time `/alert` → agent `/pending` count grew → `soar-actions-*` entry.

### Step A.5 — Quarantine executed
```bash
./verify_quarantine.sh <TARGET_MAC>      # needs the MAC arg + a test router
```
Evidence: the nftables rule present on the router + the broker log + `soar-actions-*` with `response.automated=true`.

### Step A.6 — Exclusion holds (governance protected asset)
Fire an alert targeting `192.168.1.1` (the governance exclusion) and confirm the agent returns `no_action_protected_asset` and the asset is **never** isolated.
Evidence: the agent response JSON + the matching `soc-audit-*` record.

✅ **Section A done when:** each of A.1–A.6 has a screenshot row (or an honest negative result) with the full provenance set.

---

## Section B — Dashboards (the 5-dashboard ecosystem + supporting)

Open each dashboard in Kibana, set the time picker to **your recorded UTC window**, screenshot, hash, log.

### Step B.1 — Executive / Bird's-Eye (`executive-dashboard`)
Confirm KPIs, the **NIST CSF donut**, the **MITRE ATT&CK heatmap** (techniques driven by the real detections from Section A), and SOAR response metrics all populate.

### Step B.2 — Network & Traffic (`network-dashboard-v3`)
Traffic volume, top talkers, DNS/HTTP, **TLS/SNI**, and the **GeoIP map** populated from a real public source IP — confirm `source.geo.country_name` and lat/lon are present (re-captures evidence rows #1 and #4).

### Step B.3 — Endpoint & Host (`endpoint-dashboard`) — **evidence as "tooling ready" (decision #2)**
Do **not** fabricate endpoint data. Instead prove the path exists:
- `configs/endpoint/winlogbeat.yml` + `filebeat_endpoint.yml` ship TLS to `:5044`.
- The pipeline maps endpoint fields; the 32 endpoint Sigma rules convert/deploy.
- The 19 Windows emulation scripts (`tests/anomaly_simulation/sim_win_*.ps1`) exist to drive them once an endpoint attaches.

Mark live process-anomaly / auth / Sigma-hit panels **"awaiting a live endpoint."**

### Step B.4 — Data Quality & Ingestion (`dataquality-dashboard`)
Agent heartbeats, ingest throughput, parse-error tracking, and the **Document-Lag panel** — confirm lag is ~seconds (UTC `event.created`), not a timezone-sized offset.

### Step B.5 — SOC Home / Navigation Hub (`soc-navigation-hub`)
Cross-links resolve; at-a-glance KPIs reflect the real data from B.1–B.4.

### Step B.6 — Supporting dashboards
Intel Feed Health, SLO, Hunts, Control Status / Asset Inventory — each shows real (or honestly empty) data.

✅ **Section B done when:** every dashboard above has a re-captured screenshot row; endpoint panels are honestly labeled, not faked.

---

## Section C — Pipeline & platform integrity

### Step C.1 — Data streams green + ILM-managed
```bash
ES "$ES_URL/_data_stream/.ds-logstash-security-*?pretty"           # health: green
ES "$ES_URL/.ds-logstash-security-*/_ilm/explain?pretty"           # managed:true, policy:logstash-security-ilm
```

### Step C.2 — Tenant attribution
Confirm events carry the right `tenant.id` and per-tenant indices / Kibana spaces isolate as designed.
```bash
ES "$ES_URL/logstash-security-*/_search?size=0" -H 'Content-Type: application/json' \
  -d '{"aggs":{"tenants":{"terms":{"field":"tenant.id"}}}}'
```

### Step C.3 — Snapshot-before-delete wired
```bash
ES "$ES_URL/_slm/policy/suburban-soc-daily-snapshots?pretty"
ES -X POST "$ES_URL/_slm/policy/suburban-soc-daily-snapshots/_execute"   # take one
ES "$ES_URL/_snapshot/_status?pretty"                                    # verify it
```

### Step C.4 — Audit trail append-only
Confirm the agent's `soc_audit_appender` role cannot update/delete `soc-audit-*` (an update/delete attempt should be rejected). Screenshot the role definition + a denied write.

### Step C.5 — TLS end-to-end
```bash
cd scripts/setup && ./verify_encryption.sh        # beats→Logstash :5044 and Logstash→ES CA-verified
```
Confirm no plaintext path and no `verify=False` anywhere in the live config.

✅ **Section C done when:** C.1–C.5 each have a passing command output / screenshot logged.

---

## Section D — Industry SOC metrics (Definition of Done)

Capture **real measured values** from the evidenced window (not targets) and log them in `evidence/README.md`.

```bash
cd scripts/setup/ai_agent && python slo_metrics.py        # MTTD/MTTR/SLO from soar-actions-* + data-quality
```
Record:
- **Detection:** MTTD, ATT&CK technique coverage (techniques actually fired vs the **24** in `docs/detections/attack-coverage.md`; the 24 emulation→detection pairs span 21 of them), alert volume, false-positive rate.
- **Response:** MTTR / containment latency (`soar-actions-*` `response.latency_seconds`), automation rate (autonomous vs human-approved).
- **Operational:** ingest throughput, ingest lag (UTC Document-Lag), parse-error %, data-stream health, SLO attainment vs configured targets.

---

## Section E — Reviewer self-check (run before requesting approval)

Walk the issue's 7 reviewer checks yourself first:

1. **Provenance** — every `evidence/README.md` row has SHA-256 + UTC window + source IP/host + index. Re-hash each PNG; confirm it matches.
2. **No mock residue:**
   ```bash
   ES "$ES_URL/.alerts-security.alerts-mock/_count"     # 0 / absent
   ES "$ES_URL/logstash-dynamic-2026/_count"            # 0 / absent
   ES "$ES_URL/logstash-security-*/_count" -H 'Content-Type: application/json' \
     -d '{"query":{"query_string":{"query":"mock OR fabricat* OR *.encrypted"}}}'   # 0
   ```
3. **Timestamp cross-check** — docs behind each panel fall inside the recorded window; `event.created` is UTC and within seconds of `@timestamp`.
4. **Source cross-check** — IPs/MACs/hosts match the simulator (`tests/anomaly_simulation/.env` `TARGET_HOST`, EICAR/nmap source) or the real capture NIC — not "Russia/China/NK" fabrications.
5. **End-to-end linkage** — raw Zeek event → detection → `soar-actions-*` (with `response.latency_seconds`) → Kibana Case → `soc-audit-*`, all sharing source + window.
6. **Reproducibility** — re-run `run_all.sh` (Path A) or restart capture (Path B) + `verify_detections.py` against a fresh window → passing.
7. **GeoIP reality** — the map point resolves from a genuine public IP (e.g. `8.8.8.8`) with `source.geo.location` present.

---

## Definition of Done (final checklist)

- [ ] All mock indices/docs purged; no panel reads fabricated data (Step 0.1 / E.2).
- [ ] Every A/B/C checklist item has a re-captured screenshot + complete row in **both** `evidence/README.md` and the Wiki.
- [ ] Industry SOC metrics (Section D) recorded as real measured values.
- [ ] `run_all.sh` (Path A) or live run (Path B) + `verify_detections.py` pass against the evidenced window.
- [ ] Old/suspect screenshots replaced or clearly retired; `docs/AI_conversation_transcript.md` keeps its "mock data, not validation evidence" disclaimer.
- [ ] One reviewer approval on issue #147.

---

## Related Documents

- [SOP-147 — Evidence Validation Runbook](SOP-147-evidence-validation-runbook.md) (overview)
- [SOP-022's procedure](SOP-022-anomaly-validation-procedure.md) (simulation harness this builds on)

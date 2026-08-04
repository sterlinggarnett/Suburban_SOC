# Evidence Directory

> **Important:** DO NOT upload raw evidence files (like raw PCAPs) directly to this repository. Only store hashes and download links here.
>
> Screenshots are stored in two locations:
> - **Repository:** `evidence/screenshots/` (GitHub-hosted, linked below)
> - **Wiki:** [Suburban_SOC Wiki](https://github.com/voltron-1/Suburban_SOC/wiki) (drag-and-drop uploads)
>
> **Re-capture in progress (audit P0-4).** Some screenshots below predate the security audit and may have been generated from **mock data**. They are being re-captured from **real telemetry** and re-verified per [issue #147](https://github.com/voltron-1/Suburban_SOC/issues/147) (evidence checklist + reviewer instructions). Treat any row not yet re-verified as **PENDING**.
>
> **Section references below** (e.g. "A.1 Port scan", "Section B rows #14–#22") refer to the numbered sections in [SOP-147's detailed procedure](../docs/SOP-147-evidence-validation-procedure.md) (#215) — the top-level [SOP-147](../docs/SOP-147-evidence-validation-runbook.md) is a scannable overview and no longer carries the section numbering itself.

---

## Evidence Log

| # | Status | Description | Type | SHA-256 Hash | Links |
|---|---|---|---|---|---|
| 1 | 🗄️ **RETIRED** (mock-era; superseded by Section B rows #14–#22) | Kibana GeoIP Map — live network traffic origins plotted by geographic location, confirming Logstash GeoIP enrichment is working end-to-end | Screenshot | `3a8527bd2bd17150b7cbff04bdf95d53ea268f3ba43704580eab9ff3c9ba68db` | [Repo](screenshots/kibana-geoip-map.png) · [Wiki](https://github.com/voltron-1/Suburban_SOC/wiki/kibana-geoip-map) |
| 2 | 🗄️ **RETIRED** (mock-era; superseded by Section B rows #14–#22) | Kibana Pie Chart — protocol and traffic distribution breakdown, confirming Zeek JSON logs are indexed and queryable in Elasticsearch | Screenshot | `168ba0532de146713b0fee27dbfb537b5c9aa2f29a8b7183472a2406306679a8` | [Repo](screenshots/kibana-pie-chart.png) · [Wiki](https://github.com/voltron-1/Suburban_SOC/wiki/kibana-pie-chart) |
| 3 | 🗄️ **RETIRED** (mock-era; superseded by Section B rows #14–#22) | Kibana Threat Intelligence Panel — security notice visualization confirming Zeek notice logs are flowing through the full pipeline into Kibana dashboards | Screenshot | `d5971c97d3c75253613d1da44887a0e55eb11350f477e6bce3edddc8d36ee70f` | [Repo](screenshots/kibana-intel-panel.png) · [Wiki](https://github.com/voltron-1/Suburban_SOC/wiki/kibana-intel-panel) |
| 4 | 🗄️ **RETIRED** (mock-era; superseded by Section B rows #14–#22) | Kibana Network Analysis Overview — dashboard displaying source IPs, MAC addresses, and network bytes, confirming custom Logstash ECS mapping | Screenshot | `[Pending User Upload]` | [Repo](screenshots/kibana-network-analysis.png) |
| 5 | N/A (config file) | Logstash Pipeline Configuration — documents the Filebeat→Logstash→Elasticsearch connection with GeoIP enrichment, ECS field mapping, and daily index routing | Config File | `04793dccd031899c00d76e768ba7eb59ce997f9255a3e26a76d133d58a81d08a` | [Repo](../configs/logstash.conf) |
| 6 | N/A (diagram) | Architecture Diagram — full pipeline diagram (OpenWrt → Zeek → Logstash → Elasticsearch → Kibana) with runtime environments and port numbers labeled | Diagram | `e2a59fc5c07432719a484aa7773bda166b46b90634925235fac07bce8064b40f` | [Repo](../docs/architecture-diagram.png) · [Wiki](https://github.com/voltron-1/Suburban_SOC/wiki/Architecture) |
| 7 | ✅ **VERIFIED (real telemetry)** | **A.1 Port scan (T1046)** — Kibana Discover showing two `Scan::Port_Scan` (`zeek.notice`) detections, `source.ip 10.18.81.1` → `destination.ip 10.18.81.14`, msg "probed 20+ distinct ports". Source: router-driven bat0 mesh scan (60 distinct ports). UTC window **2026-06-20T22:50–22:54Z** (notices @ 22:51:11Z, 22:52:24Z). Index `.ds-logstash-security-home-smith-*`. | Screenshot | `9b00d74cf66412d498b9c9a64e62eea7436148403929516cb694f228517cbedf` | [Repo](screenshots/a1-portscan-notice-home-smith.png) |
| 8 | ✅ **VERIFIED (real telemetry)** | **A.2 SSH brute force (T1110)** — Kibana Discover showing 5 `zeek.ssh` sessions from one source `10.18.81.190` → `10.18.81.14` (client OpenSSH_9.6p1). Source: `sim_brute_ssh.sh` over bat0 (NAT'd SOC host). UTC window **2026-06-20T22:13:30–22:16:30Z** (sessions @ 22:14:55Z). Index `.ds-logstash-security-home-smith-*`. | Screenshot | `5868e8f585ca3f73ebb77ac9891362fd54f89adf05b56d8d9ef192de57316fa3` | [Repo](screenshots/a2-ssh-bruteforce-home-smith.png) |
| 9 | ✅ **VERIFIED (SOAR draft)** | **A.2 SOAR action** — `soar-actions-home-smith` draft from a signed `/alert` for attacker `10.18.81.190`: `action.type=analyst_review`, `response.automated=false` (human-in-the-loop), `response.latency_seconds=0.097`; paired append-only `soc-audit-home-smith` record (actor `soc-ai-agent`). UTC `2026-06-20T23:07:39Z`. Drives agent→draft→audit; `/approve`→broker DROP intentionally NOT executed (no real isolation). Auto-trigger (detection→`/alert`) is not yet wired — driven manually here. | Screenshot | `983afcb71488b7aeeece0456e43c1216fd275436967136a11a086d622e4b4a6e` | [Repo](screenshots/a2-soar-action-draft-home-smith.png) |
| 10 | ✅ **VERIFIED (real telemetry)** | **A.3 Malware download (T1105, EICAR)** — Kibana Discover showing the `zeek.files` doc typed `mime_type=application/zip`, `source.ip 10.18.81.14` (peer-AP mesh client) → `destination.ip 10.18.81.1:80`, `total_bytes 184`, `fuid FTjsI62eKFzjBk1od` (paired `http.log` `uri /eicar_com.zip`, UA `uclient-fetch`). Source: EICAR ZIP served over **plain HTTP** from the main router `/www`, fetched by the peer AP `10.18.81.14` so bytes cross `bat0` in cleartext (Path B; `sim_malware_download.sh` is HTTPS/Path-A-only and never crosses bat0). UTC window **2026-06-28T22:38–22:41Z** (file event @ 22:39:25Z; ingest lag ~10s). Index `.ds-logstash-security-home-smith-*`. EICAR ZIP SHA-256 `2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad`. | Screenshot | `a17cd47a8307f562c8aef33dac559d16b9f19322608cd8ec0b612b9cf1249120` | [Repo](screenshots/a3-malware-download-home-smith.png) |
| 11 | ✅ **VERIFIED (real telemetry)** | **A.4 Live intel match (threat-intel)** — Kibana Discover: `zeek.intel` doc `threat.indicator.ip=198.51.100.66` (`Intel::ADDR`, feed `suburban-soc/test`), internal `source.ip 10.0.0.50` → flagged indicator. Drove the ingest-time map (Logstash `seen.indicator`→`threat.indicator.ip`) + agent `/alert` → SOAR draft `soar-actions-home-smith` (`analyst_review`, `response.automated=false`, `response.latency_seconds=0.04`). Source: `sim_intel_match.sh` (inject → Logstash `:5514`; Watcher auto-trigger is license-blocked, so `/alert` is sim-driven). UTC window **2026-06-28T23:43:30–23:45:30Z** (event @ 23:44:04Z). Index `.ds-logstash-security-home-smith-*`. NB: this run fixed a pipeline defect — injected intel was silently dropped (ES 400, `user_agent` keyword/object collision); `configs/logstash.conf` now strips `:5514` HTTP-input artifacts. | Screenshot | `98570dd99347cbda575262fed68e4a562060e49926efa6aaf27cf54c84136fe2` | [Repo](screenshots/a4-intel-match-home-smith.png) |
| 12 | ✅ **VERIFIED (real telemetry)** | **A.6 Exclusion holds (governance protected asset)** — Kibana Discover (`soc-audit-*`): append-only `soc-audit-home-smith` record `event.action=alert_excluded_asset`, `actor=soc-ai-agent`, `target=192.168.1.1`, `event.outcome=no_action`. The agent refused the alert (`status=no_action_protected_asset`) and queued NO draft (pending unchanged); the asset was never isolated. Source: `section_a_evidence.sh` signed `/alert` at the governance exclusion `192.168.1.1` (`governance/exclusion_list.txt`, fail-closed). UTC `2026-06-28T23:46:05Z`. Index `soc-audit-home-smith`. (Created the missing `soc-audit-*` Kibana data view this run.) | Screenshot | `a6bdd8db808c2dad4571ca54a7b8886c4e9f1d94a9a31cf2efea79bbba53eb33` | [Repo](screenshots/a6-exclusion-hold-home-smith.png) |
| 13 | ✅ **VERIFIED (honest negative)** | **A.5 Quarantine (tooling ready, not executed)** — `verify_quarantine.sh AA:BB:CC:DD:EE:FF` SSHes the router `10.18.81.1` and checks for the nft/UCI rule `SOAR_QUARANTINE_AABBCCDDEEFF` → **not found**. Real isolation requires a human `/approve` → broker dispatch and is **intentionally NOT executed** on the production mesh (same posture as A.2's broker DROP). Confirms the verifier tooling functions and that no production/protected device was isolated; the agent→broker path is exercised by A.4's draft. UTC `2026-06-28T23:47Z`. | CLI (honest negative) | n/a | [`verify_quarantine.sh`](../tests/anomaly_simulation/verify_quarantine.sh) |
| 14 | ✅ **VERIFIED (partial, honest)** | **B.1 Executive / Bird's-Eye** (`executive-dashboard`) — KPIs populate on real data: Total Events 1,077, Unresolved Critical 1, Event Rate + Alert Volume Trend timeseries. NIST CSF donut, MITRE ATT&CK heatmap, SOAR-action & severity panels show **No results** in-window (depend on tagged detections + denser `soar-actions`; honest gap, not fabricated). Window 2026-06-28T22:00Z–2026-06-29T00:15Z. | Screenshot | `3999f34f9e665ac1d2e0f29922fd09a0c93dee7cbe544f5706b659cbdd9f0cc3` | [Repo](screenshots/b1-executive.png) |
| 15 | ✅ **VERIFIED (real telemetry)** | **B.2 Network & Traffic** (`network-dashboard-v3`) — Traffic Volume, Top Dest Ports, HTTP Status populate; **GeoIP map now plots points** (US + GB geohash circles). Three stacked defects root-caused & fixed this run: (a) geoip wrote a non-ECS path → fixed `configs/logstash.conf` targets; (b) `destination.geo.location` was mapped as a lat/lon **object, not `geo_point`** → added the `geo_point` mapping to `configs/elasticsearch/logstash-security-template.json` and rolled the data stream over (new index `…000007`); (c) the panel was a **deprecated `tile_map`** that renders only the basemap → migrated to an Elastic **Maps** object (`net-geo-map`) and swapped it into the dashboard. Verified plottable via `geo_bounding_box`. NB residual ⚠️: pre-rollover backing indices still carry the object-typed field → partial-shard warning on the geo agg (new data clean; clears as old indices age out via ILM). Re-captures & retires legacy rows #1, #4. | Screenshot | map `9bf30192b2b3bfcd9bb1efa696fa67f1f5f190fecf54c19715e3a4d742a07386` · dash `06a8c36be55a050f130f43fe96c3d9a8a2af0981364a03c44bffe7bb6c0f461c` | [Map](screenshots/b2-geoip-map.png) · [Dashboard](screenshots/b2-network.png) |
| 16 | ✅ **VERIFIED (tooling ready)** | **B.3 Endpoint & Host** (`endpoint-dashboard`) — **honestly empty: awaiting a live endpoint.** No endpoint data fabricated. Path proven elsewhere: `configs/endpoint/winlogbeat.yml`+`filebeat_endpoint.yml` (TLS→:5044), endpoint Sigma rules, and `sim_win_*.ps1` emulation scripts. | Screenshot | `258da103419e3a71c6ede974571820a10f624c75c5d061652e030b94fe3eaa03` | [Repo](screenshots/b3-endpoint.png) |
| 17 | ✅ **VERIFIED (real telemetry)** | **B.4 Data Quality & Ingestion** (`dataquality-dashboard`) — Indexed Docs 1,122, Ingest Errors 2, Ingest Rate + Indexing Activity timeseries, Source Heartbeat (`zeek`/`home-smith`) fresh. Document-Lag ~seconds (UTC). Window as B.1. | Screenshot | `39335775811d7d34186bf00d681cc0e7ed282389ff5656b72b7d837d6a58b9fc` | [Repo](screenshots/b4-dataquality.png) |
| 18 | ✅ **VERIFIED (real telemetry)** | **B.5 SOC Home / Nav Hub** (`soc-navigation-hub`) — Nav grid + at-a-glance KPIs: Total Events 1,142, Open Critical Alerts 1 (Active Agents 0 — no endpoint, honest). Window as B.1. | Screenshot | `77328e284c8f738f6378d3bd5ead4c6ab0be487832c80f56eab62911fa6ed20e` | [Repo](screenshots/b5-soc-home.png) |
| 19 | ✅ **VERIFIED (real telemetry)** | **B.6 Intel Feed Health** (`intel-feed-health`) — Indicators 7, Live 5, Feed Refresh Heartbeats timeseries (driven by `refresh_intel.sh`). Window as B.1. | Screenshot | `47814cb5a7535dcde8ff9b52e12af353d9d2fb89c7029036e7b32fdde52b1238` | [Repo](screenshots/b6-intel-feed-health.png) |
| 20 | ✅ **VERIFIED (real telemetry)** | **B.6 SLO Self-Measurement** (`soc-slo`) — SLO Breaches 0, MTTR 0.001s, ATT&CK Coverage 24, Ingest Lag 182.9s (< 300s target), FP% 0, Parse-Error% 0; MTTD null (no detection→alert timing pairs since Watcher is license-blocked). Window as B.1. | Screenshot | `c4971f1bf6d01242bc21fcf57d1f22504777fd9270e6f02986932b34e9ab9742` | [Repo](screenshots/b7-soc-slo.png) |
| 21 | ✅ **VERIFIED (honestly empty)** | **B.6 Threat Hunts** (`soc-hunts`) — no hunt findings in window (no hunts run this session); panels render, honestly empty. Window as B.1. | Screenshot | `ab6699f39549cc587599d742a78315abf04a9d888ddca10c09e53d41c1d91100` | [Repo](screenshots/b8-soc-hunts.png) |
| 22 | ✅ **VERIFIED (real telemetry)** | **B.6 SOC 2 Control Status** (`soc-control-status`) — all 7 controls **PASS** (C1 TLS, C2 RBAC 6/6, C3 audit append-only, C4 ILM, C5 SLM backup, C6 vuln-scan CI gate, C7 change-mgmt), "pass 100%" donut. Populated by `scripts/setup/collect_control_evidence.sh` → `soc-controls`. UTC `2026-06-29T00:11Z`. | Screenshot | `7192b0a907d7610e20225a8113c831b5c8178f8dee1043338edff145e6ab7547` | [Repo](screenshots/b9-control-status.png) |
| 23 | ✅ **VERIFIED (mostly; 1 caveat)** | **Section C — Pipeline & platform integrity** (CLI). C.1 ILM `managed:true` policy `logstash-security-ilm`. C.2 tenant attribution: `home-smith` 66,748 / `acme-net` 2 / `unassigned` 19,794 (note: unassigned = :5514 input + unstamped sources — data-hygiene follow-up). C.3 SLM `suburban-soc-daily-snapshots` executed → `suburban-soc-snap-2026.06.29-…`. C.4 audit append-only PASS (create-only). C.5 ES :9200 TLS-only + CA-verified + transport TLS PASS; Beats :5044 mTLS enforced (verify_encryption.sh certless probe fails — real Filebeat ships fine, see A.1–A.4); no plaintext path. Full output: `findings/2026-06-28-147-remaining-requirements.md`. | CLI | n/a | `collect_control_evidence.sh`, `verify_encryption.sh` |
| 24 | ✅ **VERIFIED (measured)** | **Section D — Industry SOC metrics** (real measured values, `home-smith`). **Detection:** MTTD n/a (no detection→alert timing pairs — Watcher license-blocked, drafts are sim-driven); ATT&CK coverage **24** techniques (≥10 target); alert volume 1,938 docs/24h (`zeek.conn` 825, `ntp` 604, `ssl` 243, `dns` 206, `quic` 25, `x509` 8, `ssh` 5); **false-positive rate 0%**. **Response:** containment/draft latency 0.04–0.133s (`soar-actions response.latency_seconds`); automation rate 0% (all `analyst_review`, human-in-the-loop by design). **Operational:** ingest lag **median 8.6s / max 10.1s** (≤300s target ✓); parse-error **0%**; data-stream ILM-managed; SLO breaches 0. Source: `slo_metrics.py` (scheduled in-container run; host-direct run has a hardcoded `/certs/ca/ca.crt` caveat) + direct ES aggregation. | CLI | n/a | `scripts/setup/ai_agent/slo_metrics.py` + soc-slo (row #20) |
| 25 | ✅ **VERIFIED (self-check)** | **Section E reviewer self-check** — E.1 provenance: all captured PNG hashes re-verified against this table. E.2 no mock residue: mock/dynamic indices absent; `mock/fabricat*/*.encrypted/"North Korea"` count **0** after dropping 7 legacy pre-tenant `logstash-security-*-ecs` indices (~38k unattributed docs incl. 600 fabricated) — `home-smith` data streams unaffected (66,807 docs). E.3 timestamps in recorded windows, `event.created` UTC ~secs from `@timestamp`. E.4 sources match sims/mesh (`10.18.81.14`, `198.51.100.66`/`10.0.0.50`, `192.168.1.1`). E.5 raw→detection→`soar-actions`→`soc-audit` linked (A.4/A.6). E.7 GeoIP `8.8.8.8`→US at ECS `destination.geo.location`. | CLI | n/a | n/a |

> **Capture method (reproducible):** screenshots #7–#8 were taken headless via `evidence/capture/capture_kibana.mjs` (Playwright) against the live Kibana, with the time-picker pinned to the stated UTC window. Re-hash the PNG to verify: `sha256sum evidence/screenshots/<file>.png`.
>
> **Detection layer only:** these evidence the Zeek detection → Elasticsearch (`home-smith` tenant) link on real bat0 telemetry. The automated SOAR response loop (detection → agent `/alert` → draft → approve → broker DROP → Case → `soc-audit`) was **not** firing at capture time (no `soar-actions-*` generated; trigger not wired) — tracked separately.

---

## Screenshots

### 1. GeoIP Map — Live Traffic Origins
PENDING RE-CAPTURE

### 2. Traffic Distribution Pie Chart
PENDING RE-CAPTURE

### 3. Threat Intelligence Panel
PENDING RE-CAPTURE

### 4. Network Analysis Overview (ECS Mapping Verified)
PENDING RE-CAPTURE

---

## Verification Notes

- **Pipeline tested:** 2026-05-21 (Full End-to-End Security Validation)
- **Data source:** OpenWrt router (`10.18.81.1`) via SSH/tcpdump → Zeek Docker container
- **Log volume:** Real home network traffic captured on `br-lan` and `bat0` interfaces
- **Dashboard:** `configs/server/suburban_soc_dashboards_bundle_final.ndjson` (importable into Kibana)
- **Index pattern:** `logstash-*` (verified in Kibana Discover)

---

## How to Verify SHA-256 Hashes

**Windows (PowerShell):**
```powershell
Get-FileHash evidence\screenshots\kibana-geoip-map.png -Algorithm SHA256
```

**Linux/WSL:**
```bash
sha256sum evidence/screenshots/kibana-geoip-map.png
```

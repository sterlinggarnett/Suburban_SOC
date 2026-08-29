# Suburban-SOC — Maturity & Standards Implementation Roadmap

**Status:** Draft v1 · **Owner:** Engineering · **Last updated:** 2026-06-08
**Applies to:** Suburban-SOC product MVP → v1 (managed multi-tenant home/neighborhood SOC)

---

## 1. Purpose & scope

This roadmap takes the Suburban-SOC MVP from a working single-tenant detection/response
prototype to a deployable product that meets recognized SOC standards. It is a **phased
combo**: fix the ship-blockers, close detection coverage, reach operational maturity, then
make the technical controls audit-ready.

**In scope — the technical functioning of the SOC:**
- Security of the monitoring platform itself (auth, encryption, secrets, audit trail)
- Multi-tenancy & customer-data isolation
- Detection plane (data sources, detection-as-code, threat intel, ATT&CK coverage)
- Response automation (authenticated, validated, reversible, tenant-scoped)
- Detection-engineering lifecycle, threat hunting, pipeline robustness
- Reliability of the SOC stack (HA, backup/restore, self-monitoring)
- The **technical** control set behind NIST CSF / SOC-CMM / SOC 2

**Out of scope (deferred to the capstone / business track):**
- Analyst staffing tiers, shift schedules, on-call rotations, training & certification
- Org charter, customer SLAs-as-contracts, pricing, vendor-management paperwork
- Any governance artifact that is policy text rather than an enforced technical control

## 2. Framework anchors

| Framework | Role in this plan |
|---|---|
| **SOC-CMM** | Operational-maturity target. We drive the **Technology**, technical-**Process**, and technical-**Services** domains to a *Defined* (L3) rating. People/Business domains intentionally not targeted here. |
| **NIST CSF 2.0** | Coverage map. Every detection/response workstream is tagged to a Function (Identify/Protect/Detect/Respond/Recover). Govern is touched only via enforced technical controls. |
| **MITRE ATT&CK** | Detection-coverage yardstick. We publish a coverage matrix and drive breadth + depth. |
| **SOC 2 Type II (TSC)** | Technical-control readiness only — Security, Availability, Confidentiality, Privacy criteria that are *implemented in the platform* (not the written policies an audit also needs). |

## 3. How to read this

Each phase has: **objective**, an **exit gate** (the objective, testable), and **workstreams**.
Each workstream lists concrete **items** with: current state → target, files touched,
acceptance criteria, and a rough effort size (**S** ≤2d · **M** ≤1wk · **L** >1wk).

---

## 4. Current-state baseline (what we're starting from)

| Capability | State | Key evidence |
|---|---|---|
| SIEM pipeline (Zeek→Filebeat→Logstash→ES→Kibana) | ✅ Working | `configs/logstash.conf`, `scripts/setup/docker-compose.yml` |
| Platform authentication | ❌ **None** | `docker-compose.yml:9` `xpack.security.enabled=false`; ES/Kibana/Logstash/agent on open host ports |
| Response webhook auth | ❌ **None** | `agent_app.py:157` `/alert` is unauthenticated → `sudo isolate.sh` |
| Multi-tenancy | ❌ None | Single `logstash-security-*` index, one Kibana, one ntfy topic, one quarantine target set |
| Data retention / ILM | ❌ None | Daily indices, `data_stream => false`, no lifecycle policy |
| Detection content | ⚠️ Demo-grade | 10 `rules/sigma/*.yml` (status `experimental`, compiled as inline regex); hardcoded IOC `logstash.conf:187`; `intel.dat` = 2 entries |
| Threat-intel integration | ⚠️ Placeholder | `configs/intel/data/intel.dat` static, 2 IOCs |
| SOAR trigger correctness | ⚠️ Likely dead | `logstash.conf:268` keys on `threat.indicator.domain`, which nothing in the pipeline sets |
| Config integrity | ⚠️ Drift risk | Two copies: `configs/logstash.conf` and `scripts/setup/configs/logstash/logstash.conf` |
| Detection validation | ✅ Seed exists | `tests/anomaly_simulation/` (3 scenarios + verifier) |
| Reliability | ❌ Single-node | One ES node, no snapshots, no self-monitoring |

**Baseline SOC-CMM capability score: ~1.8/5.** Detection/Respond are real; platform security,
tenancy, retention, and reliability are the gating gaps.

## 5. Target end-state

A multi-tenant SOC where: every plane is authenticated and encrypted; each customer's
telemetry is isolated and retained to a defined policy; detections are version-controlled,
tested in CI, and mapped to a published ATT&CK matrix; response actions are authenticated,
input-validated, reversible, and scoped to the correct tenant; and the technical controls
behind SOC 2 (Security/Availability/Confidentiality/Privacy) are enforced and continuously
evidenced.

---

# PHASE 0 — Secure the platform & lay the tenancy foundation

> **These are ship-blockers.** Nothing else should be deployed to a real customer until
> Phase 0 closes. A security product whose own data and response plane are open is a liability.

**Objective:** No unauthenticated/unencrypted surface; every customer's data and every
response action is tenant-scoped; data has a defined lifecycle.

**Exit gate:**
1. `nmap`/curl against ES:9200, Kibana:5601, Logstash:5044, agent:5000 from off-host returns auth challenges or refused — no anonymous access.
2. A forged POST to `/alert` without a valid signature is rejected (401/403) and does **not** trigger isolation.
3. Two test tenants' events are provably non-cross-readable (Kibana space / role test).
4. An ILM policy is attached and rolling indices over.
5. No plaintext secrets in the repo; all via env/secret store.

### WS0.1 — Authenticate & encrypt the Elastic stack — **M**
- **Now:** `xpack.security.enabled=false`; HTTP everywhere.
- **Target:** Security enabled; TLS on ES transport+HTTP; Kibana behind login; Logstash & agent use service accounts/API keys.
- **Files:** `scripts/setup/docker-compose.yml` (env `xpack.security.enabled=true`, certs volume, `ELASTICSEARCH_USERNAME/PASSWORD` for Kibana), `configs/logstash.conf` output block (uncomment + parameterize `user`/`password`/`ssl`), `configs/network/filebeat.yml` + `configs/endpoint/*.yml` (output creds/TLS).
- **Accept:** ES `_security` API live; anonymous `curl http://es:9200` → 401; Kibana requires login; Logstash ships with an API key, not `elastic` superuser.

### WS0.2 — Authenticate & harden the response webhook — **M**
- **Now:** `agent_app.py:157` `/alert` accepts any POST; `source_mac`/`source_ip` flow unvalidated into `sudo isolate.sh` (`agent_app.py:173,178`).
- **Target:** HMAC-signed requests (match the pattern the `hive-mind-broker` already uses); strict input validation (regex-validate MAC `^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$` and IPv4/IPv6 before any subprocess); reject on failure.
- **Files:** `scripts/setup/ai_agent/agent_app.py`, `scripts/setup/isolate.sh` (defensive validation at entry too), shared secret via env.
- **Accept:** unsigned/invalid-signature POST → 401 and no `isolate.sh` invocation (assert in a unit test); malformed MAC/IP → 400, never reaches subprocess.

### WS0.3 — Multi-tenancy foundation — **L**
- **Now:** no tenant concept anywhere.
- **Target:** every event carries `tenant.id`; storage, dashboards, alerting, and SOAR are tenant-scoped.
  - **Ingest:** stamp `tenant.id` at the edge — per-tenant Filebeat (`fields: {tenant.id: ...}`) or per-tenant Logstash pipeline/port; add a `tenant.id` guard in `configs/logstash.conf`.
  - **Storage:** route to per-tenant data streams/indices (`logs-suburbansoc.<dataset>-<tenant>`); replace the single `logstash-security-%{+YYYY.MM.dd}` output.
  - **Access:** Kibana **Spaces** per tenant + ES roles with index-pattern + (optionally) document-level security so a tenant role can't read another's data.
  - **Response:** `isolate.sh` / broker must resolve the **tenant's** router from `inventory.yaml`, never broadcast across tenants; `agent_app.py` must carry `tenant.id` through `/alert` → isolation → `soar-actions`.
  - **Notify:** per-tenant ntfy topic / Discord webhook (replace hardcoded `NTFY_TOPIC` `agent_app.py:17` and `ntfy.sh/subsoc-alerts-92x8m` `logstash.conf:254`).
- **Files:** `configs/logstash.conf`, `configs/network/filebeat.yml`, `configs/endpoint/*.yml`, `scripts/setup/ai_agent/agent_app.py`, `scripts/setup/isolate.sh`, `scripts/hive-mind-broker/inventory.yaml` (+ app), dashboard NDJSONs in `configs/server/`.
- **Accept:** seed two tenants; tenant-A role queries return zero tenant-B docs; a quarantine for tenant A touches only tenant A's router; alerts land on tenant A's topic.

### WS0.4 — Secrets management — **S**
- **Now:** `inventory.yaml` holds router creds; LLM key defaults to `your_api_key_here` (`agent_app.py:18`); ntfy topic hardcoded; ES password placeholder commented in `logstash.conf`.
- **Target:** all secrets via env / Docker secrets / a vault; repo carries only `.example` templates; secret-scanning in CI.
- **Files:** `scripts/hive-mind-broker/inventory.yaml` → `inventory.example.yaml` + `.gitignore`; `agent_app.py`; `docker-compose.yml` (`env_file`/`secrets`); add `gitleaks`/`trufflehog` to CI.
- **Accept:** `gitleaks detect` clean; no functional default secret in code.

### WS0.5 — Data lifecycle & retention — **M**
- **Now:** `data_stream => false`, daily indices, no ILM → unbounded growth, undefined evidence window.
- **Target:** convert to data streams; ILM hot/warm/delete with a defined retention (e.g. 90d hot, 1y cold, then delete — set per privacy stance in WS3.4); snapshot before delete.
- **Files:** new `configs/elasticsearch/ilm/*.json`, index templates, `configs/logstash.conf` output (`data_stream => true` or template-backed), `deploy_dashboards.sh` to install policies.
- **Accept:** ILM policy attached; rollover observed; retention documented and enforced.

### WS0.6 — Consolidate the duplicate Logstash config — **S**
- **Now:** `configs/logstash.conf` and `scripts/setup/configs/logstash/logstash.conf` are separate copies kept in sync by `deploy_dashboards.sh` — drift risk, security fixes can land in one only.
- **Target:** single source of truth (symlink or compose bind to the canonical path); remove the copy step.
- **Files:** `scripts/setup/docker-compose.yml`, `deploy_dashboards.sh`.
- **Accept:** one file; `docker compose config` resolves to it; no sync step.

---

# PHASE 1 — Detection plane to NIST CSF coverage + ATT&CK depth

**Objective:** Detections are real (not demo regex), driven by live intel and real data
sources, version-controlled, and mapped to a published ATT&CK coverage matrix. NIST CSF
Detect/Identify gaps closed with technical controls.

**Exit gate:**
1. Published ATT&CK coverage matrix (data source → technique → rule → test) checked into `docs/detections/`.
2. Sigma rules deploy via a real backend to Elastic detection rules — no business logic as inline `logstash.conf` regex.
3. A live threat-intel feed populates indicators; zero hardcoded IOCs remain.
4. Each confirmed data source (network + endpoint) has a heartbeat panel proving it flows.
5. The SOAR trigger fires on a real, set field (bug below fixed).

### WS1.1 — Fix the dead SOAR trigger & remove hardcoded detection — **S**
- **Now:** `logstash.conf:268` requires `[event][dataset]=="zeek.conn"` AND `[threat][indicator][domain]`, but nothing sets `threat.indicator.domain` → trigger likely never fires. Hardcoded IOC `185.150.115.115` (`logstash.conf:187`) and ntfy topic (`:254`).
- **Target:** drive SOAR off the intel-match pipeline (WS1.3) — e.g. Zeek `Intel::Notice` → ECS `threat.indicator.*`; delete hardcoded IP; topic from tenant config.
- **Accept:** simulated intel hit (a test IOC in the feed) triggers `/alert`; assert in `tests/anomaly_simulation/`.

### WS1.2 — Detection-as-code: real Sigma pipeline — **L**
- **Now:** 10 `rules/sigma/*.yml` at `status: experimental`, logic duplicated as inline regex in `logstash.conf:135-143,223-232`.
- **Target:** `sigma` CLI + `pySigma-backend-elasticsearch` converts rules → Elastic detection rules at deploy; rules promoted past `experimental` only after passing tests; logic lives in the rule, not the pipeline.
- **Files:** `rules/sigma/`, new `scripts/setup/deploy_detections.sh`, CI job; thin `logstash.conf` to enrichment/normalization only.
- **Accept:** `deploy_detections.sh` loads N rules into Elastic; each has a passing test (WS2.1); inline regex detections removed.

### WS1.3 — Live threat intelligence — **M**
- **Now:** `intel.dat` = 2 static entries; `configs/intel/config.zeek` loads it.
- **Target:** automated feed refresh (MISP, abuse.ch, or OTX) into Zeek Intel framework + an ES intel index; matches emit ECS `threat.indicator.*`; feed freshness monitored.
- **Files:** `configs/intel/` (+ refresh job/cron), `configs/zeek/local.zeek`, dashboard panel for feed age.
- **Accept:** feed auto-updates on schedule; a known-bad test indicator matches end-to-end; stale-feed alert if refresh fails.

### WS1.4 — Confirm & expand data sources (NIST Identify/Detect) — **M**
- **Now:** endpoint configs exist (`configs/endpoint/winlogbeat.yml`, `filebeat_endpoint.yml`) but architecture is network-first; endpoint detections only fire if telemetry actually arrives.
- **Target:** prove endpoint telemetry flows (Sysmon/Winlogbeat, Linux auth); add passive asset inventory from Zeek `conn`/`known_hosts`/`known_services` per tenant; consider Suricata for signature coverage alongside Zeek.
- **Files:** `configs/endpoint/*`, `configs/zeek/local.zeek`, new asset-inventory index + panel.
- **Accept:** Data Quality dashboard shows a live heartbeat per source per tenant; per-tenant asset list populated.

### WS1.5 — Publish the ATT&CK coverage matrix — **S**
- **Now:** ~13 techniques mapped informally (this roadmap §baseline).
- **Target:** machine-readable matrix (ATT&CK Navigator layer) of data source → technique → rule → test; gaps explicit; prioritized backlog for next tactics (Collection, Exfil, C2, Lateral Movement).
- **Files:** `docs/detections/attack-coverage.json` (+ rendered md).
- **Accept:** Navigator layer renders; every deployed rule appears; gaps annotated.

---

# PHASE 2 — SOC-CMM L3 operational functioning (technical)

**Objective:** The SOC runs as a *defined*, measured system: detections have a CI/CD
lifecycle, hunting is a repeatable capability, response/triage is tracked, the SOC measures
its own performance, and the platform is reliable. (People/process-paperwork excluded.)

**Exit gate:**
1. Detection CI is green and blocks merges that break a rule's test.
2. A versioned hunt library exists and runs on schedule.
3. MTTD/MTTR and detection-coverage are measured automatically against defined targets.
4. ES runs multi-node with automated, restore-tested snapshots; the SOC monitors itself.

### WS2.1 — Detection-engineering CI/CD — **L**
- **Now:** `tests/anomaly_simulation/` (3 scenarios + `verify_detections.py`) — a strong seed, run manually.
- **Target:** every detection has a test (unit on logic + replayable PCAP/log fixture asserting it fires and the right ATT&CK/NIST tags attach); CI runs on PR; promotion `experimental → test → stable` gated on green; regression suite for false positives.
- **Files:** `tests/` (expand), `.github/workflows/detections.yml`, `rules/sigma/`.
- **Accept:** PR that breaks a rule fails CI; coverage report lists rule→test mapping.

### WS2.2 — Threat-hunting capability — **M**
- **Now:** none.
- **Target:** versioned hypothesis-driven hunt queries (saved searches / scheduled), an ATT&CK-aligned hunt backlog, findings that feed new detections (closing the loop with WS2.1).
- **Files:** new `hunts/` dir (query + hypothesis + expected data source), scheduled-query install in deploy.
- **Accept:** ≥5 hunts versioned and scheduled; a hunt finding has been promoted to a detection at least once.

### WS2.3 — Alert triage & case tracking (technical) — **M**
- **Now:** alerts → ntfy/Discord (`agent_app.py`); no case state.
- **Target:** use Kibana **Cases** (or TheHive) so each alert has state/owner/timeline; SOAR actions and AI triage attach to the case; tenant-scoped.
- **Files:** dashboard/Kibana config, `agent_app.py` (create/update case via API), `soar-actions` linkage.
- **Accept:** an `/alert` produces a case with the AI summary + action recorded; closeable with disposition.

### WS2.4 — Self-measuring metrics & SLOs — **M**
- **Now:** `weekly_ciso_report.py` computes MTTD; no target/SLO comparison, no pipeline SLO.
- **Target:** automated MTTD/MTTR vs defined targets, detection-coverage %, false-positive rate, and pipeline-health SLOs (ingest lag, drop rate) on a dashboard with alerting on breach.
- **Files:** `configs/server/executive_dashboard.ndjson` + a new SLO panel set, `weekly_ciso_report.py`.
- **Accept:** dashboard shows each metric against its target; SLO breach raises an alert.

### WS2.5 — Reliability of the SOC stack — **L**
- **Now:** single-node ES (`docker-compose.yml`), no snapshots, no self-monitoring.
- **Target:** multi-node ES (or managed) for HA; automated snapshots to object storage with periodic **restore tests**; Stack Monitoring on the SOC's own components with alerting (the SOC must detect its own outages).
- **Files:** `docker-compose.yml` (→ multi-node or split prod compose), new `configs/elasticsearch/snapshot/*`, monitoring config.
- **Accept:** kill a node → cluster stays green/serving; a snapshot restored into a scratch cluster verifies; component-down raises an alert.

---

# PHASE 3 — SOC 2 Type II technical-control readiness

**Objective:** The technical controls behind the SOC 2 Trust Service Criteria are *enforced
and continuously evidenced*. (The written policies/auditor engagement an actual SOC 2 also
requires are business-track items, out of scope here.)

**Exit gate:**
1. Encryption in transit **and** at rest everywhere; verified.
2. RBAC mapped to least-privilege roles; no shared superuser in normal operation.
3. Tamper-evident audit trail of all admin + response actions, retained.
4. Change management enforced on detections/config (review + signed deploy).
5. SOC-stack vulnerability management running (image + dependency scanning + patch cadence).
6. Control evidence is auto-collected (continuous control monitoring).

### WS3.1 — Encryption in transit & at rest — **M**
- Builds on WS0.1 (TLS in transit). Add encryption at rest for ES data volume + snapshots; enforce TLS on every hop (Filebeat→Logstash→ES, agent, broker).
- **Accept:** a transit capture shows no plaintext telemetry; at-rest encryption confirmed on volume + snapshot repo.

### WS3.2 — RBAC & least privilege — **M**
- Define roles (tenant-viewer, analyst, detection-engineer, admin, service accounts) with minimum index/feature privileges; Logstash/Filebeat/agent use scoped API keys, not `elastic`.
- **Files:** ES role definitions (`configs/elasticsearch/roles/*`), Kibana space mappings.
- **Accept:** each service account can do only its job (negative tests pass); no human uses superuser routinely.

### WS3.3 — Tamper-evident audit trail — **M**
- Enable ES/Kibana audit logging; capture every quarantine/config/rule change with actor + tenant; ship audit logs to an append-only/immutable store with retention.
- **Files:** `docker-compose.yml` (audit settings), `agent_app.py` + `isolate.sh` (structured action logging beyond `soar-actions`), broker.
- **Accept:** every privileged action is queryable with who/what/when/tenant; audit store is write-once for the retention window.

### WS3.4 — Privacy & data-handling controls — **M**
- This product captures residents' traffic — Confidentiality/Privacy criteria are first-class. Implement: documented capture scope enforced in config, PII minimization where feasible, retention limits (ties to WS0.5), per-tenant data-deletion capability (right-to-erasure).
- **Files:** `configs/zeek/local.zeek` (capture scope), ILM (WS0.5), a tenant-purge runbook+script.
- **Accept:** a tenant-deletion request provably removes that tenant's data within the retention/SLA window; capture scope matches the documented stance.

### WS3.5 — Change management on detections & config — **S**
- **Now:** delegated commits via git (README) — good foundation.
- **Target:** enforced PR review + CI gates (WS2.1) on `rules/`, `configs/`, response code; signed/pinned deploys; deployment changelog.
- **Files:** branch protection, `.github/workflows/`, deploy scripts emit a changelog.
- **Accept:** no detection/config reaches prod without a reviewed, CI-passed, recorded change.

### WS3.6 — Vulnerability management of the SOC stack — **M**
- Pin + scan container images (Trivy/Grype) and Python deps (`requirements.txt` in `ai_agent`, `hive-mind-broker`); defined patch cadence; CI fails on critical CVEs.
- **Files:** `.github/workflows/`, Dockerfiles, `requirements.txt`.
- **Accept:** CI blocks a known-critical CVE; patch cadence documented and met.

### WS3.7 — Continuous control monitoring (evidence automation) — **M**
- Automate collection of control evidence (auth enabled, TLS on, ILM attached, snapshots succeeding, audit logging on, scans passing) into a control dashboard / periodic report.
- **Accept:** a single view shows each technical control's live status; a control regressing (e.g. auth disabled) raises an alert.

---

## 6. Traceability — workstream → framework

| WS | NIST CSF 2.0 | SOC-CMM domain | SOC 2 TSC | ATT&CK |
|---|---|---|---|---|
| 0.1 Stack auth/TLS | Protect (PR.AA, PR.DS) | Technology | Security, Confidentiality | — |
| 0.2 Webhook auth | Protect, Respond | Technology/Process | Security | — |
| 0.3 Multi-tenancy | Protect | Technology/Services | Confidentiality, Privacy | — |
| 0.4 Secrets | Protect (PR.AA) | Technology | Security | — |
| 0.5 Retention/ILM | Recover, Identify | Technology | Availability, Privacy | — |
| 0.6 Config consolidation | Govern (technical) | Process | Security (change integrity) | — |
| 1.1 SOAR-trigger fix | Detect, Respond | Services | — | enables intel-driven |
| 1.2 Sigma-as-code | Detect | Process/Services | — | breadth+depth |
| 1.3 Live intel | Identify, Detect | Services | — | indicator coverage |
| 1.4 Data sources | Identify, Detect | Technology/Services | — | data-source coverage |
| 1.5 ATT&CK matrix | Detect | Services | — | the matrix |
| 2.1 Detection CI/CD | Detect | Process | Security (change mgmt) | test coverage |
| 2.2 Threat hunting | Detect | Services | — | proactive coverage |
| 2.3 Case tracking | Respond | Process | Security | — |
| 2.4 Metrics/SLO | Detect, Respond | Process/Business* | Availability | — |
| 2.5 Reliability/HA | Recover | Technology | Availability | — |
| 3.1 Encryption | Protect | Technology | Security, Confidentiality | — |
| 3.2 RBAC | Protect | Technology | Security | — |
| 3.3 Audit trail | Detect, Govern | Process | Security | — |
| 3.4 Privacy controls | Protect, Govern | Services | Confidentiality, Privacy | — |
| 3.5 Change mgmt | Govern | Process | Security | — |
| 3.6 Vuln mgmt | Identify, Protect | Technology | Security | — |
| 3.7 Control monitoring | Govern, Detect | Process | all (evidence) | — |

\* metric *instrumentation* is in scope (technical); SLA *negotiation* is not.

## 7. Sequencing & dependencies

```
Phase 0 (ship-blockers) ─┬─> Phase 1 (detection plane) ─┬─> Phase 2 (operational) ─> Phase 3 (audit-ready)
                         │                               │
   0.1 auth ─> 0.2 webhook auth                          2.1 CI gates 1.2/1.1
   0.1 ─> 0.3 tenancy ─> notify/SOAR scoping             3.x mostly builds on 0.x + 2.x
   0.5 retention ─> 3.4 privacy
   0.6 config consolidation first (cheap, de-risks all later config edits)
```

**Recommended order to start:** WS0.6 (cheap, removes drift risk) → WS0.1 → WS0.2 →
WS0.4 → WS0.3 → WS0.5. Do **not** begin Phase 1 detection expansion before WS0.1/0.2/0.3,
or you scale an open, single-tenant system.

## 8. Definition of done (program)

- SOC-CMM technical-domain rating at **Defined (L3)** for Technology + technical Process/Services.
- NIST CSF Detect/Respond **strong**, Identify/Protect/Recover **covered** by enforced controls.
- ATT&CK coverage matrix published, every rule tested in CI.
- All Phase-0/1/2/3 exit gates passed and continuously evidenced (WS3.7).
```

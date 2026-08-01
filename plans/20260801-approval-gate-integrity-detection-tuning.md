# Detection & Platform Improvement Plan — Suburban-SOC

## Context

A detection-capability evaluation covering signature vs. behavioral detection, Sigma rule
quality, alert tuning, and platform features was reviewed and fact-checked against the repo
before planning. The evaluation is directionally sound but roughly a third of its items are
already implemented, factually wrong, or re-propose a design that was already evaluated and
approved. Planning from it as written would spend real effort re-doing finished work.

More importantly, verifying its weakest-looking item (SOAR action deduplication) surfaced
something the evaluation understated: a merged commit silently removed the human-approval
gate's double-execution protection. That is a live security regression on `main`, and it
outranks everything else in the evaluation.

Intended outcome: close the regression first, resolve the uncommitted working tree, then
execute only the evaluation items that survive fact-checking.

---

## Finding that reorders the plan: approval-gate regression

`/approve` triggers network isolation of a host. Commit `2bb3d8f` ("refactor(agent): phase H
agent orchestration and compliance core", 2026-07-20, **merged to main**) moved logic from
`agent_app.py` into the new `agent.py` Agent class and dropped the atomic approval claim that
issue #172 had added.

Evidence:
- `_queue_lock` occurrences in `agent_app.py` went **6 → 0** across `2bb3d8f`.
- Pre-refactor `/approve` did: `with _queue_lock:` → read queue → subtract ids in
  `_RESOLVED_STATUSES` → append a `"claimed"` marker → *then* execute isolation.
- Current `/approve` (`scripts/setup/ai_agent/agent_app.py:47-62`) has no lock and no claim.
- Current `Agent.execute_approved` (`scripts/setup/ai_agent/agent.py:928-963`) checks
  `is_awaiting_approval()` then calls `_execute_isolation()` — a TOCTOU window. Two concurrent
  `/approve` calls both pass the check before either writes the EXECUTED checkpoint, so
  isolation dispatches twice.
- `_queue_lock`, `_RESOLVED_STATUSES`, `_append_pending_action_locked` still exist in
  `agent.py:121,150,593` but nothing uses them for approval dedup — dead code.

The **uncommitted** working tree makes this materially worse:
- `checkpoints.py` removes both `res.raise_for_status()` calls → ES checkpoint failures are
  now silent (a direct regression of #165 and #184).
- `checkpoints.py:59-69` adds a fallback where `is_awaiting_approval` returns `True` for any
  `approval_queue.jsonl` row with `status == "pending"`. Nothing ever writes a non-pending
  status to that append-only file (`agent.py:1036`), so that row authorizes replay **forever,
  surviving restarts**. Combined with the silent ES failure, isolation becomes indefinitely
  replayable.

Both paths still require a valid HMAC signature, so this is not unauthenticated. Per standing
guidance, this gets fixed directly — no public GitHub issue with exploit detail — while unpatched.

---

## Evaluation triage

| # | Item | Verdict | Action |
|---|---|---|---|
| 3.4 | SOAR action dedup / replay | **Regressed on main** | Phase 0 |
| 2.1 | Sigma false-positive filters | Partly true, **wrong examples** | Phase 2, retargeted |
| 3.1 | Discovery commands → threshold rules | True | Phase 2 |
| 3.3 | Zeek PortScan threshold tuning | True, evidence-backed | Phase 2 |
| 3.2 | Per-host/technique suppression window | Partly (5-min key exists) | Phase 3 |
| 2.3 | Live-fire detection testing | Partly (CI does compile 35/35) | Phase 3 |
| 4.4a | Webhook replay protection | **Already done** | Drop |
| 4.4b | Non-root containers | **Already done** | Drop |
| 4.4c | Logstash `:5514` mTLS | Overstated; **sharper gap found** | Phase 3, retargeted |
| 4.3 | STIX/TAXII intel feeds | Partly (cron + watcher exist) | Phase 4 |
| 4.2 | Suricata integration | **Already evaluated & approved** | Backlog, per existing doc |
| 2.2 | Sigma field-name consistency | **False** | Drop |
| 4.5 | Elasticsearch multi-node HA | Aspirational on one host | Drop, stays documented |
| 4.1 | TLS decryption proxy (mitmproxy) | Scope/privacy cost too high | **Dropped** (decided) |

Detail on the items dropped or retargeted:

- **2.2 field consistency is false *as framed*, with one caveat.** Zero occurrences of
  `process.command_line` or `process.args` in `rules/sigma/` — rules uniformly use native Sigma
  taxonomy (`Image|endswith`, `CommandLine|contains`). `configs/detections/suburban-soc-ecs.yml:27,29`
  already maps these and `.github/workflows/detections.yml:48` enforces it in CI, so there is no
  *inconsistency between rules* to fix. But the evaluation was gesturing at something real:
  whether `CommandLine → process.args` gives correct `contains` semantics against an array field
  is unverified, and Phase 2's top-ranked FP depends entirely on the answer. Resolved there, not
  by a repo-wide field rename.
- **2.1 picked the wrong rules.** `proc_creation_win_mshta_remote.yml:13-19` is *not* "any
  command containing http" — two keys in one selection block are ANDed, so it requires
  `mshta.exe` and one of `http`/`javascript`/`vbscript`. FP risk is low. The genuine offenders
  are listed in Phase 2.
- **4.4a/4.4b are done.** Both services have timestamp (`HMAC_REPLAY_WINDOW`, 300s) and nonce
  replay protection (`agent.py:188-197,225-229`; broker `app.py:148-200`), and both Dockerfiles
  set a non-root `USER` (`ai_agent/Dockerfile:32-33`, `hive-mind-broker/Dockerfile:17-18`). One
  residual carried forward, not dropped: the nonce cache `_seen_sigs` is in-process memory only,
  which is why `ai_agent/Dockerfile:38-50` pins `--workers 1`. Phase 0 moves the approval claim
  to ES partly for scale-out safety — but this nonce cache still blocks scale-out, so Phase 0
  must not be read as making multi-worker deployment safe. Shared nonce store is a prerequisite.
- **4.2 Suricata was already decided.** `docs/detections/suricata-evaluation.md:3` reads
  "Decision: Adopt as a follow-up (not in M8)" with the integration path already specified
  (EVE JSON → Filebeat → Logstash :5044). Re-evaluating it would discard that work.
- **4.1 TLS decryption proxy — dropped.** It would require distributing a CA to every endpoint,
  would break cert-pinned applications, and would decrypt household traffic on a shared home
  mesh. Suricata recovers much of the payload-inspection value at a fraction of that cost, and
  is already approved. Not revisited unless the threat model changes.

---

## Phase 0 — Restore approval-gate integrity (blocking)

Nothing else ships until this does. Design validated against the Agent-class architecture
rather than reverting to the old shape.

**Files:** `scripts/setup/ai_agent/checkpoints.py`, `agent.py`, `agent_app.py`

1. **Discard the uncommitted `checkpoints.py` diff entirely** — restores both
   `raise_for_status()` calls and removes the JSONL fallback. Also drops the
   `ES_VERIFY = ES_CA if os.path.exists(ES_CA) else True` hunk, which silently downgrades to
   system trust when the CA isn't mounted, contradicting `agent.py:110-114`.
2. **Add `claim_approval(tenant_id, alert_id, approver) -> bool` to `checkpoints.py`**, using
   ES atomic create-if-absent: `PUT /agent-checkpoints-{tenant}/_create/{alert_id}.claim`.
   201 = won, 409 = lost, connection error = raise. Chosen over `threading.Lock` because it is
   durable (closes the crash window between claim and EXECUTED write) and correct across
   processes — the lock is only sufficient because of the `--workers 1` pin at
   `ai_agent/Dockerfile:38-50`, a constraint the first scale-out would silently break. Do not
   add both; one authority.
3. **Call it from `Agent.execute_approved`** (`agent.py:928`), immediately after the
   `is_awaiting_approval` pre-check — not from `agent_app.py`. The at-most-once invariant must
   hold for every caller, including the broker path (`agent.py:257`) and direct-drive tests.
   Lost claim → 409. Store unreachable → 503, fail closed: with ES down you cannot distinguish
   "pending" from "already isolated", so the failure mode of availability here is duplicate
   containment of a host.
4. **Guard the post-execution `self.check(ctx, phase)`** (`agent.py:960`) in try/except: log
   ERROR and write the #184 health marker, but still return the execution result. The claim
   doc — not the EXECUTED checkpoint — is what blocks replay, so a 500 here would only mislead
   the approver about work that already happened.
5. **Handle the `/alert` path asymmetrically.** `write_checkpoint` is also called at
   `agent.py:880` in `run()` (the Phase 1 `PERCEIVING` checkpoint). HEAD already has
   `raise_for_status()` there, so with ES down `/alert` 500s and the alert is dropped — a
   detection gap. That is almost certainly why the working tree removed it. Fail-closed is
   right for *execution* (duplicate containment is worse than no containment) but wrong for
   *intake* (a dropped alert is a missed detection). So: keep `raise_for_status` in
   `write_checkpoint`, but at the `run()` call site catch it, emit the #184 health marker, and
   continue to PENDING_APPROVAL rather than 500. Do not apply that leniency to `claim_approval`.
6. **Restore the queue markers** (`"claimed"`, then `"approved"`/`"denied"`) via
   `_append_pending_action`. These are now an audit/ops mirror, not the gate. This re-validates
   `tests/ai_agent/test_compact_agent_approval_queue.py:83-90` and restores #176's archival —
   entries currently stay `"pending"` forever and are never compacted.
7. **Filter `/pending`** (`agent_app.py:41`) through `_RESOLVED_STATUSES`; it currently returns
   raw rows, so executed actions display as pending indefinitely.

**Tests** (`tests/ai_agent/test_alert_auth.py`, plus new `test_checkpoints_claim.py`):
- Update the existing concurrency test at `test_alert_auth.py:252` — keep the two real threads
  and 50ms slow dispatch, give the fake ES store honest create-if-absent semantics, change the
  loser's expected status `[200, 404]` → `[200, 409]`, assert `dispatch.assert_called_once()`.
- `test_claim_blocks_replay_after_checkpoint_write_failure` — EXECUTED write raises; first
  approve still 200, second freshly-signed approve 409, no second dispatch.
- `test_es_unavailable_fails_closed` — claim raises ConnectionError → 503, dispatch never called.
- `test_pending_jsonl_row_alone_does_not_authorize` — guards against the fallback returning.
- `test_approve_writes_claimed_then_resolved_queue_rows` — ties the compaction contract to reality.

**Also fix while here** (same files, currently uncommitted and clearly unintended):
`agent.py:962` hardcodes `or "case-abc123"`, the literal test fixture from
`test_alert_auth.py:85`; `_cfg_fn` probes `'scripts.setup.ai_agent.agentapp'` (missing
underscore) while `_cfg` correctly probes `agent_app`; duplicate `import sys` at
`agent.py:21,23`; two doc comments corrupted by find/replace into
`the ES-backed _cfg_fn("write_audit", write_audit)() trail below` (`agent.py:65,870`).

**Delegation:** `security-auditor` + `code-reviewer` in parallel on the diff, then
`tester-debugger` for the concurrency test.

---

## Phase 1 — Resolve the rest of the working tree

Independent of Phase 0; separate commit.

- **`inventory.py`** (+4) — unrelated, self-contained path-resolution fix: falls back to
  `os.path.dirname(__file__)` when `inventory.yaml` isn't in cwd. Keep as-is.
- **`README.md`** (+4) — adds a Compliance & Standards Mapping link to `docs/COMPLIANCE_MATRIX.md`
  (which exists). Keep; strip the stray blank lines preceding it (~line 359).
- **SOP-022 / SOP-147** — reformatted into the playbook template but, unlike the earlier
  balanced refactors, these dropped operational content with no new home: SOP-022 222→62 lines,
  SOP-147 317→61. Casualties include the 11-row prerequisite table, the troubleshooting matrix,
  and the field-verified Path B mesh recipe that was the entire payload of commits `a783085`
  and `4323d04`. Keep the playbook restructure, relocate the operational content into companion
  runbooks rather than deleting it. Recover the deleted content from
  `git show HEAD:docs/SOP-022-anomaly-validation.md` and
  `HEAD:docs/SOP-147-evidence-validation-runbook.md` — it is not lost, only uncommitted-away.
  New companion docs carry the prerequisite tables, numbered steps, troubleshooting matrices,
  evidence checklists, and the Path B mesh recipe; each SOP links to its companion. Then repair
  the four dangling references: `tests/anomaly_simulation/preflight.sh:104` cites "Step 5 of
  SOP-022"; `tests/anomaly_simulation/section_a_evidence.sh:3` and `evidence/README.md` rows
  17-25 cite SOP-147 Sections A–E; `docs/presentation_slides.md:91` claims SOP-022 still
  contains the detection-mapping table, troubleshooting matrix, and evidence-capture checklist.

---

## Phase 2 — Detection tuning (highest-value evaluation items)

> Sequencing note: the alert-volume metric in Phase 3 must land before this phase, so tuning
> has a before/after signal. Numbered 2 because it is the higher-value work, not because it
> runs first.

**Sigma false-positive filters** — 33 of 35 rules lack a `filter` block, but most are
adequately scoped. Real offenders, ranked:
1. `proc_creation_win_powershell_encoded.yml:6-9` — verify first; this may be inverted. The
   reasoning that `' -enc'` is a prefix of `-Encoding` (so `Out-File -Encoding utf8` fires) only
   holds if `CommandLine` matches against the full command string. But
   `configs/detections/suburban-soc-ecs.yml:29` maps `CommandLine → process.args`, and its own
   header (:3-4) stresses this stack deliberately uses `process.args`, not
   `process.command_line` — CI hard-fails on the latter (`detections.yml:48`). If `process.args`
   is a tokenized array, no element begins with a space, so `' -enc'` and `' -ec '` match
   nothing and the rule is dead — a false negative, not a false positive. If Logstash instead
   packs the whole command line into `process.args`, the FP reasoning stands. Query live data
   for the actual shape of `process.args` before writing either fix; the two fixes are opposite.
2. `system_win_service_installed.yml:3` — bare `EventID: 7045`, `level: medium`, no name or
   ImagePath filter; every driver and software install alerts.
3. `posh_ps_obfuscated_scriptblock.yml:5-15` — `level: high` on ordinary admin scriptblocks.
4. `net_zeek_executable_download.yml:3-13` — no allowlist for update/CDN hosts.
5. `proc_creation_win_certutil_decode.yml:3-4` — single bare `'decode'` token.

**Discovery commands → threshold rules** — confirmed single-event with no timeframe:
`proc_creation_win_user_discovery.yml` (whoami `/all`, medium),
`proc_creation_win_nltest_discovery.yml` (medium),
`proc_creation_win_domain_group_discovery.yml` (low). Follow the existing pattern in
`rules/elastic/threshold/auth-win-bruteforce-failed-logons.ndjson` (`"type": "threshold"`,
`"interval": "5m"`, `"from": "now-6m"` — the overlap is deliberate); use the cardinality
variant from `auth-win-explicit-cred-account-sweep.ndjson` where a host sweeps many targets.

**Add alongside — do not convert.** Converting single-event rules to threshold-only means one
deliberate `whoami /all` by an attacker stops alerting entirely, trading a false-positive
problem for a coverage hole. Instead demote the existing single-event rules to `level: low`
(kept for hunting and correlation) and add threshold companions at `medium`/`high`. Net
alert-noise reduction with no loss of visibility.

**Zeek PortScan threshold** — `scripts/setup/configs/zeek/scan-detection.zeek:28,31,36`
currently `port_scan_threshold = 20` / `5 min`. `evidence/README.md:23` records the real mesh
router `10.18.81.1` legitimately tripping it with 60 distinct ports — 3x the threshold, so this
fires on normal mesh behavior. Fix by excluding the router's mesh role, not by raising the
threshold: raising it past 60 to accommodate one known-benign host would blind the sensor to
every genuine 20-60 port scan on the segment. Scope the exclusion to that host's mesh interface
so scans *from* it are still detected on other paths.

---

## Phase 3 — Measurement and integrity

- **Alert-volume metric first.** `slo_metrics.py:174-183` has `metric_false_positive_pct()`,
  but it measures analyst-dispositioned cases — Zeek notices and discovery hits that never
  become cases are invisible. Phase 2's tuning is unmeasurable without a raw-signal-count
  metric. Add one to `TARGETS` (`slo_metrics.py:50-58`) before landing Phase 2, so there is a
  before/after.
- **Suppression window** — extend `generate_dedup_key` (`checkpoints.py:20-23`), today a 5-min
  tumbling window over `tenant|ip|mac|severity`, to cover host+technique over a sliding 15-min
  window as the evaluation asks.
- **Logstash mTLS — retargeted.** `:5514` is plaintext but is not host-published (compose
  publishes only `5044:5044`), so it is reachable only on the internal bridge, and
  `logstash.conf:16-22` documents that tradeoff. The sharper finding: `logstash.conf:6-13` sets
  `ssl_certificate_authorities` but never sets `ssl_client_authentication => required` (plugin
  default is `none`), while `configs/network/filebeat.yml:53-58` asserts the server requires
  client auth. Verify whether mTLS is actually enforced; if not, enforce it.
- **Live-fire detection tests** — CI is not purely `eval()`-based as the evaluation implies:
  `.github/workflows/detections.yml:40-45` already runs real `sigma convert -t lucene` and
  asserts 35/35 compile, and the `eval()` at `tests/detections/sigma_eval.py:82` is guarded by
  a token allowlist with empty `__builtins__`. The genuine gap, admitted in that module's own
  docstring at :9-13, is that no rule is fired against a live index. Add end-to-end tests
  against `.alerts-security.alerts-*`.

---

## Phase 4 — Threat intel (lowest priority)

`configs/intel/refresh_intel.sh` is not manual-only: `configs/intel/intel-refresh.cron:14` runs
it every 6 hours and `rules/elastic_watcher/intel_feed_stale.json` alerts on staleness. Real
residual gaps: a single keyless feed (Feodo Tracker), manual cron installation, and no
STIX/TAXII. Scope to adding feeds and automating install before considering MISP/OpenCTI.

---

## What this plan could degrade (accepted tradeoffs)

1. **Phase 0 reduces availability on purpose.** `/approve` will 503 when ES is unreachable,
   where the working tree currently succeeds via the JSONL fallback. Accepted: with ES down you
   cannot distinguish "pending" from "already isolated," so the alternative failure mode is
   duplicate containment of a host. Intake is handled asymmetrically (Phase 0 step 5) so alerts
   are not dropped for the same reason.
2. **Sigma exclusion filters create attacker-usable blind spots.** Any filter keyed on a path
   string or process name is something an attacker can simply satisfy. Filters must key on
   hard-to-forge attributes (code signature, service SID, parent lineage).
3. **Deprioritizing Logstash `:5514` softens a real integrity risk.** It is unauthenticated log
   injection, safe only while nothing hostile is on `soc-mesh-net`. Reassess if any new service
   joins that bridge.
4. **Dropping ES HA accepts single-host fate sharing.** Correct for one WSL2 box, but it means
   there is no answer to "the host died" beyond restore-from-snapshot.
5. **Phase 2 must land after Phase 3's alert-volume metric** — see sequencing note above.

## Verification

- **Phase 0:** `pytest tests/ai_agent/ -v` (all green, including the concurrency test); then
  live-verify against the running stack — issue two genuinely concurrent signed `/approve`
  calls for one alert_id and confirm exactly one broker dispatch and a single ES claim doc;
  confirm a replayed approve returns 409; confirm ES-down returns 503 with no dispatch.
- **Phase 2:** `pytest tests/detections/` plus `sigma convert` compiling all rules; replay
  known-good and known-FP fixtures through `tests/detections/fixtures.json`; confirm the new
  threshold rules import into Kibana via `deploy_detections.sh`.
- **Phase 3:** compare the new alert-volume metric across a window before and after tuning.
- **Standing constraint:** `gh pr checks` on the real PR before any "done" claim — local
  pytest/ruff/mypy is not a substitute.

## GitHub tracking

Milestone, user story, and per-phase issues filed 2026-08-01. Per the repo's multi-phase
execution gating rule, each phase executes and is reviewed individually — no unattended
multi-phase runs.

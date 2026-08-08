# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Current milestone: [M14 — SOAR Approval-Plane Operability & Hardening](https://github.com/voltron-1/Suburban_SOC/milestone/18).**
Started 2026-08-08, immediately after M13 closed (35 → 105 Sigma rules, all 7
user stories merged). M12/M13 sections below are retained as history, not
active work — see the M14 entry further down (search "M14 — SOAR
Approval-Plane") for the live status of each of its issues. Multi-phase
execution gating applies: each issue is its own gated unit, no unattended
multi-issue runs.

- [~] **#275 (P0, bug) — IN REVIEW** — `slo_metrics_reader` never granted
  `soc-agent-health-*`. Live-verified against a real, security-enabled,
  native Elasticsearch (not just reading the role file) that the actual
  failure mode is a SILENT false-healthy 0, not the loud exit-3 the issue
  assumed. [PR #307](https://github.com/voltron-1/Suburban_SOC/pull/307) —
  15/15 CI green, **awaiting merge sign-off**. Filed 4 follow-ups from
  security-auditor review, out of scope for this fix: #302 (unrelated
  pre-existing test-isolation bug, found incidentally), #303 (P0 —
  docker-compose.yml's `provision` service command breaks under
  shell-word-splitting on any apostrophe, blocking ALL role/user
  provisioning via `docker compose up`, likely the real cause behind
  README's pre-existing "docker compose is broken" note), #304 (generalize
  the new role-sync test to all 6 role files; `logstash_writer`'s inline
  copy has already drifted), #305 (add a live `_has_privileges` self-check),
  #306 (remaining cleartext-password lines + `logstash_writer`'s over-broad
  `manage` privilege on `soc-agent-health-*`).
- [ ] **#277 (P0, security)** — next up once #275 is merged. Broker's
  `/webhook/dispatch` response is unauthenticated; an on-path attacker can
  forge success or force a permanent stuck claim.
- [ ] **#276, #278 (P1)** — no operator tool for a stuck claim; an `unknown`
  isolation outcome has no reconciliation path. Related, likely one PR.
- [ ] **#286 (P2)** — MAC-based device quarantine is non-functional (two
  stacked pipeline breaks: no `orig_l2_addr`→`source.mac` rename in the
  reachable Logstash branch, and no conn.log↔intel.log join even after
  that).
- [ ] **#256, #257 (P2)** — checkpoint TTL retention; hardening follow-ups
  from #245's review.
- [ ] **#259 (tech-debt)** — `slo_metrics.py`'s `.env` parser breaks on
  inline comments.

Next unstarted item once #275 merges: **#277**.

---

<details>
<summary>M12/M13 history (both complete) — click to expand</summary>

**Milestone: [M12 - Approval Gate Integrity & Detection Engineering Tuning](https://github.com/voltron-1/Suburban_SOC/milestone/16).**
Filed 2026-08-01 after fact-checking a detection-capability evaluation against
the repo. Verifying the evaluation's weakest item (SOAR action dedup)
surfaced a live regression: PR-less commit `2bb3d8f` ("phase H agent
orchestration and compliance core", merged 2026-07-20) silently dropped the
atomic approval claim #172 had added to `/approve`, reopening a
double-execution race on network isolation. That regression, plus an
uncommitted working tree making it worse, blocks everything else. Full plan:
[`plans/20260801-approval-gate-integrity-detection-tuning.md`](plans/20260801-approval-gate-integrity-detection-tuning.md).
Umbrella user story: [#213](https://github.com/voltron-1/Suburban_SOC/issues/213).

Multi-phase execution gating applies: each phase below executes and is
reviewed individually, no unattended multi-phase runs.

- [x] **Phase 0 (CRITICAL, blocking) — #214 — COMPLETE** — restore the atomic
  approval-gate claim via ES create-if-absent (`claim_approval()` in
  `checkpoints.py`). [PR #248](https://github.com/voltron-1/Suburban_SOC/pull/248)
  merged 2026-08-02 to `main`; issue closed. Scope grew substantially during
  implementation (see 2026-08-01 session log below): a relative-import bug
  had broken test collection for the entire `ai_agent` suite since
  `2bb3d8f`; ~45 tests were failing against a silently-changed API contract
  (status vocabulary, `/pending`'s response key, `/approve`'s body key) that
  diverged from both the pre-existing tests and the broker's own
  independent suite — all fixed, restoring the evidence-verified contract
  rather than the drifted one. `security-auditor` + `code-reviewer` ran in
  parallel on the diff; all Should-Fix items addressed. Three follow-up
  issues filed from that review:
  [#245](https://github.com/voltron-1/Suburban_SOC/issues/245) (blocks
  #214 from actually functioning — the agent's ES role likely doesn't
  grant `agent-checkpoints-*` access at all, and the index template is a
  data stream while the code uses APIs data streams reject; needs
  live-stack verification this session's environment couldn't perform, no
  Docker available), [#246](https://github.com/voltron-1/Suburban_SOC/issues/246)
  (`/approve` shares its HMAC secret with `/alert`, which Logstash holds —
  architectural, needs a credential split), and
  [#247](https://github.com/voltron-1/Suburban_SOC/issues/247) (a claim is
  never released on execution failure, permanently stranding the alert;
  partially mitigated in #248, full fix deferred). CI on the PR: 14/15
  checks pass, including `SOAR auth / exclusion / approval / tenant-scoping`
  and `detections` — the first time either has run against this code since
  `2bb3d8f`, since both trigger only on `pull_request` and that commit went
  straight to `main`. The one failing check (`ruff (python)`) is a
  pre-existing, repo-wide, unrelated CI issue (no version pin on
  `pip install ruff`, so CI always installs latest and has drifted from
  what's locally reproducible) — it fails on every PR in the repo
  regardless of content, not something introduced by or fixable within this
  diff. **Fixed 2026-08-02 via [PR #255](https://github.com/voltron-1/Suburban_SOC/pull/255)**
  (pinned to 0.15.15) — see LAST SESSION below for how this and #248/#253's
  merges depended on each other.
- [x] **Phase 1 — #215 — COMPLETE** — relocated SOP-022/SOP-147 operational
  content (dropped by an earlier uncommitted playbook-template refactor)
  into two new companion runbooks, repaired 4 dangling references, landed
  the `inventory.py` fallback fix + `test_inventory.py` + README
  compliance-link addition. [PR #262](https://github.com/voltron-1/Suburban_SOC/pull/262)
  merged 2026-08-03. security-auditor caught a silently-reworded (not
  verbatim-relocated) passage and 2 dropped links during review — fixed
  before merge.
- [x] **Phase 3 (metric) — #216 — COMPLETE** — added `raw_alert_volume` SLO
  metric (Zeek notices + Sigma/Elastic rule hits, no target — pure
  visibility). [PR #260](https://github.com/voltron-1/Suburban_SOC/pull/260)
  merged 2026-08-03.
- [x] **Phase 2 — #217 — COMPLETE** — Sigma false-positive/false-negative
  tuning across 6 rules (`posh_ps_obfuscated_scriptblock`,
  `proc_creation_win_powershell_encoded`, `system_win_service_installed`,
  `net_zeek_executable_download`, `proc_creation_win_certutil_decode`, +3
  discovery rules demoted to threshold companions).
  [PR #264](https://github.com/voltron-1/Suburban_SOC/pull/264) merged
  2026-08-03. Two independent security-auditor rounds — the second
  specifically re-verifying the first round's fixes — each found real
  gaps (missed pipeline-form `iwr | iex` cradle, unanchored `irm `
  substring FP, `-Encoding:` colon-syntax bypass, `/enc` switch-prefix
  bypass, `ImagePath` case-sensitivity); all fixed and re-verified via 10
  combinatorial `sigma_eval.py` cases before merge. Follow-up filed:
  [#263](https://github.com/voltron-1/Suburban_SOC/issues/263)
  (`ignore_above:8191` lets both PowerShell rules be bypassed by payload
  length — pipeline-wide, pre-existing, needs a live-cluster reindex plan,
  out of scope for a rule-tuning issue).
- [!] **Phase 2 — #218 — CLOSED, invalid** — the "60-port legitimate trip"
  cited from `evidence/README.md:23` was a mis-transcription: that event is
  the deliberately-run A.1 port-scan simulation
  (`docs/SOP-147-evidence-validation-runbook.md:127-133`), not organic
  router chatter. Implementing the exclusion as scoped would have suppressed
  the repo's only verified real-telemetry T1046 detection — caught by a
  security-auditor pass during implementation. Branch deleted, no code
  change to `scan-detection.zeek`. Docs corrected in commit `e6e309d`.
- [x] **Phase 3 — #219 — COMPLETE** — enforced `ssl_client_authentication
  => "required"` on the Logstash Beats input (:5044); `configs/network/filebeat.yml`
  had asserted this for a while but nothing server-side actually enforced
  it. [PR #266](https://github.com/voltron-1/Suburban_SOC/pull/266) merged
  2026-08-04. Live-verified against the running stack, not just config
  inspection: recreated the `logstash` container, confirmed a client-cert
  connection succeeds and a certless one gets rejected
  (`SSLHandshakeException: certificate_required`, confirmed via Logstash's
  own log — the TLS client's own handshake summary turned out not to be a
  reliable signal here under TLS 1.3). Also fixed 2 pre-existing bugs found
  while live-verifying: `verify_encryption.sh`'s Beats check only proved
  TLS worked, not that client auth was enforced, and its default
  network/volume names were stale against the compose project's actual
  name. Follow-up filed: [#265](https://github.com/voltron-1/Suburban_SOC/issues/265)
  (Winlogbeat/endpoint-Filebeat have no client cert minted — harmless
  today since no live endpoint is deployed yet, but will break onboarding
  until fixed).
- [x] **Phase 3 — #220 — COMPLETE** — bounded sliding 15-min host+technique
  suppression window (`should_suppress_technique` in checkpoints.py),
  kept deliberately separate from `generate_dedup_key`'s 5-min tumbling
  window (#214's load-bearing alert_id, required to stay unaffected).
  [PR #268](https://github.com/voltron-1/Suburban_SOC/pull/268) merged
  2026-08-04. Two review rounds on the first version found it was
  non-functional end to end (strict ES mapping would have rejected every
  suppression write, silently, forever) and had a real design flaw
  (unbounded window refresh = permanent suppression during a sustained
  attack — fixed with a 1h duration cap + severity-escalation bypass).
  Also caught mid-review: the `technique` passthrough was first wired into
  `rules/elastic_watcher/soar_quarantine_alert.json`, which turned out to
  be dead code (superseded by `configs/logstash.conf`'s ingest-time HTTP
  output per that file's own comment — missed during investigation);
  rewired into the real live path. Follow-up filed:
  [#267](https://github.com/voltron-1/Suburban_SOC/issues/267) (the
  Watcher file has no HMAC auth and may not even install — unrelated
  pre-existing gaps, found while fixing the above).
- [x] **Phase 3 — #221 — COMPLETE** — `tests/detections/test_live_fire.py`
  runs the real `sigma convert` CLI, translates fixtures through the real
  pipeline mapping table, indexes them into a throwaway index carrying the
  real production index template, and fires the compiled query against a
  real Elasticsearch — one rule per category (process_creation, network,
  threshold) per the issue's acceptance criteria.
  [PR #269](https://github.com/voltron-1/Suburban_SOC/pull/269) merged
  2026-08-04. New, separate `live-fire` CI job (ephemeral, unauthenticated
  ES service container) — deliberately not folded into the required
  `detections` job, so ES infra flakiness can never block an unrelated PR.
  Two review rounds found the original network exemplar
  (`net_zeek_port_scan.yml`) exercised zero field-mapping translation — the
  one thing this module exists to catch — swapped for
  `net_zeek_executable_download.yml`, the exact rule #217's MEDIUM-4
  finding was about. Also fixed: a skip-vs-error bug for auth-protected ES,
  a missing time-range filter on the threshold test, an index-leak-on-
  setup-failure bug, and a PATH-hijack guard that failed even against the
  real `sigma` binary (verified and fixed empirically, not just by
  inspection).
- [x] **Phase 4 — #222 — COMPLETE** — added a second keyless feed (Emerging
  Threats compromised-ips.txt, alongside abuse.ch Feodo Tracker) and
  replaced the manual cron-install step with a systemd timer
  (`intel-refresh.{service,timer}`, matching the existing `slo-metrics`
  pattern) + an idempotent installer script.
  [PR #272](https://github.com/voltron-1/Suburban_SOC/pull/272) merged
  2026-08-04. Largest review cycle of the six M12 issues: a code-reviewer
  pass empirically reproduced a real bug (untracking the fully-regenerated
  `intel.dat` from git — needed so the new 6h timer stops leaving a
  permanent uncommitted diff — could hang Zeek's packet processing
  indefinitely on a fresh host, since `config.zeek` suspends processing
  until that exact file's `Input::end_of_data` fires, which never happens
  if the file does not exist at all); a security-auditor pass then found 1
  HIGH (the new persistent service would have held the `elastic` superuser
  password, violating this repo's own documented "no service uses elastic
  in normal operation" control — fixed with a dedicated `intel_writer`
  least-privilege role, matching the `slo_metrics`/`agent_checkpoints`
  pattern) and 8 MEDIUMs (unverified ES writes, non-atomic file writes, no
  bogon-address filter, unbounded feed-response size, a destructive
  `RemoveIPC=true` on the shared login account, missing timeout, and a
  stale-Watcher-alert-text/per-feed-visibility gap). One more bug found
  empirically while live-verifying the HIGH fix (not in either review):
  `/storage/PCAP/intel` was `root:root` on this exact host, so the
  live-capture sync had been silently failing the whole time — fixed with
  a self-healing `chown` in `zeek-host-capture.service`. Every fix
  empirically re-verified against the real running stack (not mocks) —
  created the `intel_writer` role/user live, ran the full script against
  it, reproduced and confirmed-fixed the Zeek hang via a real `zeek/zeek`
  container. Follow-ups filed for what was deliberately deferred:
  [#270](https://github.com/voltron-1/Suburban_SOC/issues/270)
  (`configs/intel/` mixes data with code Zeek executes as root; CA
  fingerprint pinning) and
  [#271](https://github.com/voltron-1/Suburban_SOC/issues/271) (ES
  indicator index never retracts a removed indicator).

M12's own issue sequence (#214-#222) is complete, and so is one of the two
architectural follow-ups #214's review filed:

- [x] **#246 — COMPLETE** (priority:critical) — `/approve` (executes
  isolation) and `/pending` (discloses the drafted-action queue) shared
  Logstash's `SOC_AGENT_HMAC_SECRET` with `/alert`, so a Logstash compromise
  (RCE, container escape, a crafted Ruby filter) could both draft AND
  approve/execute containment end-to-end; the recorded `approver` was also
  an unauthenticated, self-asserted request-body field. Fixed with a second,
  independent `SOC_APPROVER_HMAC_SECRET` provisioned to the agent container
  only (never Logstash), and the recorded `approver` now derives from the
  operator-configured `SOC_APPROVER_IDENTITY` bound to that credential, not
  the request body. [PR #274](https://github.com/voltron-1/Suburban_SOC/pull/274)
  merged 2026-08-05. security-auditor (no CRITICAL/HIGH) + code-reviewer
  (approved outright) ran in parallel; 3 MEDIUM/LOW findings fixed before
  merge: no runtime guard stopped an operator from setting both secrets
  equal, silently reverting the whole fix (added `_resolve_approver_secret()`,
  fails closed on `/approve`+`/pending` if they match); the SOP-147
  evidence-collection scripts (`section_a_evidence.sh`, `sim_intel_match.sh`)
  still signed `/pending` with the old secret, which would have silently
  reported "0 pending" every run instead of failing loudly — the same
  false-negative shape as the earlier "SOAR trigger not wired" issue; and a
  set-but-empty `SOC_APPROVER_IDENTITY` fell through past its intended
  default. CI also caught a CodeQL false positive post-review (a
  `secret_name` parameter tripped the clear-text-logging heuristic purely on
  naming, never held actual secret bytes — renamed to `hmac_env_var`,
  fixed). Follow-up filed for what's out of scope:
  [#273](https://github.com/voltron-1/Suburban_SOC/issues/273)
  (hive-mind-broker runs its own separate `/approve` with the same
  unauthenticated-approver defect on a different trust boundary —
  `HIVE_MIND_SECRET`, not `SOC_AGENT_HMAC_SECRET`, so criterion 1 already
  holds there; criterion 2 does not).

- [x] **#247 — COMPLETE** — an approval claim was never released when execution
  failed, permanently stranding the alert: nothing could ever retry it and
  nothing surfaced that it was stuck. A pre-existing architectural follow-up
  filed during #214's review (2026-08-02), not part of the #214-#222 sequence
  but tagged to this milestone.
  [PR #279](https://github.com/voltron-1/Suburban_SOC/pull/279) merged
  2026-08-05 (`ef96b61`). Three security-auditor rounds reshaped the design
  twice — the substantive change being that a *confirmed* router-block failure
  is now distinguished from an *ambiguous* one: `dispatch_block_to_all()`
  returns `(count, unknown_count)` and an unconfirmed router is never folded
  into the failure count, since a caller treating the two alike would risk a
  real double-dispatch on retry. The terminal `ESCALATED` state was removed in
  the process — a confirmed execution failure now reverts to
  `PENDING_APPROVAL` so a retry is possible, rather than dead-ending in a state
  nothing ever leaves. Closed manually: the PR body carried no `Closes #247`
  keyword, so the merge did not auto-close it.
- [~] **#273 — IN REVIEW** — the hive-mind-broker's own `/approve` recorded the
  approver straight from the request body (`body.get("approver", "unknown")`),
  so anyone holding `HIVE_MIND_SECRET` — the ai-agent container, and anything
  reaching 127.0.0.1:8000 — could execute a router block and stamp it with an
  arbitrary analyst name. Broker-side counterpart to #246, on a different trust
  boundary. Fixed with credential-bound `BROKER_APPROVER_IDENTITY` /
  `BROKER_DISPATCH_IDENTITY` labels resolved through a pure `_resolve_identity()`
  that handles the set-but-empty env var (the same defect #246's review caught);
  what the caller sent is retained on both endpoints as
  `upstream_approver_claimed`, sanitised and bounded, never as the approver of
  record. [PR #280](https://github.com/voltron-1/Suburban_SOC/pull/280) — all
  16 CI checks green, **awaiting merge sign-off**.
  security-auditor + code-reviewer ran in parallel. Both code-review Must-Fix
  items were real: two of the six original tests were vacuous (one asserted on
  a re-implementation of the fallback expression rather than the module
  constant; the other passed by coincidence because the configured default
  equalled the old hardcoded literal) — both rewritten and re-verified by
  mutation. **Known residual risk, deliberately not closed there** (the
  auditor's HIGH): `/approve` and `/webhook/dispatch` share one secret, so a
  compromised agent can call `/approve` and be recorded under the human label.
  The fix narrows forgery from any string to one of two labels chosen by URL;
  it does not prove a human acted. The docstring, compose comment and
  `.env.example` now state that limit rather than overclaiming. Fully closing
  it needs a second independent credential the way #246 did — its own issue.

**M12 is COMPLETE** — 14/14 issues closed 2026-08-05. #273 merged via
[PR #280](https://github.com/voltron-1/Suburban_SOC/pull/280) (16/16 CI green),
and #213 closed with the full arc summarised.

- [x] **M13 US2 — #225 — COMPLETE** — 7 credential-access/AD-attack rules
  (4 process_creation + 3 Security-channel: Kerberoasting 4769, AS-REP 4768,
  DCSync 4662). [PR #282](https://github.com/voltron-1/Suburban_SOC/pull/282)
  merged 2026-08-05, closing #232. `winlogbeat.yml` didn't collect
  4769/4768/4662 and the Security-channel ECS mapping lacked the fields
  these rules select on — both fixed up front (same silent-no-op shape as
  #217's `ImagePath` defect). security-auditor + code-reviewer found real
  bypasses (Kerberoasting `Status` blacklist let other failure codes
  through; LaZagne name-only check defeatable by rename; DCSync missing a
  third replication-rights GUID) — all fixed pre-merge. 45 → 52 rules.
  Umbrella issue #225 closed manually 2026-08-06 (PR said "Part of #225",
  not "Closes").
- [x] **M13 US3 — #226 — COMPLETE** — 13 persistence/privesc/discovery rules
  (8 process_creation + 5 System-log, 1 over the original 12-estimate from 2
  deliberate reclassifications). [PR #284](https://github.com/voltron-1/Suburban_SOC/pull/284)
  merged 2026-08-05, closing #233/#234. Found and fixed a repo-wide silent
  no-op: `suburban-soc-ecs.yml` claimed an `OriginalFileName` rename
  `logstash.conf` never performed, which would have broken all 8 rules
  using it. 2 HIGH from security-auditor (accessibility-backdoor rule
  couldn't detect the IFEO variant it claimed to; netsh portproxy false-
  positived on `delete`). 45 → 58 rules. Umbrella issue #226 closed
  manually 2026-08-06.
- [x] **M13 US4 — #227 — COMPLETE** — 10 ransomware/collection/exfiltration
  rules, closing Collection TA0009 (0→4) and Exfiltration TA0010 (0→2) gaps
  plus 4 impact rules. [PR #285](https://github.com/voltron-1/Suburban_SOC/pull/285)
  merged 2026-08-06, closing #235/#236. HIGH from security-auditor:
  `certutil -encode`/`-decode` flag matching collided with hyphen-compound
  filenames like `base64-encoded-output.txt` — fixed and backported to the
  pre-existing `-decode` rule too. 58 → 75 rules. Umbrella issue #227
  closed manually 2026-08-06.

- [x] **M13 US5 — #228 — COMPLETE** — Campus Network Detection via Zeek
  Telemetry, 15 rules across 4 implementation issues (#237 DNS x5, #238
  SSL/TLS x2, #239 conn x4, #240 HTTP/SMTP x4). Split into two commits on
  `feat/m13-us5-zeek-network-detection`: a prerequisite-fix commit (`0c416bb`,
  Zeek/Logstash/pySigma field mapping for dns/ssl/conn/http — every prior
  M13 batch's silent-no-op check, done up front this time instead of found
  broken after) and the 15-rule commit (`11e0b9a`).
  [PR #294](https://github.com/voltron-1/Suburban_SOC/pull/294) merged
  2026-08-06 (`988eb2c`, squash), 12/12 CI green including `live-fire`
  against a real Elasticsearch — the one thing that couldn't be confirmed
  before merge (the `re` Sigma modifier's assumed Lucene full-match
  semantics) is now proven, not just reasoned about. 75 → 90 rules.
  #237-#240 and #228 itself closed manually after merge (PR body referenced
  them narratively, not via a Closes keyword — same not-auto-closed shape
  as #225/#226/#227/#247).
  Two review rounds on the rule diff (security-auditor + code-reviewer
  parallel, then a second, more thorough security-auditor pass) found and
  fixed real defects, not style nits: `net_zeek_ssl_self_signed_c2.yml`
  would have been a silent no-op on OpenSSL 3.x (confirmed empirically —
  real string is "self-signed", not "self signed"); the RDP/SMB rules'
  "boundary sensor" assumption was contradicted by this repo's own capture
  config and rebuilt with a new `cidr` Sigma modifier; an ICMP-tunnel
  threshold was 1000x too low because `orig_bytes` is a per-flow total, not
  per-packet; a DGA regex had a one-character-bypass copy/paste bug; a
  mining-pool rule's stated rationale for skipping the #222 intel-feed
  pattern was factually wrong (corrected, not just patched around).
  Known, stated gap: one new live-fire test (`net_zeek_dns_dga_nxdomain_burst.yml`)
  can't be confirmed passing outside CI (no reachable Elasticsearch in the
  authoring environment) — it's the first real test of the `re` Sigma
  modifier's assumed Lucene full-match semantics, added for this batch.
  Follow-ups filed: [#286](https://github.com/voltron-1/Suburban_SOC/issues/286)
  (MAC quarantine correlation), [#287](https://github.com/voltron-1/Suburban_SOC/issues/287)
  (static logstash.conf↔ecs.yml drift test — this defect class recurred in
  4 consecutive PRs), [#288](https://github.com/voltron-1/Suburban_SOC/issues/288)
  (capture-loss monitoring), [#289](https://github.com/voltron-1/Suburban_SOC/issues/289)
  (compliance docs citing dead config), [#290](https://github.com/voltron-1/Suburban_SOC/issues/290)
  (ES template case-normalization gap), [#291](https://github.com/voltron-1/Suburban_SOC/issues/291)
  (leading-wildcard query cost + cross-stream duplicate-alert risk),
  [#292](https://github.com/voltron-1/Suburban_SOC/issues/292) (DNS TXT-C2
  download-direction mapping), [#293](https://github.com/voltron-1/Suburban_SOC/issues/293)
  (pin the unpinned `zeek/zeek` image a rule's string match now depends on).

- [x] **M13 US6 — #229 — COMPLETE, MERGED** — PowerShell Deep Inspection &
  Windows Event Log Detection, 10 rules (not #229's stated "8" — #241/#242's
  detailed spec is 3+7=10, same over-delivery-vs-umbrella-estimate shape as
  US3's 12→13; one of the 7 auth_win_* rules was then deleted after review,
  see below, and one posh_ps_* rule was split into two, netting back to 10).
  [PR #298](https://github.com/voltron-1/Suburban_SOC/pull/298) merged
  2026-08-08 (squash), 12/12 CI green. 90 → 100 rules.
  Two review rounds (security-auditor + code-reviewer parallel, both
  unusually thorough) found and fixed real defects: `auth_win_disabled_
  account_logon_attempt.yml`'s hex literal was uppercase-only against a
  field with no case normalizer — Windows renders it lowercase in the raw
  EVTX XML Winlogbeat parses, same class of bug as US5's OpenSSL string
  mismatch; `auth_win_after_hours_admin_logon.yml` was DELETED after
  round-2 review found it was a strictly-worse, unfiltered superset of the
  already-`stable` `auth_win_sedebug_special_logon.yml` (same EventID, same
  tag, but that rule already filters correctly) — its own "compensating
  control" (a Kibana off-hours rule schedule) turned out not to exist as a
  real feature; `auth_win_sensitive_group_recon.yml` used unanchored
  `contains` for SID RID suffixes (false-fires broadly across a domain),
  fixed to `endswith` matching a sibling rule's already-correct pattern;
  `posh_ps_ad_recon_module.yml` was split into two severity-differentiated
  rules (PowerView high, official ADModule cmdlets low) rather than one
  rule with an unworkable signal-to-noise ratio. Added the first-ever
  live-fire test coverage for the Security-channel pipeline. Follow-ups
  filed: [#295](https://github.com/voltron-1/Suburban_SOC/issues/295)
  (ScriptBlockText truncation risk across the whole 4104 rule surface),
  [#296](https://github.com/voltron-1/Suburban_SOC/issues/296) (never-
  implemented NIST/CIS tag mandate), [#297](https://github.com/voltron-1/Suburban_SOC/issues/297)
  (possible pre-existing logstash.conf type-comparison bug, unrelated to
  any Sigma rule's own compiled query).

- [x] **M13 US7 — #230 — COMPLETE, MERGED** — Linux Auth Log Detection &
  Final CI Verification, 5 rules (auth_linux_ssh_root_login, auth_linux_ssh_
  authorized_keys_change, auth_linux_sudo_privilege_escalation,
  auth_linux_invalid_user_ssh_attempt, auth_linux_su_session_opened) via
  #243. **First Linux-telemetry batch in this whole corpus** — everything
  before this has been Windows or Zeek.
  [PR #300](https://github.com/voltron-1/Suburban_SOC/pull/300) merged
  2026-08-08 (squash), 12/12 CI green. 90 → 105 rules. Branched off main
  before US6 (#298)/the escape-semantics fix (#301) merged, so landing it
  required resolving a real merge conflict (not just an "update branch"
  fast-forward) in `sigma_eval.py`, `fixtures.json`, `test_live_fire.py`,
  and the generated docs — both US6 and US7 had independently added content
  near the same insertion points. Resolved by hand: `sigma_eval.py`'s
  conflict combined US7's own `_TEXT_MAPPED_FIELDS`/word-boundary matching
  with #301's `_sigma_wildcard_to_regex()`, since both are real, independent
  fixes to the same `cmp()` function, not competing versions of one fix;
  the docs were regenerated fresh from the merged 105-rule corpus rather
  than hand-merged. Re-verified post-resolution: 52/52 pytest, ruff clean,
  105/105 rules pass a full live-fire sweep against real Elasticsearch, no
  duplicate UUIDs.
  Central mechanism, novel to this corpus: `message` is the first field
  ever selected on that's mapped `text` (analyzed) rather than `keyword` —
  required extending sigma_eval.py (`_TEXT_MAPPED_FIELDS`) and switching
  from `contains` (unsafe: unanalyzed Lucene wildcards against an analyzed
  field) to bare-equality selectors split across single words (safe:
  compiles to an analyzed, whole-token query_string term) ANDed together.
  Independently confirmed correct by security-auditor's own analysis of
  Lucene/ES internals, since no live Elasticsearch was available locally.
  Review found 3 HIGH findings, two in already-shipped pipeline
  infrastructure this batch made load-bearing for the first time:
  `configs/endpoint/filebeat_endpoint.yml` had a `syslog: ~` parser
  mutually exclusive with the existing sshd grok (stripped the exact
  header the grok's pre-filter needs — removed); the sshd grok's tail
  regex couldn't match modern OpenSSH's key-fingerprint suffix on
  publickey lines, silently failing every publickey login including root
  (fixed, with a regression test using a real modern OpenSSH line); and
  both the `event.module` stamp and the sshd pre-filter only matched
  `auth.log`, never `/var/log/secure` — all 5 new rules were silently dead
  on RHEL/CentOS (fixed). Follow-up filed:
  [#299](https://github.com/voltron-1/Suburban_SOC/issues/299) (rule
  descriptions carry ES-analyzer detail into the Kibana alert flyout).

- [x] **Live-ES tuning pass — no issue, session-initiated — COMPLETE, MERGED**
  — started a real Elasticsearch (native 9.3.2, matching CI) and swept the
  entire rule corpus's actually-compiled queries against it, rather than
  trusting `sigma_eval.py`'s local re-implementation alone. Found 2 real,
  pre-existing bugs (predate this session, not in US6/US7's own new rules)
  sharing one root cause — Sigma's own `*`/`?`/`\` value-escaping being
  silently mishandled by rule authors, never modeled by `sigma_eval.py` at
  all: `system_win_service_installed.yml`'s `\??\` NT-path filters had their
  leading backslash silently eaten (`\?`→literal `?`), never matching real
  `\??\`-prefixed paths — a false positive/over-alert;
  `proc_creation_win_psexec_client_side_launch.yml`'s `contains: '\\'`
  UNC-path check collapsed to matching any single backslash, an effective
  no-op on any local file path. Also closed the structural gap:
  `sigma_eval.py` now has `_sigma_wildcard_to_regex()` so future rules can't
  hide the same class of bug from local fixture tests. Delivered as a
  minimal, focused fix against `main` (not bundled into US6/US7, since these
  bugs predate both): [PR #301](https://github.com/voltron-1/Suburban_SOC/pull/301)
  merged 2026-08-08 (squash), 12/12 CI green. The same live-fire sweep (run
  against a local-only merge of main+US6+US7, not pushed) also confirmed all
  15 of US6/US7's own rules passed live with no further findings — no
  separate fix needed there.

**M13 is COMPLETE** — all 7 user stories (#224-#230) merged, 35 → 105 Sigma
rules. #298, #300, #301 merged 2026-08-08 (no GitHub-side human review —
explicit review-bypass confirmed by the repo owner before merging; all three
had 2 rounds of security-auditor/code-reviewer sub-agent review and 12/12 CI
green). Merging #300 after #298/#301 surfaced a real merge conflict (both
US6 and US7 touched `sigma_eval.py`/`fixtures.json`/the generated docs near
the same insertion points) — resolved by hand, re-verified post-resolution
(52/52 pytest, 105/105 live-fire against real ES, no duplicate UUIDs), documented
above under US7. #229, #230, #241, #242, #243 closed manually (PRs said
"Part of #XXX", not "Closes"). **#244 — COMPLETE, CLOSED** — final
cross-corpus verification against real `main`: 31/31 `tests/detections/`
+ 8/8 `test_live_fire.py` against real Elasticsearch (exceeds the original
"5/5" estimate — the live-fire suite grew per-story), 105 rules, zero
duplicate UUIDs, TA0009 Collection = 4 (meets `>=4`), TA0010 Exfiltration =
2 (meets `>=2`), every rule has a fixtures.json entry, both doc generators
re-run clean. Fixtures for each story's own rules were already added
incrementally per-PR (per the `sigma-rule` skill), so #244's remaining scope
was purely this final verification pass.

**M13 milestone note:** [#252](https://github.com/voltron-1/Suburban_SOC/issues/252)
stays open, tagged to this milestone but deliberately deferred since US1
(2026-08-02) — `ScriptBlockText`'s `ignore_above: 8191` may still be below
real PowerShell 4104 chunk sizes; separate scope from M13's rule-count goal.

M14 started 2026-08-08 — see NEXT UP at the top of this file for its live
status.

</details>

---

## MILESTONE BACKLOG — M15/M16, opened 2026-08-05 (M14 moved to NEXT UP, started 2026-08-08)

13 open issues had accumulated with **no milestone at all** — every one filed as
a follow-up during an M11/M12 security review, real but deliberately out of
scope for the issue being fixed at the time. Triaged into three milestones so
they stop being invisible.

M14 is now IN PROGRESS — see NEXT UP at the top of this file, not here.

**[M15 — Detection Correctness & Pipeline Fidelity](https://github.com/voltron-1/Suburban_SOC/milestone/19)** (3) —
whether the *existing* corpus behaves as written, as distinct from M13's count.
- [ ] **#263** (P1, security) — `ignore_above: 8191` lets both PowerShell rules be
  bypassed by payload length. **Compounds as M13 grows the corpus**, so this
  should not trail M13 by much.
- [ ] **#261** (P1) — Zeek T1046/T1110 classification tags every matching event
  rather than an aggregated notice.
- [ ] **#267** (P1) — `soar_quarantine_alert.json` Watcher has no HMAC auth and may
  not install at all.

**[M16 — Endpoint Onboarding & Threat-Intel Integrity](https://github.com/voltron-1/Suburban_SOC/milestone/20)** (3)
- [ ] **#265** (P2) — **DEFERRED**, gated on an external event: Winlogbeat/endpoint
  Filebeat have no client cert minted. Harmless while no endpoint is deployed;
  a hard blocker the moment one is.
- [ ] **#270** (P2) — `intel-refresh.service` co-locates config with data Zeek
  executes as root, and re-trusts the CA on every use.
- [ ] **#271** (P2) — the indicator index never retracts an indicator a feed removed.

---

**Milestone: [M13 - Detection Expansion: 35 → 105 Sigma Rules (Campus SOC)](https://github.com/voltron-1/Suburban_SOC/milestone/17).**
Created 2026-08-01 by an uncoordinated external tool (Google's Antigravity/
Gemini CLI), found running on this same repo mid-M12-session — see the
2026-08-01 session log below for that incident. 7 user stories (#224-#230,
~10 rules each), 14 implementation issues (#231-#244), one final-verification
issue (#244). User approved continuing the milestone 2026-08-02 conditional
on the repo/board being current — they weren't (M13's 22 issues existed on
GitHub but were entirely absent from Project Board #17, and all 14
parent-child links had silently failed because the seeding script used
`--add-parent`, not a real `gh issue edit` flag — both fixed before
proceeding). Multi-phase execution gating applies here too: each user story
is its own gated batch, no unattended multi-story runs.

- [x] **US1 — #224/#231 — COMPLETE, MERGED** — 10 Windows LOLBin/execution
  rules. [PR #251](https://github.com/voltron-1/Suburban_SOC/pull/251)
  merged 2026-08-03; both #224 and #231 closed. `security-auditor` review
  of the first draft: **"0 of 10 rules are solid as written"** — 3 had zero
  real detection value or matched routine legitimate activity, all fixed
  (see PR body for the per-rule breakdown). Surfaced two corpus-wide
  findings unrelated to this batch specifically — see below.
- [x] **#249/#250 — process.args mapping — COMPLETE, LIVE-VERIFIED** — the
  security review of US1 found `process.args` (and
  `process.parent.args`/`ScriptBlockText`/etc.) indexed as plain `keyword`,
  `ignore_above: 1024`, no normalizer — meaning (#249) Sigma's lowercase
  literals may not match real mixed-case telemetry at all, and (#250) any
  command line over 1024 characters is silently un-indexed. Both affected
  **all 45 pre-existing rules**, not just US1's 10. [PR
  #253](https://github.com/voltron-1/Suburban_SOC/pull/253) merged
  2026-08-02; both issues closed. Needed **two** `security-auditor` passes:
  the first fix drafted used `wildcard` field type + a normalizer, which the
  review caught as likely rejected by Elasticsearch outright, or — worse —
  if somehow accepted, would have caused *total* false negatives on every
  mixed-case rule literal in the corpus (the `wildcard` type's
  query-verification is case-sensitive against the raw doc value regardless
  of the normalizer). Corrected to `keyword` + normalizer +
  `ignore_above: 8191`, re-reviewed clean. Also fixed: `apply-templates.sh`
  printed each template PUT's HTTP status but never checked it (curl treats
  a 400 as "success"), which is exactly the mechanism that would have let
  the wrong first draft ship silently broken — now asserts on the code and
  fails loudly. Filed [#252](https://github.com/voltron-1/Suburban_SOC/issues/252)
  for a narrower related finding (`ScriptBlockText`'s real chunk size may
  still exceed the new 8191 ceiling) — remains open, separate scope.
  **Live-verified 2026-08-02** once Docker Desktop's WSL2 integration was
  restored (see LAST SESSION): template PUT confirmed HTTP 200, installed
  mapping confirmed byte-for-byte via `GET _index_template`, a synthetic
  mixed-case `process.args` doc confirmed a lowercase Sigma-style query now
  matches it, a synthetic 1385-char value confirmed no longer silently
  dropped, and all 6 `logstash-security-*` data streams rolled over
  (`POST .../_rollover`) with each new write index's mapping confirmed
  corrected via `GET .../_mapping/field/process.args`. No real
  Windows/process telemetry currently flows through the pipeline (live
  sampling found NTP-only data) — verification used synthetic scratch-index
  data for that reason, never the real `logstash-security-*` streams; this
  is a pre-existing gap (echoes the DEFERRED real-telemetry ticket), not
  something #253 introduced.
- [ ] **US2 — #225/#232** — 7 Credential Access & AD Attack rules. Not started.
- [ ] **US3 — #226/#233,#234** — 12 Persistence/PrivEsc/Discovery rules. Not started.
- [ ] **US4 — #227/#235,#236** — 10 Ransomware/Collection/Exfiltration rules
  (closes the TA0009/TA0010 coverage gaps). Not started.
- [ ] **US5 — #228/#237-#240** — 15 Zeek network-telemetry rules. Not started.
- [ ] **US6 — #229/#241,#242** — 8 PowerShell/Windows Security log rules. Not started.
- [ ] **US7 — #230/#243,#244** — 5 Linux auth.log rules + final CI
  verification (105-rule count, no duplicate UUIDs, coverage docs in sync).
  Not started.

Next unstarted item: **US2 — #232** (7 Credential Access & AD Attack rules).

---

<details>
<summary>Prior milestone — M11 Phase A-H (structural remediation + agent
orchestration), COMPLETE 2026-07-16 through 2026-07-20 — click to expand</summary>

Approved plan (2026-07-16, Fable 5 planning session): Phase 0 triage of all 9
open issues (each classification adversarially verified, 9/9 agreement) →
execute-now = #189, #190, #204-#208; #201 closed as superseded; #182 stays
DEFERRED. Phase sequence: **A gate integrity — COMPLETE** → B P3 fixes (#189,
#190) → C compliance foundation (#204, #205) → D detection/pipeline logic
(#206, #208 — gated Logstash-restart sign-off) → E SOP standardization (#207,
5 sequential PRs) → F three-lens audit (soc-architect / red-team-architect
[Opus 4.8] / purple-team-architect [Opus 4.8], security-diff-framing
vocabulary) → G remediation reserve (gated fix-now vs backlog split) → H agent
orchestration refactor (Perceive→Think→Act→Check loop, ES-backed checkpoints,
retry logic — 6 components, §12.3 human gate preserved). Execution
model: Sonnet 5 for phases A-E.

**Phases B-E COMPLETE**: PRs
[#209](https://github.com/voltron-1/Suburban_SOC/pull/209) (System Hardening
& Config), [#210](https://github.com/voltron-1/Suburban_SOC/pull/210)
(Compliance & Documentation),
[#211](https://github.com/voltron-1/Suburban_SOC/pull/211) (Pipeline,
Detections & Data Enrichment) merged 2026-07-16, closing #189, #190,
#204-#208. **Phase H COMPLETE**: `agent.py`, `checkpoints.py`, `retry.py`,
`test_agent.py` merged via `2bb3d8f` (2026-07-20) — **but this commit also
introduced the approval-gate regression that M12/#214 now fixes**; see NEXT
UP above. Phases F/G (three-lens audit, remediation reserve) were not
executed as separate tracked work before this session's evaluation review
superseded them — folded into M12's scope going forward.

Phase A (gate integrity) — **COMPLETE 2026-07-16**:
- [x] Branch protection enabled on `main`: 9 required status checks (`Analyze
  (python)`, `detections`, `shellcheck (bash)`, `ruff (python)`,
  `mypy (python)`, `yamllint (configs)`,
  `pytest-cov >= 70% (slo_metrics / run_hunts / weekly_ciso_report)`,
  `gitleaks`, `SOAR auth / exclusion / approval / tenant-scoping`); no
  required reviews (solo-maintainer repo — the session-level review-bypass
  confirmation stays the human gate); `enforce_admins: false` so chore
  pushes to `main` (e.g. this file's own update-on-merge habit) keep working;
  `allow_force_pushes`/`allow_deletions` now `false` for all collaborators
  (closes the gap #168's structural review originally flagged). Verified via
  `gh api repos/voltron-1/Suburban_SOC/branches/main/protection`. This was
  #168's explicitly deferred "separate explicit sign-off" repo-settings
  change — obtained this session before applying.
- [x] **#201** closed as superseded — PR #202 (merged 2026-07-12) delivered
  every acceptance criterion here (Kibana HTTPS-only, all internal consumers
  migrated to `https://`, TLS-aware healthcheck, live-verified end-to-end)
  before #201 was even filed; the ticket was simply left orphaned-open.
  Closed with a comment citing the specific evidence per file/line.

</details>

- [x] **#184** — SOC agent audit-write failures had no dashboard-visible
  metric (follow-up to #165). `write_audit()`'s except block now best-effort
  writes a failure-marker doc to a new per-tenant `soc-agent-health-<tenant>`
  index (its own nested try/except — the "never raise" contract is
  unchanged); `logstash_writer`'s ES role extended to that index pattern,
  reusing the agent's existing credential; new `metric_audit_write_failures()`
  in `slo_metrics.py`, wired into the existing generic breach/alert/dashboard
  machinery — 1-2 failures in the rolling window tolerated, 3+ breaches
  (`SLO_AUDIT_WRITE_FAIL_MAX`, default 2, combined with the existing strict
  `>` comparator). Built via subagent-driven development (implementer +
  task-reviewer per task, final whole-branch review on `opus`). Two real bugs
  surfaced and fixed during task review: the originally-planned threshold
  default (3) combined with the existing comparator actually meant "breach at
  4+," not "3+" — corrected to 2; the new metric's query was missing the
  `WINDOW` range filter used by every sibling metric, making it an all-time
  count instead of a rolling one — fixed to match. The final whole-branch
  review found a more significant gap: `write_audit()` (and the new marker
  write) only caught connection-level failures — `requests.post` doesn't
  raise on HTTP 4xx/5xx, and ES's `_bulk` API can return HTTP 200 with an
  embedded per-item rejection, which is exactly the case that matters most
  ("ES up, write silently rejected"). Fixed (with explicit sign-off, since it
  touched the pre-existing primary audit-write path) by checking the bulk
  response body inside the existing try/except, unifying detection with no
  duplicated logic. Live verification against the running stack caught two
  more real bugs no mocked test surfaced: an ES role missing the
  `auto_configure` privilege silently rejected the new index's writes (the
  live trigger for the bulk-response-checking finding above), and a
  `docker compose up -d <service>` gotcha where the `provision` service
  re-running silently reverts whatever the `roles` service last applied,
  requiring `roles` to be re-run after any dependent-service redeploy — a
  pre-existing infra behavior, not introduced by this issue, worth a future
  look. [PR #203](https://github.com/voltron-1/Suburban_SOC/pull/203) merged;
  issue closed.
- [x] **#177** — residual hardening, five independent fixes: (1) Kibana TLS
  (SC-8) — a dedicated server cert minted off the existing stack CA (mirrors
  the logstash/filebeat cert-gen blocks), `SERVER_SSL_*` + a TLS healthcheck;
  every internal consumer (agent, `slo_metrics.py`, 7 operator scripts, docs)
  moved from `http://` to `https://`, reusing the existing `ES_CA`/`ES_VERIFY`
  trust chain rather than a second one. (2) ntfy/Discord notification masking
  (AC-4) — source IP/MAC masked by default (`NOTIFY_INCLUDE_RAW_IOCS` opts
  into raw), Kibana case/audit/broker dispatch always keep the unmasked
  value; new `tests/ai_agent/test_notify_masking.py`. (3) Removed the 2.2MB
  `suburban_soc_dashboard_v2.ndjson` — `git log --follow` confirmed it was
  never wired into `deploy_dashboards.sh` or referenced anywhere else
  (orphaned, not an LFS migration candidate). (4) Broker `__main__` now binds
  `127.0.0.1`/`reload=False`. (5) `isolate.sh` SSH host-key verification now
  strict by default. `security-auditor` + `code-reviewer` (parallel) caught
  two real pre-existing bugs surfaced by the new masking code's dependencies:
  a shadowed module-level `_MAC_RE` that let `is_valid_mac()` accept a MAC
  with trailing garbage (renamed the unrelated sanitizer regex to
  `_MAC_TOKEN_RE`), and `_mask_mac()` leaking a whole MAC when `:`/`-`
  separators were mixed (now tokenizes instead of splitting on one guessed
  separator) — both fixed with regression tests. The audit also found
  `isolate.sh`'s exclusion-list check failed OPEN on a missing list (unlike
  the agent/broker's fail-closed posture); fixed in the same PR rather than
  filed separately, since it's a small fix in the same file/control family.
  Live-verified against the running stack: Kibana confirmed HTTPS-only +
  healthy (caught and fixed a real healthcheck bug — curl ALPN-negotiates
  HTTP/2 over TLS by default, silently breaking the original
  `HTTP/1.1 302 Found` status-line grep; fixed to match status code only),
  the agent's Kibana Cases integration confirmed working end-to-end
  post-rebuild (a real HMAC-signed `/alert` produced a real case id over
  TLS), `stack_health.sh` confirmed green, and all four `isolate.sh`
  exclusion-list scenarios exercised directly (missing/present list ×
  default/opt-in). 145/145 tests passing.
  [PR #202](https://github.com/voltron-1/Suburban_SOC/pull/202) merged;
  issue closed.
- [x] **#176** — unbounded runtime state, three separate vectors:
  `run_hunts.py`'s hourly cron re-ran every hunt over a rolling window with
  no dedup (`soc-hunts` growing forever) — fixed with a deterministic
  per-day `_id` so ES's `index` op upserts instead of appending; both the
  agent's and broker's append-only approval-queue JSONL files grew forever
  — new `compact_agent_approval_queue.py`/`compact_broker_approval_queue.py`
  archive fully-resolved, aged-out entries, coordinated with the live
  services via a stable lock-file path (flocking the mutable data file
  directly doesn't compose safely with atomic replace); `weekly_ciso_report.py`
  moved its PDF output off a fixed, world-readable `/tmp` path to a `0700`
  `reports/` dir with per-run filenames and retention pruning.
  `security-auditor` + `code-reviewer` (parallel) each caught a real bug:
  an unlocked "claimed" marker write that bypassed the whole point of the
  new flock, and a crash-durability gap in the original truncate-in-place
  rewrite — both fixed (the latter via a stable lock file + atomic
  temp-file replace, after realizing the reviewers' suggested naive fix
  would have introduced a *worse* silent-data-loss race). Live-verified
  against the running stack: full pending→claimed→resolution sequence,
  both compaction scripts against the real live queues, PDF path/perms via
  a real triggered report, and the ES upsert mechanic directly. Also caught
  two stray runtime lock-artifact files that nearly got committed;
  `.gitignore` updated so that can't happen again.
  [PR #200](https://github.com/voltron-1/Suburban_SOC/pull/200) merged;
  issue closed.
- [x] **#175** — convention drift: standardized all 12 remaining
  `#!/bin/bash` scripts to `#!/usr/bin/env bash` (0 bare left across 39
  tracked `.sh` files); converted 6 Python modules to proper PEP 257 module
  docstrings (`agent_app.py`, broker's `app.py`/`dispatcher.py`/
  `inventory.py`, `slo_metrics.py`, `run_hunts.py` — verified via
  `ast.get_docstring()`); removed README's stale `/wiki-temp` reference
  (confirmed via `git log` the gitlink was already resolved pre-session)
  plus a second stale entry it had drifted into, `/scripts/agile` (deleted
  in #173); new `docs/CONVENTIONS.md` to stop the drift going forward
  (shebang/docstring style + dashed `YYYY-MM-DD` date-stamps, not a
  retroactive rename). No functional changes — pure cosmetic/hygiene, so
  skipped the usual agent-based code review this time and relied on lint +
  the full affected test suite (141 tests) instead.
  [PR #199](https://github.com/voltron-1/Suburban_SOC/pull/199) merged;
  issue closed.
- [x] **#174** — no Python package structure; `sys.path` hacks scattered
  across 6 test files; one unpinned requirements file. Offered two designs;
  the lower-risk one was chosen — pytest's native `pythonpath` config
  (root `pyproject.toml`) over converting the broker/agent into real
  installed packages with relative imports and Dockerfile CMD rewrites, so
  zero changes to either production entrypoint. Single-sourced the Python
  version via `.python-version` across all 5 workflows. Left the broker's
  CI `working-directory` workaround in place — tested removing it first,
  which broke 7 tenant-routing tests because `app.py`'s
  `Inventory("inventory.yaml")` resolves relative to CWD, not `__file__` (a
  separate, pre-existing issue out of scope this pass). Two real gaps
  caught before merge: `code-reviewer` found `test_es_client.py`'s
  `sys.path.insert` wasn't actually removed (only its docstring was), and
  the first real CI run caught that `detections.yml` never installed
  `pytest` in the first place (the old bare-`python` invocation didn't need
  it). [PR #198](https://github.com/voltron-1/Suburban_SOC/pull/198)
  merged; issue closed.
- [x] **#173** — repo-root clutter and dead scripts: deleted `audit_repo.sh`
  (stale foreign repo slug) and `validate_soc.sh` (superseded by
  `stack_health.sh`/`verify_*.sh`); moved the two `UIW_*.html` deliverables
  into `reports/`; removed the empty `scripts/logstach/`; deleted the
  entire `scripts/agile/` (15 one-shot historical board-automation scripts,
  all referencing a stale/wrong repo slug); merged the 3 near-duplicate
  stream-capture scripts into one `stream_capture.sh <bat0|br-lan|raw>`,
  updating every call site and doc reference (`code-reviewer` caught one
  I'd missed — a stale comment in the live systemd unit file). Live-traced
  all three capture modes with a sudo test-shim (no passwordless sudo in
  this environment) confirming byte-for-byte identical command construction
  to the originals, without touching the actually-running capture service.
  [PR #197](https://github.com/voltron-1/Suburban_SOC/pull/197) merged;
  issue closed.
- [x] **#172** — zero test coverage on the SOC reporting plane
  (`slo_metrics.py`/`run_hunts.py`/`weekly_ciso_report.py`); agent ran on
  Flask's dev server, not a production WSGI server (SA-11/SC-5). 82 tests,
  97%+ combined coverage on all three files, gated in new CI workflow
  `reporting-coverage.yml`. Dockerfile CMD → gunicorn — deliberately
  `--worker-class gthread --workers 1 --threads 4`, not the issue's suggested
  `-w 2`: agent_app.py's HMAC replay-nonce cache and approval-queue writer
  are `threading.Lock`-guarded in-process state, not cross-process-safe.
  `security-auditor` caught a real concurrency regression this move exposed —
  `/approve`'s check-then-execute wasn't atomic, so genuinely concurrent
  gthread requests could double-execute an isolation the old sequential dev
  server could never race. Fixed (atomic claim under `_queue_lock`),
  live-verified against the running container (confirmed double-dispatch
  without the fix, single-dispatch with it), and covered by a permanent
  regression test. [PR #196](https://github.com/voltron-1/Suburban_SOC/pull/196)
  merged; issue closed.
- [x] **#171** — broker security events logged via bare `print()`, no
  persisted record of denied/replayed/invalid-signature attempts (AU-2/3/12).
  All `print()` converted to `logging`; new `write_denial()` persists every
  `_verify()` auth-failure to `soc-audit-unassigned` via a new dedicated
  least-privilege `hive_mind_broker` ES user (reuses the existing
  `soc_audit_appender` role, no new role). 37 tests passing; `security-auditor`
  (no exploitable issues) + `code-reviewer` (one should-fix, resolved) both
  ran. Live-verified against the running stack: real invalid-signature
  request → 401 + matching ES doc; confirmed the account is create-only (403
  on search/delete); confirmed agent's `basicConfig` fix against a control
  case. [PR #194](https://github.com/voltron-1/Suburban_SOC/pull/194) merged
  (rebased cleanly onto #183's fix first); issue closed.
- [x] **#183** — `weasyprint==68.0` CVE (CVE-2026-49452, CSS injection via
  presentational hints), surfaced by `pip-audit` failing on #171's PR (that
  job scans the whole `requirements.txt`, not just the diff — the failure was
  pre-existing, unrelated to #171 itself). Verified per-release against
  PyPI's advisory data that 68.1 *still* carries the CVE — only 69.0 is
  clear; confirmed no breaking-API impact on `weekly_ciso_report.py`'s only
  call site. Live-verified: rendered a real PDF via a fresh venv and again
  inside the rebuilt `soc_ai_agent` container.
  [PR #195](https://github.com/voltron-1/Suburban_SOC/pull/195) merged;
  issue closed.

- [x] **#192** (unplanned, detection-engineering coverage review, filed
  2026-07-09 — separate from the #164-#190 structural review) — collected
  Windows Security/System events had no alert rules (4625/4648/4672/4732),
  and key channels weren't collected at all (Security 1102, System 104/7040/
  7045, WMI-Activity 5861, PowerShell 4103/4104). Added 12 new Sigma rules +
  3 Elastic threshold-rule companions (count/cardinality logic the Sigma
  fixture evaluator and lucene conversion can't express), new logsource-
  conditioned ECS field mappings, `winlogbeat.yml` channel collection,
  `test_threshold_rules.py`, coverage matrix regenerated (24 → 36 rows).
  [PR #193](https://github.com/voltron-1/Suburban_SOC/pull/193) merged;
  issue closed.

- [x] **#164** — Broker: unvalidated `attacker_ip` reached the `nft`/SSH command
  sink (SI-10/PR.PS-06). [PR #178](https://github.com/voltron-1/Suburban_SOC/pull/178) merged; issue closed.
- [x] **#165** — SLO metrics & threat hunts silently swallowed ES errors as false
  negatives (SI-11). [PR #179](https://github.com/voltron-1/Suburban_SOC/pull/179)
  merged; issue closed. 20 new tests, all passing. Deferred `agent_app.py:696`
  (audit-write visibility) to a follow-up — filed as #184.
- [x] **#166** — Bash admin tooling skipped TLS verification (`curl -k`) while
  sending ES credentials (SC-8). [PR #180](https://github.com/voltron-1/Suburban_SOC/pull/180) merged; issue closed.
  Operator note: host scripts relying on the old implicit `-k` fallback now
  need `ES_CA=<path>` or `ES_INSECURE=true`.
- [x] **#167** — Unhardened systemd units + `elastic` superuser default in host
  automation (AC-6, CM-7). [PR #181](https://github.com/voltron-1/Suburban_SOC/pull/181)
  merged; issue closed. New least-privilege `slo_metrics_reader` ES role +
  `slo_metrics` user, live-created and verified end-to-end — holding.
  `zeek-host-capture.service` sandboxing was deployed, broke live capture in
  production (crash-loop), and was reverted same-day — root cause was the
  WSL2 `eth0` interface being administratively down, unrelated to the
  hardening itself, but the unit currently runs unsandboxed. Follow-up #182
  covers re-attempting it safely. `es_common.sh`'s shared `elastic` default
  deliberately left alone (~15 other legitimate admin-tooling consumers
  depend on it).
- [x] **#185** (unplanned, discovered this session) — `deploy_detections.sh`
  silently no-op'd on every run since its introduction (#93, 2026-06-12):
  competing `< "$RAW"` / `<<'PY'` stdin redirects meant the transformed rule
  payload was always empty, and Kibana's import API returns `success:true`
  for an empty file — a silent false-positive (CM-3, SI-11). Surfaced while
  investigating shellcheck findings for #168. Fixed via `RAW_PATH` env var +
  explicit `open()`; verified with synthetic + realistic-data transform
  tests. [PR #186](https://github.com/voltron-1/Suburban_SOC/pull/186)
  merged; issue closed.
- [x] **#168** — CI had no linter and functional tests were path-filtered
  (SA-11/CM-3). New always-on `.github/workflows/lint.yml` (shellcheck, ruff,
  mypy, yamllint); `soar-tests.yml`/`detections.yml` path filters removed
  entirely. Fixed all findings surfaced (2 real shellcheck unused-vars, 3
  ruff, 8 mypy — 2 of which were genuine latent type-signature/behavior
  mismatches, not just stub pickiness) rather than suppressing. Along the way
  found a real shellcheck directive-scoping gotcha (a `disable=` comment
  before a `cmd1; cmd2; cmd3` chain only covers `cmd1`). Explicitly deferred:
  required branch-protection status checks (repo-settings change, needs
  separate explicit sign-off). Real CI confirmed: ruff/mypy/yamllint pass;
  `soar-tests`/`detections` now actually run and pass (previously would have
  been skipped). Branch `remediation/p2-issue-168-nist` (commit `1e7c0f4`).
  [PR #187](https://github.com/voltron-1/Suburban_SOC/pull/187) merged;
  issue closed.
- [x] **#169** — Logstash pipeline had no dead-letter queue and no grok
  parse-failure test coverage (SC-24). New `configs/logstash.yml`
  (`queue.type: persisted`, `dead_letter_queue.enable: true`), output split
  routing parse failures to a `logstash-security-quarantine-*` index, new
  `dq-quarantine` dashboard panel, 14 new grok/JSON parse-failure tests.
  Branch `remediation/p2-issue-169-nist`.
  [PR #188](https://github.com/voltron-1/Suburban_SOC/pull/188) merged;
  issue closed.
- [x] **#170** — ES client/credential consolidation (#156/#157) incomplete; no
  connection reuse or retry (CM-2). Branch `remediation/p2-issue-170-nist`.
  New `scripts/setup/lib/es_client.py` (`requests.Session` + `urllib3.Retry`;
  `read=0` deliberately — never auto-retry a write after a read-timeout, only
  pre-send connection failures and explicit 502/503/504);
  `slo_metrics.py`/`run_hunts.py` migrated onto it. `weekly_ciso_report.py`/
  `verify_detections.py` (elasticsearch-py, not raw requests — one uses
  `api_key` auth) got `retry_on_timeout=True, max_retries=3` added natively
  instead. `es_common.sh`'s `es()`/`es_code()` now set `--max-time
  "${ES_CURL_TIMEOUT:-60}"` (previously unset on all 19 sourcing scripts).
  Live-verified against the running stack: `slo_metrics.py`, `run_hunts.py`,
  `refresh_intel.sh` (bulk index under the new 60s cap), `stack_health.sh`
  (its own `-m 6` override still wins). 26 unit tests, all green. Several
  items in the original issue evidence turned out stale on fresh inspection
  and were deliberately left untouched — see the PR description for the
  full list (redundant-looking `ES_PASS` derivation in
  `refresh_intel.sh`/`deploy_changelog.sh` is an intentional best-effort-ES
  gate, not a bug; the `logstash_writer` role "duplication" in
  `docker-compose.yml` is a documented two-phase bootstrap, not drift).
  Two new findings surfaced and filed separately rather than folded in:
  [#189](https://github.com/voltron-1/Suburban_SOC/issues/189)
  (`soc_pipeline.sh` health checks probe `http://` against the TLS-only
  stack — always fail) and
  [#190](https://github.com/voltron-1/Suburban_SOC/issues/190)
  (`reindex-existing.sh`'s local `es()` override recurses infinitely
  through `esj()` — script is currently non-functional).
  [PR #191](https://github.com/voltron-1/Suburban_SOC/pull/191) merged;
  issue closed.

#182 remains DEFERRED (see DEFERRED section — needs an interactive-sudo
terminal session). All other structural-review follow-ups (#184, #189, #190)
plus the new Area 1-5 compliance wave (#204-#208) are now sequenced by the
Phase A-H plan above; [Project Board #17](https://github.com/users/voltron-1/projects/17)
continues to track everything.

Phase H (agent orchestration refactor) — **COMPLETE via `2bb3d8f`,
2026-07-20** — refactored the monolithic `handle_kibana_webhook()` in
`scripts/setup/ai_agent/agent_app.py` into an explicit `Agent` class with a
two-phase Perceive→Think→Act→Check loop, ES-backed checkpoints, and retry
logic. **Component 4's atomic-claim carryover requirement
("Retain ... `_queue_lock` atomic claim") was dropped during the refactor —
this is the regression M12/#214 fixes; see NEXT UP.** All components below
are implemented in code; checked off with that one caveat noted inline.

  Component 1 — Agent Core (`agent.py`):
  - [x] `Agent` class with `run()` (Phase 1) and `execute_approved()` (Phase 2)
  - [x] `perceive()` — parse, validate, sanitise inputs, open Kibana case
  - [x] `think()` — LLM triage with retry + circuit breaker
  - [x] `act()` — §12.3/§12.4 decision gate: DRAFTED (default), EXECUTED
        (autonomous only), or NO_ACTION (excluded asset)
  - [x] `check()` — verify outcome, set terminal state (PENDING_APPROVAL,
        EXECUTED, or CLOSED — not ESCALATED, removed by #247: a confirmed
        execution failure now reverts to PENDING_APPROVAL so a retry is
        possible, rather than dead-ending in a state nothing ever leaves)
  - [x] `execute_approved()` — Phase 2 entry point: Act(execute) → Check(verify)
  - [x] `AlertContext` frozen dataclass — typed, immutable between phases
  - [x] `AgentResult` dataclass — status code + serialisable response

  Component 2 — Checkpoint Store (`checkpoints.py`):
  - [x] `write_checkpoint()` — upsert phase transition to `agent-checkpoints`
        ES index, keyed by alert_id
  - [x] `read_checkpoint()` — load latest checkpoint for crash resume
  - [x] `is_duplicate()` — idempotency gate (terminal phase = reject)
  - [x] `is_awaiting_approval()` — validates PENDING_APPROVAL state for
        Phase 2 entry

  Component 3 — Retry Logic (`retry.py`):
  - [x] `@retry` decorator — exponential backoff on transient failures
  - [x] Apply to `analyze_alert_with_ai()` (LLM call — 3× retry)
  - [x] Apply to `dispatch_block_via_broker()` (broker call — 3× retry)
  - [x] Non-transient errors (4xx) do NOT retry

  Component 4 — Refactor `agent_app.py` (MODIFY):
  - [x] `/alert` → thin shell delegating to `Agent.run()` (Phase 1)
  - [x] `/approve` → delegate post-claim execution to
        `Agent.execute_approved()` (Phase 2)
  - [!] Retain HMAC auth, `_queue_lock` atomic claim, JSONL queue — **HMAC and
        JSONL queue retained; the atomic claim was NOT carried over. Fixed by
        M12/#214** (ES create-if-absent claim, not the old lock — see that
        issue for why).
  - [x] Move input parsing, LLM call, exclusion check, isolation/draft logic,
        SOAR logging, case management into `agent.py`

  Component 5 — Tests (`test_agent.py`):
  - [x] Phase 1 tests: perceive validates inputs, think retries on timeout,
        think does not retry on 4xx, act drafts by default, act respects
        exclusion list, checkpoint resume, duplicate alert idempotent
  - [x] Phase 2 tests: execute_approved calls broker, escalates on failure,
        rejects wrong state, loads checkpoint from ES
  - [x] Human gate integrity: `run()` with `AUTONOMOUS_ISOLATION=false` never
        calls `dispatch_block_via_broker()`; no code path from `run()` to
        `execute_approved()`

  Component 6 — ES Index Template (`agent-checkpoints-template.json`):
  - [x] Index template for `agent-checkpoints` (30-day ILM retention)
  - [x] Fields: `alert_id`, `phase`, `context` (JSON), `@timestamp`,
        `tenant.id`
  - [x] Deploy to `configs/` following existing `soar-actions-*` template pattern

  Resolved Architecture Decisions:
  - Alert ID sourcing: uses a Semantic Deduplication Key (hash of tenant+IP+severity+5m_bucket)
  - Check-phase depth: uses Hybrid Asynchronous approach (Agent fast-returns EXECUTED, slo_metrics.py cron runs the 60s active ES verification)

---

## LAST SESSION — 2026-08-07

- **M13 US6 (#229) and US7 (#230) both built end-to-end this session**,
  back to back per explicit instruction (keep building through #244
  without waiting for individual merge sign-off, but review/merge itself
  is reserved for the repo owner — do not merge any of these PRs
  automatically on green CI). US6: plan written, prerequisite winlogbeat/
  pySigma fixes, 10 rules, 2 review rounds, [PR #298](https://github.com/voltron-1/Suburban_SOC/pull/298).
  US7: 5 rules, the corpus's first Linux-telemetry batch and first `text`-
  field-based detection mechanism, 2 review rounds finding 3 HIGH issues
  (two in already-shipped pipeline infra this batch made load-bearing),
  [PR #300](https://github.com/voltron-1/Suburban_SOC/pull/300). Both real
  defect-finding rounds, not style nits — see NEXT UP for detail on each.
  4 more follow-up issues filed this session (#295-#297, #299). Both PRs
  open, CI running, neither merged — stopping here since #244 (the next
  item) needs both actually merged into `main` first, a hard dependency
  (it operates on the complete rule set).

## LAST SESSION — 2026-08-06

- **M13 US5 (#228) built end-to-end this session**, after the housekeeping
  below. Plan written (`plans/20260806-m13-us5-zeek-network-detection.md`),
  prerequisite Zeek/Logstash/pySigma field-mapping fixes implemented and
  reviewed (2 rounds), then all 15 rules written, reviewed (2 more rounds),
  fixed, and pushed as [PR #294](https://github.com/voltron-1/Suburban_SOC/pull/294) —
  see NEXT UP for the full defect list the reviews caught (OpenSSL 3.x
  string drift, a wrong sensor-placement assumption, an order-of-magnitude
  threshold error, a regex bypass, a factually-wrong design rationale — all
  fixed, not just flagged). 8 follow-up issues filed (#286-#293) for what's
  genuinely out of scope. Merged 2026-08-06 on explicit go-ahead (`988eb2c`,
  12/12 CI green including live-fire against a real cluster); #237-#240 and
  #228 closed manually afterward (see NEXT UP).
- **Housekeeping, start of session.** This file's NEXT UP was stale (still
  showing M13 US2/#232 as next-unstarted) despite US2 (PR #282), US3 (PR
  #284), and US4 (PR #285) all having merged since. Refreshed NEXT UP with
  all three phases marked done + evidence links, and closed the three
  umbrella issues (#225, #226, #227) manually — same not-auto-closed shape
  as #247: their PRs used "Part of #NNN" rather than "Closes #NNN".
  Confirmed via `gh api .../milestones` (M13: 15 open / 10 closed at
  session start) and `gh api .../issues?milestone=17` rather than trusting
  the file. Local `main` was also 1 commit behind `origin/main` (US4's
  squash-merge, PR #285) — fast-forwarded before editing this file.

## LAST SESSION — 2026-08-05 (later)

- **M12 CLOSED, 14/14.** #273 merged (PR #280, 16/16 green), #213 closed with the
  full arc summarised. One residual risk is documented rather than closed: the
  broker's `/approve` and `/webhook/dispatch` share a single `HIVE_MIND_SECRET`,
  so approver forgery is narrowed from an arbitrary string to one of two labels
  selected by URL — not proof that a human acted. The docstring, compose comment
  and `.env.example` now state that limit instead of overclaiming. Closing it
  needs a second broker credential mirroring #246's split.
- **Triaged the 13 unmilestoned issues into M14/M15/M16** (see MILESTONE BACKLOG
  above). Every one was a review follow-up that had accumulated with no
  milestone — invisible to any milestone-based view of the work. Two are P0
  defects in already-shipped code, not new features: #275 (#184's metric has
  never functioned in production) and #277 (forgeable containment outcome).
  README, wiki Home, and project board #17 all updated to match; the wiki's
  Project Status also had a garbled M11 entry from a bad paste, repaired.
- **#247 closed** — PR #279 merged to `main` (`ef96b61`). Closed manually, since
  the PR body had no closing keyword and the merge therefore didn't auto-close
  it. Worth remembering as a recurring trap: this is the second M12 issue
  (#224 was the first) left orphaned-open by a PR that referenced it without
  the keyword.
- **#273 implemented and reviewed** — see NEXT UP. PR #280, 16/16 green,
  awaiting merge sign-off.
- **Project board #17 was materially stale and has been reconciled.** 23 issues
  were absent from it entirely — 14 open (including M12's own #273) and 9
  closed historical ones. Everything already on the board had a correct Status,
  so the drift was pure absence rather than mislabeling. All 14 open issues
  added; #247 moved out of Backlog (it had a green PR at the time). The 9
  closed historical issues were deliberately left off — adding them would pad
  the Done column with no tracking value.
- Two things found that are nobody's assigned scope yet:
  `tests/ai_agent/test_slo_metrics.py` has **3 failures on `main`**
  (`MainExitCodeTests` — exit code 2 instead of 0), confirmed pre-existing and
  unrelated to any branch work; CI's coverage job passes, so it looks
  environment-dependent. And `plans/2026-06-28-147-remaining-evidence.md` was
  found deleted in the working tree by something outside this session
  (restored; it is tracked, 12,982 bytes since `04f35e1`) alongside an
  untracked `plans/20260805-fork-security-onion-migration.md` and a `.gemini/`
  directory — the same signature as the uncoordinated external tool that
  created M13 on 2026-08-01.

## LAST SESSION — 2026-08-05

- Closed **#246** (priority:critical) — split `/approve`+`/pending`'s HMAC
  credential from `/alert`'s. [PR #274](https://github.com/voltron-1/Suburban_SOC/pull/274)
  merged. See NEXT UP for full detail (findings, fixes, follow-up #273).
  M12 now has exactly one open issue left: #247.

---

## LAST SESSION — 2026-08-04

- Executed M12 Phases 1-3 (#215, #216, #217, #218, #219) unattended per
  standing user authorization, pausing before #220 as instructed to present
  a consolidated review. Each issue got its own branch/PR, `security-auditor`
  + `code-reviewer` in parallel per standing rules, and independent
  verification of every subagent finding before acting on it (never took a
  "looks fixed" claim at face value).
- **#218 turned out to be invalid.** The issue's own evidence citation
  (`evidence/README.md:23`) was traced back to its source during
  implementation and found to describe the deliberately-run A.1 port-scan
  simulation, not organic router chatter as both the plan doc and the issue
  had transcribed it. Implementing the fix as scoped would have suppressed
  the repo's only verified real-telemetry T1046 detection. Closed with the
  evidence citation, branch deleted, `plans/20260801-...` and this file
  corrected in the same commit (`e6e309d`, pushed directly to `main` — docs
  bookkeeping, not code, consistent with this file's own auto-update rule).
- **#219's own verification method turned out to be wrong**, caught by
  re-testing rather than trusting the first live result: a certless TLS
  handshake against the Beats input completes cleanly from the *client's*
  side under TLS 1.3 regardless of whether the server ends up rejecting it a
  moment later, so the original `openssl s_client`-output-based check (and
  the pre-existing `verify_encryption.sh` check it was modeled on) wasn't
  proof of anything. Fixed by checking Logstash's own log output instead —
  reproduced the exact `SSLHandshakeException: certificate_required`
  rejection live, both before and after comparison.
- Mid-session infra incident: a `docker restart` (approved, to pick up the
  #219 config change) hit a stale WSL bind-mount and killed the running
  Logstash container; the documented recovery
  ([[ingest-pipeline-restart-recovery]]) itself turned out to be blocked by
  an unrelated `docker compose` v5.1.0 incompatibility with this file's
  `$$` password-escaping (likely a Compose version bump during an earlier
  Docker Desktop restart this same session). `docker desktop restart` then
  failed too (missing backend binary). User restarted Docker Desktop
  manually; `docker compose` remained broken afterward (confirmed a Compose
  file issue, not a Desktop backend issue) — recovered by reconstructing the
  `logstash` container directly via `docker run` (secrets via a short-lived
  0600 env file, not the command line) after explicit user approval.
  **`docker compose` itself is still broken for this repo** — worth a
  dedicated fix before the next person needs to bring the stack up the
  normal way.
- All four PRs — [#260](https://github.com/voltron-1/Suburban_SOC/pull/260)
  (#216), [#262](https://github.com/voltron-1/Suburban_SOC/pull/262)
  (#215), [#264](https://github.com/voltron-1/Suburban_SOC/pull/264)
  (#217), [#266](https://github.com/voltron-1/Suburban_SOC/pull/266)
  (#219) — went fully green on CI and were merged on explicit user
  go-ahead ("Merge all four PRs", same standing review-bypass confirmation
  pattern). User merged them directly (the `gh pr merge` action was blocked
  by the local auto-mode permission classifier); confirmed via `gh pr list`
  rather than assumed, since the user's own phrasing suggested they thought
  only one had merged.
- Two follow-up issues filed for gaps found but out of scope for the issue
  being worked: [#263](https://github.com/voltron-1/Suburban_SOC/issues/263)
  (`ignore_above:8191` payload-length bypass on both PowerShell rules,
  pipeline-wide/pre-existing), [#265](https://github.com/voltron-1/Suburban_SOC/issues/265)
  (Winlogbeat/endpoint-Filebeat need client certs before real endpoint
  onboarding, harmless today since none is deployed).

## LAST SESSION — 2026-08-03

- User asked why CI was still failing on the two PRs left open from the prior
  session (#251, #254). Root cause: both branches were cut from `main`
  *before* that session's ruff-pin (#255) and approval-gate (#248) fixes
  landed, so their CI runs were stale snapshots of the same two
  already-diagnosed pre-existing failures — confirmed directly via
  `git merge-base --is-ancestor` rather than assumed. Updated both branches
  (`git merge origin/main`), both went 15/15 clean, no bypass needed.
- Merged both on explicit go-ahead (same standing review-bypass confirmation
  as every other self-authored PR this cycle — asked directly since sub-agent
  review isn't a substitute). [PR #251](https://github.com/voltron-1/Suburban_SOC/pull/251)
  merged, closing #231 automatically; #224 (its parent user story) didn't
  auto-close since the PR body only referenced #231, so closed manually with
  evidence. [PR #254](https://github.com/voltron-1/Suburban_SOC/pull/254)
  merged (no tracked issue). Branches deleted on merge; local stale branches
  and remote-tracking refs pruned after.

## LAST SESSION — 2026-08-02 (later)

- Docker Desktop's WSL2 integration with Ubuntu crashed mid-session ("the
  pipe is being closed" on the Windows host) — root-caused via systematic
  debugging rather than just clicking retry blind: Docker Desktop's own
  processes had just (re)started ~90s before the Ubuntu distro finished
  booting, so its integration health probe raced the distro's interop pipe
  coming up. Ruled out sleep/resume, OOM, and disk/memory pressure with
  evidence first. Confirmed healthy on retry; this is what finally unblocked
  live-verifying #253 (see below) after last session's Docker-unavailable
  blocker.
- **#253 (#249/#250 process.args mapping) fully live-verified and merged.**
  Delegated to `tester-debugger` for the live-cluster checks (template PUT,
  installed-mapping GET, synthetic mixed-case/long-value behavioral tests —
  see the M13 entry above for detail), then executed the previously-deferred
  data-stream rollover myself on explicit go-ahead (`POST .../_rollover` ×6,
  gated behind the Claude Code auto-mode classifier as a live-mutation
  action — re-ran once with auto-mode off to get the interactive prompt).
  Verified each new write index's mapping directly rather than trusting the
  rollover response alone. Issue #250 closed with the evidence cited above
  (#249 had auto-closed via #253's merge; #250 hadn't, so closed manually).
- Separately, debugged an unrelated user-reported issue: `soc_pipeline.sh`'s
  prereq checks warned "Elasticsearch/Kibana not reachable" despite the
  stack being fully healthy. Root cause: `ES_CA` defaulted to
  `/certs/ca/ca.crt`, a container-only path (named Docker volume, not
  host-mounted) — every host-side `--cacert` curl call failed with curl exit
  77, silenced by `&>/dev/null`, and misreported a healthy stack as down, at
  5 call sites across 2 functions. New `resolve_es_ca()` reuses SOP-003's
  already-provisioned `/etc/filebeat/certs/ca.crt` or self-provisions via
  `docker cp` (established repo idiom, also used by
  `configs/systemd/slo-metrics.service`). `security-auditor` (0
  CRITICAL/HIGH/MEDIUM, 2 LOW on the new self-provisioning path — both
  hardened: symlink-safe extraction, cert-content validation) +
  `code-reviewer` (1 Should-Fix — re-resolve after `run_sop_005`'s "ELK is
  running" prompt so a cold start doesn't latch a stale failure — applied) +
  `tester-debugger` (live-verified all scenarios pass) ran in parallel per
  this repo's standing rule. [PR
  #254](https://github.com/voltron-1/Suburban_SOC/pull/254) open, not yet
  merged — no tracked issue for this, discovered and fixed ad hoc within the
  session at the user's direct request.
- Merging #253 surfaced a genuine circular CI dependency between two
  infra-only fixes, both required-status-check blockers: `ruff (python)`
  fails on every PR because `pip install ruff` in `lint.yml` was unpinned
  and had drifted to 0.16.x, which newly enables rule `UP045` and flags 144
  pre-existing, unrelated findings repo-wide (traced to the exact CI log
  diff before concluding this, not assumed); `SOAR auth / exclusion /
  approval / tenant-scoping` fails on every PR still based on pre-#248
  `main` because of the relative-import bug #214's session already
  diagnosed. Each fix's own PR branch was blocked by the *other* fix's
  absence. Broke the cycle with exactly one admin-privileged bypass — on
  [PR #255](https://github.com/voltron-1/Suburban_SOC/pull/255) (the ruff
  pin itself, 1 unrelated required check failing) — chosen deliberately
  over bypassing either substantive PR, presented to the user as an
  explicit tradeoff before acting. After #255 merged, updated #248's and
  #253's branches with the fix (`git merge origin/main`) and both then
  merged **cleanly, 15/15 checks, zero further bypasses**. Branches deleted
  on merge for all three (#255, #248, #253).

## LAST SESSION — 2026-08-02

- User asked to update the README, wiki, and project board "if the repo and
  project board are current." Checked rather than assumed: `main` was in
  sync with origin and PR #248 was correctly tracked, so pushed the
  README fixes (stale `sterlinggarnett` repo owner in the milestones link,
  M11 shown as still-in-progress, M12 missing entirely, a stale Sigma-rule
  claim already disproven this session) and mirrored the same fixes into
  the GitHub wiki (`Home.md` had a garbled, duplicated M11 status line from
  a prior bad edit). Moved `#213` to "In progress" on the board to match
  reality.
- User then said "if the repo and project board are current move to m13."
  Checked again rather than assuming the prior check still held — it
  didn't fully: M13's 22 issues (from the Antigravity incident earlier
  this session) existed on GitHub but were **entirely absent** from
  Project Board #17, and all 14 parent-child links had silently failed
  (the seeding script used `--add-parent`, not a real `gh issue edit`
  flag). Fixed both before treating the condition as met.
- Implemented M13 US1 (10 Windows LOLBin/execution Sigma rules, issue
  #231) as its own gated phase, TDD throughout. `security-auditor` +
  `code-reviewer` ran in parallel before commit per this repo's standing
  rule — the security review's verdict on the first draft: **"0 of 10
  rules are solid as written."** Fixed all of it (not left as caveats):
  one rule matched a command line Windows Script Host cannot execute
  (zero real detection value while still scoring green in the coverage
  matrix); two required flags together that the real technique uses
  independently, missing the canonical form entirely; one matched the
  single most common *legitimate* invocation of its own target binary.
  [PR #251](https://github.com/voltron-1/Suburban_SOC/pull/251),
  `feat/213-m13-us1-windows-lolbin`. CI: `detections` passes; the only
  failures are the same two pre-existing, unrelated issues already on
  PR #248 (main's broken relative import, ruff version drift).
- That review also surfaced two corpus-wide findings unrelated to the 10
  new rules specifically: `process.args` (and related fields) map to
  plain `keyword`/`ignore_above:1024`/no normalizer, meaning Sigma's
  lowercase literals may not match real mixed-case telemetry at all
  (#249), and any command line over 1024 characters is silently
  un-indexed (#250) — both affecting **all 45 pre-existing rules**, not
  just the new batch. Fixed via [PR
  #253](https://github.com/voltron-1/Suburban_SOC/pull/253),
  `fix/249-250-process-args-mapping`. This one took **two**
  `security-auditor` passes: the first fix (switch the field to
  Elasticsearch's `wildcard` type + a lowercase normalizer) was reviewed
  and found likely broken — `normalizer` almost certainly isn't a valid
  parameter on a `wildcard`-mapped field, so the template PUT would 400
  and get silently discarded; and if somehow accepted, the `wildcard`
  type's query-verification is case-sensitive against the raw doc value
  regardless of the normalizer, which would have caused **total** false
  negatives on every mixed-case rule literal in the corpus — a strictly
  worse outcome than the bug being fixed. Caught before committing,
  corrected to `keyword` + normalizer + `ignore_above: 8191`, re-reviewed
  clean. Also fixed in the same PR: `apply-templates.sh` printed each
  template PUT's HTTP status but never checked it (curl treats a 400 as
  "success") — exactly the mechanism that would have let the wrong first
  draft ship undetected. Filed
  [#252](https://github.com/voltron-1/Suburban_SOC/issues/252) for a
  narrower, related finding the second review pass caught
  (`ScriptBlockText`'s real chunk size may still exceed the new 8191
  ceiling). **Cannot be live-verified in this environment** — Docker/an
  Elasticsearch daemon is not reachable here (checked: no
  `/var/run/docker.sock`, no `docker.service` unit, no `dockerd` binary —
  most likely gated behind Docker Desktop's WSL2 integration on the
  Windows host, which has to be started from outside this session).
- Lesson reinforced from this session's earlier Antigravity incident and
  M12 work, now repeated on the SAME turn with the SAME pattern: a fix
  that "looks right" for an infrastructure/config change needs the same
  adversarial review as application code, especially when it cannot be
  live-verified — the first `process.args` mapping draft would have
  shipped a plausible-looking but backwards fix had the review not caught
  it before commit.
- Neither PR merged — same standing rule as #248 (sub-agent review alone
  doesn't authorize a merge). Board updated: `#213`, `#214`, `#224`,
  `#231`, `#249`, `#250`, `#252` all reflect "In progress."

---

## LAST SESSION — 2026-08-01

- Reviewed a pasted detection-capability evaluation (signature/behavioral
  detection, Sigma quality, alert tuning, platform features). Fact-checked
  every claim against the repo via three parallel Explore agents before
  planning — about a third of the evaluation's items turned out already
  implemented (webhook replay protection, non-root containers), factually
  wrong (Sigma field-name consistency claim), or re-proposing a design
  already evaluated and approved elsewhere (Suricata integration, per
  `docs/detections/suricata-evaluation.md`'s existing "adopt as follow-up"
  decision).
- Verifying the evaluation's weakest item (SOAR action dedup) surfaced a live
  regression instead: commit `2bb3d8f` (2026-07-20, Phase H merge) silently
  dropped the atomic approval-gate claim #172 had added, reopening a
  double-execution race on `/approve` (network isolation). Confirmed via
  direct diff inspection (`_queue_lock` 6→0 across that commit) rather than
  taking a subagent's report at face value. The uncommitted working tree at
  session start made it worse (silent ES-write failures, an unbounded replay
  fallback) — also found and root-caused, not just described.
- User pushed back on an initial framing that the resulting plan only
  "improves or completes" the evaluation with no downside — correct
  challenge. Re-verified two items under that scrutiny and found real
  problems: the top-ranked Sigma FP fix (`-enc` rule) may be exactly
  backwards depending on whether `process.args` is tokenized (unverified);
  and Phase 0's fail-closed design, applied uniformly, would have made ES
  outages drop alerts at intake, not just block approval. Both corrected in
  the plan before filing issues. Lesson: verify triage claims when
  challenged, don't just restate confidence.
- Wrote the approved plan to
  [`plans/20260801-approval-gate-integrity-detection-tuning.md`](plans/20260801-approval-gate-integrity-detection-tuning.md).
  Filed [Milestone M12](https://github.com/voltron-1/Suburban_SOC/milestone/16),
  umbrella user story [#213](https://github.com/voltron-1/Suburban_SOC/issues/213),
  and 9 child issues (#214-#222) as GitHub sub-issues of #213, with #217
  (Sigma tuning) formally `blocked-by` #216 (the prerequisite alert-volume
  metric) via `gh issue create --blocked-by`. All 10 added to
  [Project Board #17](https://github.com/users/voltron-1/projects/17).
- This file's NEXT UP was stale (last touched 2026-07-16, still showing
  Phase B as next-unstarted) despite PRs #209-#211 having merged Phases B-E
  and Phase H being fully implemented in code. Refreshed NEXT UP and the
  Phase H component checklist to match reality, and folded the prior
  milestone's detail into a collapsed `<details>` block rather than deleting
  it.
- Per the multi-phase execution gating rule, stopped after issue creation to
  report before starting Phase 0 implementation — did not commit/push this
  file yet, pending go-ahead.
- User approved committing the docs prep and starting Phase 0. Pushed the
  M12 plan doc + refreshed NEXT UP directly to `main` (docs-only, matches
  this file's own established direct-push convention).
- **Incident, caught before it caused damage:** during Phase 0 verification,
  discovered `docs/detections/SIEM_KQL_Documentation.md` had been silently
  overwritten — every rule's real Lucene query replaced with a literal
  `(display this help summary)` placeholder. Traced by file mtime to the
  window when three parallel verification `Explore` agents were running;
  `Explore` is meant to be read-only but retains Bash access, and something
  run there mutated the file. Restored from HEAD. Separately, found an
  **unrelated, uncoordinated actor active on the same repo**:
  `~/.gemini/antigravity-cli` (Google's Antigravity/Gemini CLI) had, in the
  same session window, (a) created **Milestone M13** "Detection Expansion:
  35 → 105 Sigma Rules" with **22 real GitHub issues** (#223-#244,
  completely unrelated to M12), and (b) rewritten
  `agent.py`/`agent_app.py`/`checkpoints.py`/`test_agent.py` in the working
  tree with a *different and worse* attempt at the same approval-gate
  problem — 200ms ES timeouts, a permanently-sticky broken circuit breaker,
  blanket exception swallowing, and tests weakened (`assert status_code ==
  409` loosened to `in (404, 409, 500)`) rather than fixed. User confirmed:
  discard Antigravity's edits to those 4 files and implement Phase 0
  cleanly (done — `git checkout` to HEAD, then rebuilt from the approved
  design); leave M13 alone entirely (not touched, not investigated further).
- Implementing Phase 0 surfaced three escalating discoveries beyond the
  atomic-claim fix itself, each verified empirically before acting on it
  (TDD throughout — RED confirmed before every GREEN):
  1. `agent.py:16`'s `from .checkpoints import ...` is a relative import
     that breaks under this repo's `pythonpath`-based test setup — the
     entire `ai_agent` test suite (0 tests) had been failing to even
     *collect* on `main` since `2bb3d8f`. Fixed to an absolute import,
     matching the sibling `from retry import retry` line beside it.
  2. With collection fixed, 45 of 83 tests failed for real: Phase H moved
     nearly everything out of `agent_app.py` into `agent.py` without
     updating the pre-existing `test_alert_auth.py`/`test_notify_masking.py`,
     which still patched attributes directly on `agent_app` (e.g.
     `agent_app._seen_sigs`, `agent_app.create_case`) that no longer live
     there. Retargeted mechanically to `agent.X` (except the Flask `app`
     object itself, which correctly stays on `agent_app`).
  3. Deeper still: Phase H had silently changed the *external API contract*
     — `/alert`'s status vocabulary (`"pending_approval"` instead of the
     established `"drafted"`; `"no_action"` instead of
     `"no_action_protected_asset"`; `"executed"`/`"escalated"` reused for
     both the autonomous and approved paths instead of distinct
     `"auto_isolated"`/`"isolation_failed"`), `/pending`'s response key
     (`"actions"` instead of `"pending"`), and `/approve`'s request body key
     (`"action_id"` instead of `"id"`). Resolved by evidence, not
     assumption: the old vocabulary is verified live in
     `evidence/README.md` (a real, checksummed Kibana screenshot) and
     hard-checked by `tests/anomaly_simulation/section_a_evidence.sh`; the
     `"pending"`/`"id"` keys are independently confirmed by
     `scripts/hive-mind-broker`'s own, completely separate test suite.
     Restored the evidence-backed contract in the code rather than
     rewriting the tests to match Phase H's drift. One exception, flagged
     explicitly rather than silently changed: `test_approve_twice_...`'s
     expected re-approval status moved 404→409, since the *pre-existing*
     `execute_approved()` (verified via `git show HEAD`) already returned
     409 before this session touched it — the old test's 404 was already
     stale relative to its own target, not something this session weakened.
  4. Fixing the context-loss bug (`write_checkpoint` is a full ES document
     PUT, not a merge — a checkpoint transition that omitted `context`
     silently wiped whatever a prior transition had stored) also fixed a
     latent bug where `execute_approved()`'s response never carried
     `case_id`, and added the missing case-closing call on human-approved
     execution (previously only the autonomous path closed the Kibana
     case).
- Delegated to `security-auditor` + `code-reviewer` in parallel per this
  repo's standing rule. `code-reviewer`: "Approve with conditions," one
  Should-Fix (two new `_append_pending_action` calls in `execute_approved`
  were unguarded — fixed with a `_append_pending_action_or_warn` helper,
  and reordered so the audit row for a won claim is written unconditionally
  before any further validation can short-circuit). `security-auditor`:
  0 CRITICAL, 3 HIGH, 4 MEDIUM, 1 LOW, 1 INFO — the atomic-claim mechanism
  itself confirmed sound with no bypass, but three HIGH findings about the
  *environment* the fix assumes exists (ES role/data-stream mismatch;
  shared HMAC secret; see #245/#246 above). Fixed in-branch: an unguarded
  `is_duplicate()` read that defeated the diff's own stated intake-leniency
  design; missing request timeouts on all three `checkpoints.py` ES calls;
  unvalidated `alert_id` reaching ES REST paths (added format validation at
  the HTTP boundary in `agent_app.py`, not deep in `checkpoints.py`, so
  existing unit tests using short synthetic ids didn't need rewriting);
  `tenant_id` now pinned the same way `alert_id` already was, with a
  mismatch treated as a tamper signal rather than silently trusted.
- 140/140 tests passing (whole repo, one unrelated pre-existing local `.env`
  parsing issue excluded), ruff/mypy clean locally. Opened
  [PR #248](https://github.com/voltron-1/Suburban_SOC/pull/248) on
  `fix/214-approval-gate-atomic-claim` rather than pushing directly —
  necessary, not just cautious: `soar-tests.yml`/`detections.yml`/
  `reporting-coverage.yml` only trigger on `pull_request`, which is
  exactly how `2bb3d8f` shipped this session's entire chain of regressions
  undetected. CI on the PR: 14/15 pass, including `SOAR auth / exclusion /
  approval / tenant-scoping` and `detections` — first run of either against
  this code since `2bb3d8f`. The one failure (`ruff`) is unrelated,
  pre-existing, repo-wide version drift (see NEXT UP).
- Per this repo's merge-review-bypass convention, did not merge the PR —
  automated sub-agent review (`security-auditor` + `code-reviewer`) is not
  a substitute for the explicit human confirmation merging requires.

## LAST SESSION — 2026-07-16

- Planning session (Fable 5, read-only until approval): inventoried all 9 open
  issues plus the uncommitted working tree, which turned out to be a
  deliberate 2026-07-15 bulk port seeding a new "Area 1-5" compliance-mapping
  issue wave (#204-#208, filed same day). Ran a Phase 0 triage — one
  read-only classifier + one adversarial verifier per issue, plus dedicated
  CI-gate and working-tree recon passes — landing on 9/9 verifier agreement:
  execute-now = #189, #190, #204-#208 (7, all reversible); stale-or-wont-fix =
  #201 (superseded by already-merged PR #202); decision-gated = #182 (needs
  the maintainer at a real terminal with interactive sudo, stays DEFERRED).
  User approved the execute-now set, the #201 close, keeping #182 deferred,
  and adding branch-protection enablement as a gated front-of-plan item (main
  had zero required checks, force-push, or deletion protection — CI passing
  was convention-only, per #168's explicit deferral).
- Built and adversarially reviewed a per-item implementation spec (acceptance
  criteria, exact files, test plan, verification commands, branch/PR name,
  rollback) for all 8 approved items; every review surfaced concrete
  corrections (stale line-count/file-count claims, non-runnable verification
  commands, missing irreversible-action checkpoints, factual mismatches
  against live fixtures) that are now folded into the plan as execution
  requirements rather than left implicit.
- Phase A (gate integrity) executed same session — see NEXT UP for detail:
  branch protection applied to `main` (9 required checks, no required
  reviews, admins exempt, force-push/deletion blocked) after an explicit
  payload sign-off; #201 closed with an evidence-cited comment.
- Full plan (phases A-G, CI gate spec, three-lens audit scope, remediation
  reserve) written via the plan-mode workflow; this file is the execution
  view derived from it going forward.

## LAST SESSION — 2026-07-12

- **#177** implemented, reviewed (`security-auditor` + `code-reviewer` in
  parallel), live-verified end-to-end against the running stack, and
  merged — see NEXT UP for detail. [PR #202](https://github.com/voltron-1/Suburban_SOC/pull/202).
  The security-audit pass also surfaced `isolate.sh`'s exclusion-list
  fail-open gap (unrelated pre-existing code, same file/control family) and
  a shadowed `_MAC_RE` validator bug — both fixed in the same PR rather than
  filed separately, since both were small and directly relevant to what was
  already being touched. Confirmed #189 is now partially resolved as a side
  effect (Kibana half of its `soc_pipeline.sh` fix); its ES-target half
  remains open, left as-is for that issue's own pass.
- Process note: a security finding with exploit-relevant detail (exact
  file:line + vulnerable code + exploitation conditions) must not go into a
  public GitHub issue on this repo unpatched — the auto-mode classifier
  blocked two attempts at this (once with full detail, once redacted) before
  the finding was simply fixed directly instead. For future MEDIUM+ findings
  discovered mid-session: fix first if small, or use GitHub Security
  Advisories (private-by-default) rather than a plain public issue, per the
  user's explicit guidance in this session.
- Process note: merging a self-authored PR with no GitHub-side human review
  (only sub-agent review) is blocked by the auto-mode classifier unless the
  user explicitly confirms the review-bypass in response to a direct
  question — a bare "merge it now" was not sufficient on its own.
- **#184** implemented via subagent-driven development (brainstorm → spec →
  plan → 4 tasks, each with an implementer + task-reviewer subagent, plus a
  final whole-branch review) and merged — see NEXT UP for detail.
  [PR #203](https://github.com/voltron-1/Suburban_SOC/pull/203). Confirmed
  the same review-bypass confirmation requirement applies to every
  self-authored PR in this session, not just the first one.
- Process note: the user added an explicit multi-phase execution gating rule
  to this repo's CLAUDE.md mid-session (execute one phase at a time; show
  diff + summary before any commit/push/deploy; wait for explicit go-ahead
  between phases) — applies going forward, including to this file's own
  update-on-merge habit (previously automatic per an earlier session's
  memory note; now gated like any other push).

## LAST SESSION — 2026-07-11

- **#171** implemented, reviewed (`security-auditor` + `code-reviewer` in
  parallel), live-verified, and merged — see NEXT UP for detail.
  [PR #194](https://github.com/voltron-1/Suburban_SOC/pull/194).
- **#183** (weasyprint CVE, filed 2026-07-08) fixed and merged same-session
  after its `pip-audit` failure surfaced on #171's PR — turned out to be
  pre-existing and unrelated to #171 itself, not a regression.
  [PR #195](https://github.com/voltron-1/Suburban_SOC/pull/195), merged
  first, #194 rebased cleanly onto it (disjoint files, no conflicts).
- Process note: reported #194 as fully done before actually checking
  `gh pr checks` against the real CI run — local verification (pytest/ruff/
  mypy) is not a substitute for confirming the actual PR checks. Caught when
  the user reported a CI failure; corrected by checking `gh pr checks` /
  the check-runs API before any future "done" claim on a PR.
- **#172** implemented, reviewed, live-verified, and merged same-session —
  see NEXT UP for detail. [PR #196](https://github.com/voltron-1/Suburban_SOC/pull/196).
  Also corrected a stale reading of the remaining P2/P3 queue: #182 (filed
  2026-07-08, priority:medium) had been missed from "P2 remaining" in this
  file — it's next, not the P3 backlog.

## LAST SESSION — 2026-07-10

- Detection-engineering coverage review (unplanned, separate track from the
  #164-#190 structural review): filed and closed #192 same-session. 12 new
  Sigma rules + 3 Elastic threshold companions covering Windows Security/
  System/WMI/PowerShell event IDs that were either collected-but-unalerted
  or not collected at all. [PR #193](https://github.com/voltron-1/Suburban_SOC/pull/193)
  merged; branch `detections/issue-192-coverage-gaps` deleted post-merge
  (squash merge — local branch cleaned up separately since git didn't
  recognize it as an ancestor of `main`).

## LAST SESSION — 2026-07-08

- Principal-engineer structural health review of the full repo (architecture map,
  robustness/access-control gap analysis mapped to NIST CSF 2.0 + SP 800-53
  Rev.5, sustainability/test/resource-management lenses). Filed 14 issues
  (#164-#177: P1 critical ×4, P2 medium ×5, P3 low ×5) with evidence, control
  mappings, and acceptance criteria; labeled by priority/nist-compliance/
  tech-debt/security; linked to [Project Board #17](https://github.com/users/voltron-1/projects/17).
- **All four P1 (critical) items fixed, tested, PR'd, and merged this
  session**: #164 (PR #178, SI-10), #165 (PR #179, SI-11), #166 (PR #180,
  SC-8), #167 (PR #181, AC-6/CM-7). Each PR includes end-to-end verification
  against the live running stack where no CI path existed to lean on instead.
- Two follow-up issues filed: #182 (zeek-host-capture.service capability
  scoping — needs live-tested sudo access) and #183 (weasyprint CVE
  unrelated to the P1 work, surfaced while investigating pip-audit CI
  failures on the four PRs).
- #160/#161: shipped pipeline ECS fixes + HIGH source.ip-spoof hardening (parallel
  code-reviewer + security-auditor); **PR #162 merged, both issues closed.** Live investigation
  found two extra root causes the issues missed: (1) panels bucket on `.keyword` subfields
  absent on the keyword-mapped real data (fixed net-sni/net-cipher, like be95698); (2) #161 is
  ~entirely mock-data-driven. Backfilled tls.* (5,711 real docs, via approved ILM write-block
  lift+restore) and mock `country_name` (800 docs); redeployed the Network dashboard; both
  panels verified rendering via live aggregations. Logstash restarted → pipeline config live.

Prior session (per merged PR history):

- [x] #159 — ingest-lag SLO recovery + end-to-end dashboard validation
- [x] #158 — ingest-lag SLO recovery + #147 telemetry evidence
- [x] #157 — consolidate es() helpers + ES credential loading (#156)
- [x] #153 — restore + harden ingest pipeline after restart-induced SLO breach (WS2.4)
- [x] #152 — fix small-detection-log ingestion + A.1/A.2 evidence (SOP-147)
- [x] #151 — Path A/B evidence-generation chain + Beats mTLS (SOP-147)
- [x] #150 — evidence validation runbook + flag suspect evidence (SOP-147)
- [x] #149 — emulation→telemetry map + validator, Zeek rules, CI gate

---

## DEFERRED

- [!] **#182** — safely narrow `CapabilityBoundingSet`/`User` for
  `zeek-host-capture.service`. Requires an interactive `systemd-run` trial
  against the *live* capture service before touching the installed unit
  (per the issue's own explicit caution — a prior hardening attempt on this
  exact service caused a production crash-loop, #167). No passwordless sudo
  in this environment, and a sudo password must never be typed into this
  chat. Reason: needs the user at a real terminal with interactive sudo;
  picking up again in a session where that's available.
- [ ] Follow-up issue (to file) — #161 coverage/robustness leftovers surfaced in review:
  standalone `Invalid user <x> from <ip>` sshd line (no verb) not parsed; numeric captures
  (`source.port`, `process.pid`) land as keyword not `long`; add `tls.*`/`process.pid` to
  the index template; `::ffff:` IPv4-mapped-IPv6 gap + 3×-duplicated geoip guard regex.
  Reason: non-blocking enhancements; core acceptance is met by the current fix.
- [ ] Real-telemetry gap ticket (to file) — "Failed SSH by Country" + TLS panels currently
  demo on mock/recent data; live SSH brute-force telemetry is ~absent (2 real failure docs).
  If these must reflect real attacks, the auth.log Filebeat→pipeline shipping path needs to
  actually deliver events. Separate from the ECS fix.
- [x] Activate the PR #162 pipeline config on the running Logstash — done 2026-07-08
  (`docker restart logstash`); container came up stable, so config parsed; forward enrichment
  of new docs active.

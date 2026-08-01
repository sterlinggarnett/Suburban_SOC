# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

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

- [ ] **Phase 0 (CRITICAL, blocking) — #214** — restore the atomic
  approval-gate claim via ES create-if-absent (`claim_approval()` in
  `checkpoints.py`), restore `raise_for_status()` on checkpoint writes,
  discard the uncommitted JSONL-fallback replay hole, handle `/alert` intake
  vs `/approve` execution asymmetrically (intake tolerates ES hiccups,
  execution fails closed).
- [ ] **Phase 1 — #215** — resolve the rest of the uncommitted working tree:
  relocate SOP-022/SOP-147 operational content (dropped by an uncommitted
  playbook-template refactor) into companion runbooks, repair 4 dangling
  references, land the `inventory.py` path fix and README compliance-link
  addition.
- [ ] **Phase 3 (metric) — #216** — add a raw alert-volume SLO metric.
  **Sequenced before #217** — Phase 2 tuning has no before/after signal
  without it.
- [ ] **Phase 2 — #217** (blocked-by #216) — Sigma false-positive tuning;
  verify `CommandLine → process.args` semantics against live data before
  patching the `-enc` rule (the fix direction is ambiguous and the two
  candidate fixes are opposite).
- [ ] **Phase 2 — #218** — exclude the mesh router from the Zeek PortScan
  false-positive (evidence: `evidence/README.md:23`, 60-port legitimate trip
  vs 20-port threshold) without raising the threshold itself.
- [ ] **Phase 3 — #219** — verify/enforce Logstash Beats-input mTLS
  client-cert requirement (`ssl_client_authentication` may not actually be
  `required`).
- [ ] **Phase 3 — #220** — extend alert dedup key to a sliding host+technique
  suppression window.
- [ ] **Phase 3 — #221** — add live-fire Sigma detection tests against real
  Elasticsearch data.
- [ ] **Phase 4 — #222** — expand threat-intel feed coverage, automate
  `refresh_intel.sh` cron install.

Next unstarted item: **Phase 0 — #214**, blocking everything else in this
milestone.

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
        CLOSED, or ESCALATED)
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

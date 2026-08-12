# Plan — Issue #267: soar_quarantine_alert.json Watcher gaps

## Issue as filed
`rules/elastic_watcher/soar_quarantine_alert.json` is dead code, superseded
by `configs/logstash.conf`'s ingest-time HMAC-signed HTTP output. Two
pre-existing gaps *if revived*: no HMAC signing, and possibly-invalid
install (`_comment`/`_comment_paths` top-level keys Watcher's parser may
reject). Suggested fix: either fix both gaps and revive it as a fallback,
or retire it explicitly.

## Root-cause investigation finding (expands scope)
The live replacement (`configs/logstash.conf` Category 6) only covers 1 of
the Watcher's 3 original trigger conditions:
`[event][dataset] == "zeek.intel" and [threat][indicator][value]`.
The Watcher additionally fired on `Scan::Port_Scan` (T1046) and a 5+
failed-SSH-auth burst (T1110) — dropped when #220-era work superseded the
Watcher, undocumented as an intentional decision (the surviving comment
just states it as a known gap, referencing the Watcher's own equivalent
branch). Practical effect, confirmed by reading the code: **T1046/T1110
network detections get pipeline-tagged and show up in dashboards, but never
reach automated SOAR response today.** Exactly the milestone's own stated
concern ("detections that look deployed but cannot fire as intended").

Confirmed with the repo owner: close the real gap in the architecturally-
current place (extend the live trigger) rather than revive the Watcher.
Reasons, in order of weight:
1. Reviving the Watcher means re-implementing the same HMAC-SHA256 signing
   scheme in Painless (Elasticsearch's more restricted scripting engine) —
   duplicating security-critical signing logic in a second language, a real
   drift risk, vs. extending an `if` condition on an already-proven Ruby
   block.
2. `deploy_dashboards.sh`'s own comment says a Watcher install failure "may
   require a trial/Gold license" — reviving it may hit a licensing wall the
   ingest-time approach never has.
3. Two live, overlapping trigger paths (a 1-min-scheduled Watcher poll +
   the ingest-time trigger) reintroduces exactly the double-dispatch race
   #214/#172's atomic-approval-claim work exists to prevent.
4. Even a successful narrow fix still leaves the real milestone-relevant
   gap open, since the ingest-time trigger would eventually need extending
   anyway — narrow-then-full is strictly more total work than full alone.

## Additional gaps found during design (not in the original issue)
1. **`source.ip` would be empty for T1110 dispatches.**
   `detect-bruteforcing.zeek`'s `Password_Guessing` notice sets only
   `$src = key$host`, not `$conn` — so its notice.log JSON carries a
   top-level `src` field but no `id` sub-record, meaning the pipeline's
   existing universal `"[id.orig_h]" => "[source][ip]"` rename (Category 0)
   never fires for it. T1046's `Scan::Port_Scan` (`scan-detection.zeek`)
   sets `$conn = c` *and* `$src = src` — already covered by the existing
   rename, no gap there. Fix: a fallback rename, `[src] -> [source][ip]`,
   scoped to `event.dataset == "zeek.notice"` and only applied when
   `[source][ip]` isn't already set (never overwrite a value the generic
   rename already populated correctly).
2. **`source.mac` will stay empty for T1046/T1110 dispatches, deliberately
   not fixed here.** #286's MAC correlation (uid-keyed conn.log<->intel.log
   join) is a bespoke, heavily-reviewed mechanism scoped specifically to
   zeek.intel's single-connection case. It doesn't generalize to aggregated
   notices (a port-scan notice spans N connections across 20+ distinct
   ports — there is no single `uid` to correlate against the way a single
   intel match has one). Building an equivalent would be its own
   substantial, separately-reviewable piece of work, likely harder than
   #286's original (which already needed 3 security-auditor rounds).
   Confirmed this doesn't block a *functional* fix: `dispatch_block_via_broker()`
   in `scripts/setup/ai_agent/agent.py` treats `source_mac` as optional
   (default `""`), so IP-only containment dispatch is still a fully working
   path — matches how the zeek.intel branch itself already leaves `technique`
   empty when it has no evidence rather than fabricate one. Filed as a
   follow-up rather than solved inline.

## Scope
1. Extend `configs/logstash.conf` Category 6's trigger condition to also
   fire when `[threat][technique][id]` is `T1046` or `T1110` (both already
   precise, aggregated, notice-based tags as of #261 — no new threshold
   logic needed, just read the existing tag).
2. Add the `src -> source.ip` fallback rename for `zeek.notice` events,
   scoped and conditional as above.
3. Update Category 6's own comment (stale as of this change — it currently
   says T1046/T1110 "neither of which fires this trigger") and the
   `slo_metrics.py` docstring I touched during #261, which says the same
   thing.
4. Retire `rules/elastic_watcher/soar_quarantine_alert.json` in place:
   expand its `_comment` to state it's historical/superseded, matching how
   `configs/zeek/local.zeek` was left in place with a dead-code header
   (#286) rather than deleted.
5. Add a regression test (mirrors #261's CI-enforced-invariant pattern) —
   `tests/pipeline/test_framework_enrichment.py` — asserting the Category 6
   condition includes T1046/T1110, so this can't silently regress.
6. Live-verify via spliced-pipeline replay (the same technique tester-debugger
   used for #261's Check 1) — deliberately NOT bringing up the full
   ES/Kibana/agent stack, since nothing here needs it: the change is
   entirely within Logstash's own filter logic, and a splice test against
   just the `docker.elastic.co/logstash/logstash:9.3.2` image proves it
   directly. Test matrix:
   - T1046-tagged event (with `id.orig_h` present, matching real
     `scan-detection.zeek` output shape) -> dispatches, `source.ip` set
     from the generic rename.
   - T1110-tagged event with only a bare `src` field, no `id` (matching
     real stock `detect-bruteforcing.zeek` output shape) -> dispatches,
     `source.ip` set from the new fallback rename.
   - zeek.intel path -> still dispatches, unaffected (regression check).
   - An untagged / different-technique event -> does NOT dispatch
     (negative check, guards against an overly-broad condition).
7. `security-auditor` + `code-reviewer` in parallel on the diff (project
   mandate), `tester-debugger` for the splice-replay verification, all
   three launched together.

## Additional gap found during implementation (not caught by design review)
The `output{}` block has its **own, separate** copy of the trigger condition
gating the actual `http` dispatch (Logstash has no way to share a condition
across `filter{}`/`output{}`) — its own comment even said "same condition as
the signing block." Widening only the filter-stage signing condition and
missing this one would have shipped a signed-but-never-dispatched event for
T1046/T1110 — the exact silent-no-op failure mode this whole issue is about,
just moved one stage later. Caught by inspecting the file for every
`soar_quarantine_alert.json`/"SOAR trigger" reference before considering the
change complete, not by the original design. Fixed identically; added
`test_soar_trigger_signing_and_dispatch_conditions_match` so the two can
never silently desync again.

## Live verification (self-performed splice-pipeline replay, same technique as #261)
Ran a spliced pipeline (byte-identical excerpts: the `id.orig_h` rename +
new `src` fallback, Category 5's T1046/T1110 tagging, Category 6's widened
trigger) against the real `docker.elastic.co/logstash/logstash:9.3.2` image
with 6 synthetic events. All 6 behaved as expected: T1046 (with `$conn`)
dispatches with `source.ip` from the existing rename; both T1110 notice
types (`$src`-only, no `$conn`, matching stock `detect-bruteforcing.zeek`'s
real output shape) dispatch with `source.ip` from the new fallback;
`zeek.intel` still dispatches unaffected; ordinary traffic and an unrelated
notice type correctly do not dispatch. Full command/output log at
`test-artifacts/t1046_1110_splice_output.log` (session-scratch, not
committed). Deliberately did not bring up the full ES/Kibana/agent stack —
nothing in this change needs it (see "Explicitly out of scope" below).

## Documentation swept for the same drift #261 already found
Live/operational docs that described the retired Watcher as the active
trigger (would mislead an operator following them today), fixed:
`README.md` (architecture table), `docs/SOP-022-anomaly-validation.md` and
`docs/SOP-022-anomaly-validation-procedure.md` (a validation runbook with a
literal "install the Watcher" step), `docs/cost-breakdown-analysis.md` (a
licensing risk warning that's now moot, presented as live), and
`docs/SOP-147-evidence-validation-procedure.md` (an evidence-capture step
naming the wrong trigger mechanism). Deliberately did NOT touch dated
historical artifacts (`reports/`, `findings/`, old `plans/`,
`docs/presentation_slides.md`) — those describe a point in time, not current
state, matching this repo's own append-only history convention.

## Explicitly out of scope
- Reviving `soar_quarantine_alert.json` as a live Watcher.
- `source.mac` correlation for notice-based dispatches (follow-up).
- Tuning `password_guesses_limit`/scan thresholds — unchanged, this fix
  only changes what happens once a technique is already tagged, not when
  tagging happens.
- End-to-end verification against a live agent/ES stack — the change is
  fully contained in Logstash filter logic; splice-replay is sufficient
  and avoids restarting a currently fully-down production stack for a
  change that doesn't touch it.

## Review round — HIGH finding, scope reduced (T1110 only, not T1046)
`security-auditor` review (parallel with `code-reviewer` + `tester-debugger`,
same pattern as #261) found a real HIGH: wiring T1046 into live dispatch
converts `scan-detection.zeek`'s already-known spoofable weakness (#331 —
fires on a bare SYN, no completed handshake, attacker-chosen source IP) from
"inflates a dashboard count" into "queues a real automated-containment
workflow against an attacker-chosen victim IP" — verified directly: `severity`
is hardcoded `"critical"` for every Category 6 dispatch, there is no rate
limiting anywhere in `agent_app.py`/`agent.py`, and the agent's own Dockerfile
caps concurrency at `--workers 1 --threads 4`. T1110 does not share this
problem (handshake-backed, not spoofable this way).

**Resolution (confirmed with the repo owner): split the fix.** Wired T1110
into live dispatch (both the filter-stage signing condition and the
output-stage dispatch condition, changed from `[threat][technique][id] in
["T1046", "T1110"]` to `[threat][technique][id] == "T1110"`). T1046 stays
pipeline-tagged for dashboards exactly as before this fix — not wired into
live dispatch. Deferred until [#331](https://github.com/voltron-1/Suburban_SOC/issues/331)
(a source-spoofing defense for `scan-detection.zeek`) actually exists;
commented on that issue to record the new blocking relationship. Re-verified
via a fresh splice-pipeline replay after the change: T1046 tags but does not
dispatch, T1110 and zeek.intel still dispatch, negative cases still do not.
Updated the 3 new regression tests, the retired Watcher's `_comment`, and
every doc touched in the earlier sweep that had claimed "all 3 conditions"
or implied T1046 dispatches.

Two other findings from the same review applied regardless of the T1046
decision and were fixed: the retired Watcher was never actually being
un-installed from clusters `deploy_dashboards.sh` had already run against
(no `DELETE _watcher` existed anywhere in the repo) — added an idempotent
delete step to both `deploy_dashboards.sh` and `deploy_dashboards.ps1`; and
MAC-less dispatch silently narrows the §12.4 exclusion list to IP-only
matching for anyone who followed `governance/exclusion_list.txt`'s existing
advice to list infra by MAC — documented the gap in that file directly.

`code-reviewer`'s Must-Fix (`tests/anomaly_simulation/preflight.sh` still
hard-gated on the now-never-installed Watcher, would have permanently
blocked the SOP-022 live-lab harness) was fixed the same session, before
the T1046 scope change — unaffected by it, still correct.

`tester-debugger` independently re-verified the pre-split fix end-to-end,
including a gap in my own self-verification: it built a second splice
exercising the *actual* `http` output plugin (not just a textual-identity
check between the two condition copies) against a local fake HTTP server,
confirming real POSTs fire for tagged events and not for untagged ones. No
functional bugs found in the core logic at any point — the HIGH finding was
about the security *consequence* of what conditions to dispatch on, not a
defect in how the dispatch mechanism itself works.

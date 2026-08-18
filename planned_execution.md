# Planned Execution — Suburban-SOC

Sequenced execution view. Derived from the GitHub issue tracker + merged PR history;
the issue tracker remains the source of truth for completion state.

Status: `[ ]` todo · `[~]` in-progress · `[x]` done · `[!]` blocked

---

## NEXT UP

**Restructured 2026-08-16, per direct request:** the backlog had grown to
37 open issues, 33 of them with no milestone at all (filed as review
follow-ups across M12–M16 and never triaged), plus 4 more crammed into
M16 despite sharing no real theme with its actual "endpoint onboarding /
threat-intel" scope. M15 closed outright (its last open item, #283, moved
to its true thematic home below — #283 was never "M15 work," it just
hadn't been re-sorted). Every open issue now has exactly one
properly-scoped milestone; M15's full history moved to `<details>` below,
matching the M12/M13/M14 pattern.

**7 open milestones** (issue counts as of the restructure):

| Milestone | Issues | Theme |
|---|---|---|
| [M16 — Endpoint Onboarding & Threat-Intel Integrity](https://github.com/voltron-1/Suburban_SOC/milestone/20) | ⏸️ 7/8 closed, 1 deferred (no actionable work left) | Minting endpoint certs before a real host onboards; threat-intel/checkpoints compactor credentials have no detection coverage |
| [M17 — Detection Rule Coverage & Correctness](https://github.com/voltron-1/Suburban_SOC/milestone/22) | ⏳ 18/34 closed — 14 real follow-ups still open, 2 permanently not actionable (#283, #333) | Sigma rule logic gaps, spoofable/evadable detections, threshold-band blind spots, coverage-metric accuracy |
| [M18 — ECS Pipeline & Field-Mapping Integrity](https://github.com/voltron-1/Suburban_SOC/milestone/23) | ⏸️ 12/16 closed, 4 not actionable (no actionable work left) | Logstash rename/copy drift vs. suburban-soc-ecs.yml's claims, dashboard fields that don't exist on the real mapping, truncation ceilings, index-template rollover |
| [M19 — SOC Platform Credential & Secret Hygiene](https://github.com/voltron-1/Suburban_SOC/milestone/24) | 6 | Cleartext passwords in argv, ES role drift with no sync check, no live self-check on role regressions, unpinned CI toolchain, ES network exposure |
| [M20 — SOAR Response-Path Hardening](https://github.com/voltron-1/Suburban_SOC/milestone/25) | 3 | Residual hive-mind-broker/#277 hardening, autonomous-isolation MAC-gate policy decision |
| [M21 — Zeek Sensor Operational Resilience](https://github.com/voltron-1/Suburban_SOC/milestone/26) | 3 | No liveness/dead-man detection for a silently-dead capture source; symlink/ownership primitives; CA trust-on-every-use |
| [M22 — Compliance & Documentation Accuracy](https://github.com/voltron-1/Suburban_SOC/milestone/27) | 3 | Docs/compliance matrix citing dead code as a live control; a tagging mandate never implemented; analyst-facing rule text leaking implementation detail |

**Full per-issue detail lives in each milestone's own GitHub issue list**
(the issue tracker is the source of truth per this doc's own header) —
this doc doesn't duplicate 37 issue bodies inline the way it narrates
*completed* work. As each issue is picked up, gate and record it here the
same way every prior milestone's issues were recorded below.

M17 closed out 2026-08-17 (6/8, no actionable work left) — **then resumed
the same day**: the project-board milestone-backfill audit found 7 more
open issues that had been filed as M17 review follow-ups without a
milestone and retroactively assigned them back to M17, so "no actionable
work left" was true only against an incomplete view of the milestone.
Working the corrected 15-issue set now, smallest/most-contained first
(see M17 progress below). **M18 closed out 2026-08-17 too** (12/16, no
actionable work left — #326 externally blocked on real telemetry,
#396/#403/#405 are review-discovered follow-ups deliberately scoped out
of the fixes that found them, not active gaps). M19–M22 remain open
calls, not yet started. Same approach as M16/M17/M18 whenever the next
one starts: smallest/most-contained issue first, one at a time, each
through the full implement → parallel security-auditor + code-reviewer
review → live-verify → PR → CI → merge → update this doc → commit+push
cycle, no unattended multi-issue runs.

**M18 progress:**

- [x] **#344 (P2, security, bug) — COMPLETE, MERGED** — `winlog.event_data.
  CommandLine` (Windows Security-channel, Winlogbeat's raw un-renamed
  shape) matches the `long_command_fields` dynamic_template's `*CommandLine`
  glob at `ignore_above:32766` but had no entry in `configs/logstash.conf`'s
  `long_fields` byte-clamp hash — same #263/#290 whole-document Lucene
  immense-term rejection risk, undiscovered because `CeilingConsistencyTests`
  only walks the template's *explicit* properties, not dynamic_template
  glob matches. Fixed per the issue's own suggested option 1 (add the one
  concretely-identified field), not option 2 (rewrite the filter to sweep
  by glob generically — scoped out, see below).
  [PR #368](https://github.com/voltron-1/Suburban_SOC/pull/368) merged
  2026-08-16 (squash), auto-closing #344 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (17/17 CI green,
  parallel security-auditor + code-reviewer sub-agent review only).
  security-auditor follow-up found a **second live instance** of the same
  gap already in the repo — `network_parsed.uri` (Zeek `http.log`'s uri
  field, reachable today via the unauthenticated `:5514` HTTP input, same
  attacker-controlled-URI shape as #290's `url.path`) — added in the same
  fix. Also found a MEDIUM gap in the CI gate itself: nothing asserted the
  ruby `long_fields` hash and its Python `LONG_FIELDS` test mirror agreed
  with *each other*, only that each agreed with the template separately —
  deleting either new entry left the whole suite green. Closed with a
  direct bidirectional equality assertion, verified by mutation test
  (deleting an entry now fails it). Both new clamp entries live-verified
  against the real ruby filter logic (not just the Python mirror) in a
  throwaway `ruby:3-alpine` container, `--network none`, fed a fake
  Logstash `event` object — 40000-char tagging, byte-ceiling clamping for
  multi-byte content, and no regression on the pre-existing `ImagePath`
  entry, individually and with all 7 clamped fields in one event.
  Filed [#367](https://github.com/voltron-1/Suburban_SOC/issues/367) to
  track the deferred structural fix (union of a glob sweep with the
  explicit list) — scoped out because it needs a per-event recursive
  field walk on a pipeline with its own ingest-lag SLO, not because of a
  correctness concern with the 2-field fix that shipped.
- [x] **#341 (P2, bug) — COMPLETE, MERGED** — Kibana panels bucketing on
  a `.keyword` sub-field of an ECS field that's mapped bare `keyword` (or
  `ip`) in the real templates match nothing and silently render empty —
  same shape as the already-fixed Network dashboard bug (commit
  `be95698`). #341 named 4 broken fields on the Endpoint dashboard; fixing
  it found 3 more in the same file by hand, which is what prompted writing
  a general regression test
  (`tests/dashboards/test_dashboard_field_mapping.py`) instead of a
  one-off fix. That test's first run found **15 more instances across 7
  other dashboard files**. [PR #369](https://github.com/voltron-1/Suburban_SOC/pull/369)
  merged 2026-08-16 (squash), auto-closing #341 — same review-bypass
  basis as every prior session fix.
  security-auditor follow-up on the new test found it was STILL
  under-flagging: its "unmapped field → skip, don't guess" rule treated
  every governed index the same way, but `logstash-security-template.json`'s
  `strings_as_keyword` dynamic_template is an unrestricted catch-all (no
  `path_match`), so an "unmapped" field there is still provably bare
  keyword, not unknown. That hid 3 live, populated fields on the
  Executive dashboard (`nist.function`, `threat.technique.id`/`name` —
  set by `configs/logstash.conf`'s Zeek classification block) plus
  `action.type` (checked against the separate `soar-actions-template.json`,
  which has no dynamic_templates at all — genuinely NOT exhaustive the
  same way, now modeled as per-pattern `GOVERNED_INDEX_PATTERNS`). Also
  found 2 instances entirely outside the checker's original scan surface
  (a Talos-lookup `fieldFormatMap` pivot on two dashboard-bundle files).
  All 6 fixed; checker widened with its own synthetic tests proving the
  exhaustive/non-exhaustive asymmetry. A self-review before merge then
  caught that the `fieldFormatMap` scan's first draft (a regex keyed on
  `"id"` being serialized first) would have silently broken the moment
  Kibana re-exported the file with different key order — replaced with
  real `json.loads` plus a key-order-independence regression test.
  Wired into CI as a new `tests/dashboards` directory-glob step in
  `detections.yml`, mirroring the existing `tests/pipeline` step.
- [x] **#342 (P3, bug) — COMPLETE, MERGED** — the Windows Security-channel
  block only ever stamped `event.outcome`; it never mapped
  `winlog.event_data.IpAddress`/`TargetUserName` to ECS
  (`source.ip`/`user.target.name`), so a Windows-side auth failure had no
  source attribution on any ECS-field-based dashboard/hunt.
  [PR #371](https://github.com/voltron-1/Suburban_SOC/pull/371) merged
  2026-08-16 (squash), auto-closing #342. M18 now 3/13 closed.
  Deliberately `copy`, not `rename` (unlike the Sysmon block above it):
  3 deployed `level:high` Elastic threshold rules bucket/cardinality-count
  directly on the raw field names outside the pySigma pipeline — a
  `rename` would've silently broken all of them, confirmed by reading the
  actual rule files. security-auditor review found the geoip guard let
  `0.0.0.0`/`::` (both valid ES `ip` values) index as meaningless buckets,
  and missed `::ffff:`-mapped Kerberos Client Addresses from domain
  controllers — both fixed and live-verified in a real `logstash:9.3.2`
  container (7 synthetic events). A follow-up review then found the new
  regression test only checked field *presence*, not copy *direction* —
  the exact flat-field footgun this repo already hit as #328/#161 —
  fixed, plus a `remove_field` regex that could never match this file's
  own bracket-notation fields. All 6 new/changed assertions
  mutation-tested. CodeQL then flagged the `remove_field` fix itself as a
  HIGH-severity ReDoS (nested quantifiers that can all match empty) —
  replaced with a plain linear quote-tracking scan, confirmed on the
  exact adversarial input CodeQL cited (150k chars in ~5ms). Folded into
  `tests/pipeline/test_framework_enrichment.py` (already covers this same
  block for #297) rather than a new file, per code-reviewer feedback.
  Filed [#370](https://github.com/voltron-1/Suburban_SOC/issues/370)
  (out of scope: a threshold rule still buckets on the raw, unsanitized
  field) as a new M18 Backlog item.
- [x] **#337 (P2, bug) — COMPLETE, MERGED** — `user.name` was mapped
  `keyword` with NO `ignore_above` at all (Elasticsearch's own unbounded
  default, 2147483647) — a long value reached Lucene directly with no
  char-ceiling backstop, the same whole-document immense-term rejection
  risk `#263`/`#290`/`#344` fixed elsewhere. Separately, `#328` correctly
  nested 9 Sysmon-derived fields but the truncation filter only ever
  tracked 4 of them under one global 32766 ceiling; restructured to
  per-field ceilings so the other 6 (at their own real 8191/1024
  ceilings) get truncation-visibility tagging for the first time.
  [PR #372](https://github.com/voltron-1/Suburban_SOC/pull/372) merged
  2026-08-16 (squash), auto-closing #337. M18 now 4/13 closed.
  Two security-auditor review rounds found: `related.user` wrongly
  raised to 32766 despite being an ECS array field the byte-clamp can't
  handle (backed off to 8191, matching `related.hosts`); a PII-redaction
  gsub that grows matched substrings running *after* the byte-clamp
  (reordered); Ruby counting Unicode code points where Elasticsearch
  counts UTF-16 code units, silently undercounting astral characters —
  e.g. emoji — for the 6 newly-tracked fields (fixed in both the ruby
  filter and its Python mirror, live-verified the exact 4095-vs-4096-
  emoji boundary against a real `logstash:9.3.2` container); and an
  exact-match byte-clamp guard that would've silently skipped any future
  tier between 8192 and 32765 (generalized). A follow-up pass then found
  3 more minor gaps (a comment citing a nonexistent test, a hardcoded
  tier regex blind to a future third tier, stale guard-formula comments)
  — all fixed. 8 mutation-test scenarios total, every one caught.
- [x] **#370 (P3, bug) — COMPLETE, MERGED** — `auth-win-bruteforce-source-
  spray.ndjson`'s threshold query had no exclusion for Winlogbeat's
  `IpAddress` sentinel placeholders (`"-"`, `"0.0.0.0"`, `"::"`, `""`) on
  local/console/service-account 4625 failures, so every sentinel-valued
  event shared one bucket and 6 distinct accounts failing a local logon
  within 5 minutes fired a false `severity:high` "password spray" alert.
  [PR #397](https://github.com/voltron-1/Suburban_SOC/pull/397) merged
  2026-08-17 (squash), auto-closing #370. M18 now 5/13 closed.
  Query now excludes the same 4-value set `configs/logstash.conf`
  established for the `source.ip` ECS copy (#342) — the issue's own
  suggested fix only listed 3 of the 4; live-tested against the real
  Elasticsearch container before shipping and confirmed the empty-string
  sentinel needs its own explicit exclusion, dropping just `"-"` leaves it
  unfiltered. Parallel security-auditor + code-reviewer review:
  code-reviewer approved with one fast-follow (a `logstash.conf`
  cross-reference comment, applied); security-auditor found a real,
  deliberately-accepted trade-off — excluding these sentinels also
  removes the only coverage this rule accidentally had for genuine
  on-host password spray (`runas`/`LogonUser()` from an already-landed
  foothold, same `"-"` sentinel) — documented in the rule's own
  description rather than silently absorbed, filed
  [#396](https://github.com/voltron-1/Suburban_SOC/issues/396) (a
  companion rule bucketing on `winlog.computer_name` instead) as the
  proper fix.
- [x] **#339 (P2, bug) — COMPLETE, MERGED** — #328 fixed the Sysmon
  `Hashes` rename's NESTING but not its CONTENT: Sysmon's `Hashes` field
  is algorithm-prefixed (`"SHA256=<hex>"`, or composite
  `"SHA1=...,MD5=...,SHA256=...,IMPHASH=..."`), so `file.hash.sha256` held
  the raw prefixed string, never a bare hash an IOC hunt could match.
  [PR #398](https://github.com/voltron-1/Suburban_SOC/pull/398) merged
  2026-08-17 (squash), auto-closing #339. M18 now 6/13 closed.
  Added a grok extraction after the rename, live-verified against the
  real pinned `logstash:9.3.2` image across 5 scenarios (single value,
  composite value, no-SHA256 value, absent field, >64-char value). A
  custom `tag_on_failure` keeps a normal "no SHA256 in this value"
  condition out of the parse-error-rate SLO; on that failure the field is
  removed rather than left mislabeled. Parallel security-auditor +
  code-reviewer review, both approved with only LOW findings, applied
  before shipping: the regex had no trailing boundary (a >64-char value
  would silently truncate-match instead of failing closed — added
  `(?![A-Fa-f0-9])`, re-verified live), and
  `configs/detections/suburban-soc-ecs.yml`'s mapping comment updated so a
  future Sigma rule using the standard `Hashes|contains: 'SHA256=...'`
  idiom doesn't compile to a permanently non-matching query.
- [x] **#338 (P2, bug) — COMPLETE, MERGED** — #328 fixed `[user][name]` to
  actually populate from Sysmon's `User` field, which reaches this
  pipeline Windows-formatted `DOMAIN\user` (e.g. `CONTOSO\bob`), while the
  ABAC translate lookup keys `configs/lookups/abac-attributes.csv` on
  bare usernames — every Sysmon event got `user.abac_attribute:
  "unassigned"` (100% miss). [PR #399](https://github.com/voltron-1/Suburban_SOC/pull/399)
  merged 2026-08-17 (squash), auto-closing #338. M18 now 7/13 closed.
  Adds a ruby filter, scoped to the Sysmon branch only (not the SSH
  auth-log's own attacker-controlled `[user][name]`), stripping the
  domain prefix via `rpartition` before the ABAC lookup. Parallel
  security-auditor + code-reviewer review, both with real findings
  applied before shipping: code-reviewer found the original `92.chr`
  workaround unnecessary — live-verified this file's own established
  single-quoted `code => '...'` convention for multi-line ruby blocks
  sidesteps the escaping problem entirely with standard Ruby escaping;
  security-auditor (MEDIUM) found a plain rename would DESTROY the
  domain, letting a local account sharing a bare username with a real
  privileged CSV entry (e.g. a workstation's own local "tjlam") silently
  inherit its ABAC attributes — now preserves the domain to its own field
  (doesn't fully close the gap alone, since the lookup still keys on the
  bare name until the CSV gains domain-qualified keys, which needs real
  telemetry to know — but makes the ambiguity visible instead of
  silent); plus a LOW empty-string guard for a degenerate (trailing/bare
  backslash) value, and a strengthened regression test pinning the exact
  `.last` call and the full SSH branch's negative-window span. Live-
  verified the final logic against the real pinned image across 7 cases.
- [x] **#349 (P3, tech-debt) — COMPLETE, MERGED** — Category 0's
  `zeek_stream` grok tags `_zeek_path_nomatch` on a bad filename, but
  nothing consumed the tag; #291's `event.dataset:zeek.<service>` scoping
  means a grok-failed document is now completely invisible to every
  zeek-sourced detection, a real blackout with zero visible signal.
  [PR #400](https://github.com/voltron-1/Suburban_SOC/pull/400) merged
  2026-08-17 (squash), auto-closing #349. M18 now 8/13 closed.
  Stamps `pipeline.zeek_path_nomatch` from the tag and adds
  `metric_zeek_path_nomatch_count()` (target 0, a detection-coverage
  signal not a data-quality baseline) to `slo_metrics.py`; tags an
  undated document in the related `:5514` `network_logs` branch too.
  security-auditor found 2 HIGH findings before landing on this design:
  the shared 7-day `WINDOW` + 15-min poll cadence would pin a single
  nomatch document in breach for ~672 consecutive runs — fixed with a
  dedicated short window (`SLO_ZEEK_PATH_NOMATCH_WINDOW`, default
  `now-1h`), mirroring `metric_capture_loss_percent()`'s own established
  precedent for the identical problem; and Category 0's content-based
  (not input-based) gate makes this attacker-triggerable via the
  unauthenticated `:5514` input — the SAME pre-existing, already-tracked
  gap `metric_capture_loss_percent()` documents for itself (private
  security advisory, not a public issue), not a new one this metric
  introduces — the dedicated short window bounds the combined impact to
  a transient, self-clearing false breach rather than a permanent one.
  Both reviewers also independently flagged the `network_logs` branch's
  tag name (`_zeek_undated`) as overclaiming Zeek-specific content —
  renamed to `_network_logs_undated`.
- [x] **#347 (P3, tech-debt) — COMPLETE, MERGED** — #287's static
  field-mapping drift checker (catches a Sigma rule selecting a field
  `suburban-soc-ecs.yml` claims gets renamed, but `logstash.conf` never
  actually renames — bit the corpus 4 times: #217, #232, #233/#234,
  #228) was deliberately scoped to `product:zeek` only; Winlogbeat
  channels were a known, out-of-scope gap. [PR #401](https://github.com/voltron-1/Suburban_SOC/pull/401)
  merged 2026-08-17 (squash), auto-closing #347. M18 now 9/13 closed.
  Extends it to Sysmon's `process_creation`/`file_event` renames — new
  extractors mirroring the Zeek-side ones' assumption guards and
  landmark tripwires; `find_mismatches()` reused completely unchanged.
  Parallel security-auditor + code-reviewer review converged on the same
  real MEDIUM: the category filter was an INCLUDE allowlist that would
  silently exclude any future category-scoped transformation before it
  ever reached the checker, with the test's own set-equality assertion
  built from that same filter so it could never notice — fixed by
  inverting to an EXCLUDE denylist (a future real transformation is
  auto-discovered; a future identity-mapped category not added to the
  denylist surfaces as a loud mismatch failure instead of a silent gap),
  plus the Zeek side's own forward-looking corpus-glob test, mirrored
  for Windows categories. Also fixed: a fail-silent normalizer tightened
  to assert the exact expected bracket shape plus a key-collision guard;
  a negative self-test that could never actually fail (mutation-tested
  to confirm the fix works); two docstring accuracy nits.
- [x] **#345 (P3, tech-debt) — COMPLETE, MERGED** — `apply-templates.sh`
  documented in its own header comment that a data-stream-backed index
  template's mapping only shapes indices created AFTER the template is
  re-applied, and rolling over the current write index was needed to
  actually take effect — but never performed that rollover; every prior
  fix to this template needed it as a separate, manual, undocumented-
  in-code step. [PR #402](https://github.com/voltron-1/Suburban_SOC/pull/402)
  merged 2026-08-17 (squash), auto-closing #345. M18 now 10/13 closed.
  Adds a `ROLLOVER=1`-gated step enumerating and rolling over the real
  `logstash-security-*`/`soar-actions-*` data streams. Live-verified end
  to end against the real running dev-stack Elasticsearch: all 9 real
  data streams in this environment correctly discovered and rolled
  over, generations bumped, cluster health unaffected. Parallel
  security-auditor + code-reviewer review, both independently converging
  on the same critical finding: the discovery GET's HTTP status was
  never checked, so an error response parsed as invalid JSON exactly
  like a genuine zero-match, both silently reporting "nothing to roll
  over" — precisely the silent-no-op this issue exists to kill. Fixed
  with an explicit status check, live-verified against all 3 real
  response shapes. Also fixed: rollover is additive, not idempotent, so
  abort-on-first-failure became collect-and-report (a partial failure no
  longer requires re-rolling already-succeeded streams); `--globoff` on
  the rollover POST; and an unconditional read-only reminder (data-
  stream count still on the old mapping) whenever `ROLLOVER` isn't set,
  since the opt-in gate reintroduces the exact "operator forgets" risk
  this issue exists to close.
- [x] **#336 (tech-debt) — COMPLETE, MERGED** — `test_no_rename_block_
  uses_a_dotted_string_target` (#328) checked every `rename => {...}`
  block for a dotted-string target, but only scanned `rename` blocks
  (missing the identical footgun in `logstash.conf`'s own `copy`
  block) and only matched double-quoted config strings (Logstash
  allows single-quoted too). [PR #404](https://github.com/voltron-1/Suburban_SOC/pull/404)
  merged 2026-08-17 (squash), auto-closing #336. M18 now 11/13 closed.
  Extends the check to `copy` blocks too and accepts either quote
  style (mutation-tested to confirm the single-quote gap was real). A
  first implementation (matching the issue's own suggested combined
  `rename|copy|replace|update` regex) broke a different pre-existing
  test relying on rename-only matching, AND parallel security-auditor +
  code-reviewer review found the combined approach wrong on the merits
  too — `replace`/`update` have `field => VALUE` semantics, never
  `field => field-path`, so a dot in their value was never the #328 bug
  at all. Fixed by scanning rename+copy only, keyed by `(keyword,
  source, target)` rather than just `(source, target)` — the same pair
  has very different risk as a rename (removes the source) vs. a copy
  (keeps it). Independently verified (not taken at face value) that of
  the 2 pre-existing dotted copy targets the issue named, only one is
  actually dashboard-consumed as claimed; the other's dotted target
  dot-expands to the exact same final ES location as its own source —
  live-confirmed against a real index — a harmless but redundant
  self-write, filed as [#403](https://github.com/voltron-1/Suburban_SOC/issues/403).
  #336 also asked for a Sysmon-vs-`suburban-soc-ecs.yml` cross-reference
  test — already fully covered by #347, not duplicated here.
- [x] **#367 (security, tech-debt) — COMPLETE, MERGED** — `logstash.conf`'s
  `long_fields` byte-clamp hash protects specific fields against a
  Lucene whole-document-rejection bug; 2 entries (#344) are only
  reachable via the `long_command_fields` dynamic_template's glob
  match, not an explicit template property, so `CeilingConsistencyTests`
  structurally cannot discover a future field reaching ES only through
  that glob match. [PR #406](https://github.com/voltron-1/Suburban_SOC/pull/406)
  merged 2026-08-17 (squash), auto-closing #367. M18 down to #326
  (not actionable) plus 3 follow-ups filed during this milestone's own
  review work (#396, #403, #405) — no more actionable M18 work.
  Implements the narrower of #367's own two suggested fixes (a
  benchmarked runtime rewrite of the ruby filter is real design +
  performance work on an SLO-bound pipeline, out of scope without a
  benchmark) — a static CI check deriving "every field this pipeline's
  own configuration claims to produce" from `suburban-soc-ecs.yml`'s
  mapping targets UNIONED with the real rename targets
  `logstash.conf`/`filebeat.yml` actually produce (reusing #347's own
  extractors), checked against the same 6 glob patterns the real
  dynamic_template uses. Parallel security-auditor + code-reviewer
  found 2 real gaps in the first draft: ceiling-blindness (the check
  accepted a field listed at ANY tier, but the dynamic_template always
  assigns CEILING for a glob match — a future field at the wrong tier
  would have passed while remaining genuinely unclamped, fixed and
  mutation-tested) and too-narrow a universe (checking only ecs.yml's
  own claims misses a brand-new pipeline rename target with no ecs.yml
  entry at all — fixed by unioning in real rename targets, confirmed
  live to add 7 real fields ecs.yml never claims). Honest scope note,
  documented rather than overclaimed: this still cannot catch
  `network_parsed.uri`'s own shape — a field that reaches ES
  specifically because it's deliberately never renamed and never
  mapped: true permanent closure needs the benchmarked runtime sweep or
  a full Sigma-rule-corpus parse, filed as
  [#405](https://github.com/voltron-1/Suburban_SOC/issues/405) rather
  than letting #367's own "close...permanently" title go silently
  unaddressed.

**M18 wrapped 2026-08-17** — 12/16 closed. Remaining: #326 (not
actionable, needs real Windows/PowerShell telemetry this environment
doesn't have) and 3 follow-ups filed during this milestone's own review
cycles ([#396](https://github.com/voltron-1/Suburban_SOC/issues/396) —
a companion detection rule for #370's local-spray blind spot;
[#403](https://github.com/voltron-1/Suburban_SOC/issues/403) — remove a
verified-redundant `log.file.path` self-copy;
[#405](https://github.com/voltron-1/Suburban_SOC/issues/405) — full
byte-clamp closure needs a benchmark or full rule-corpus parse), each
deliberately scoped out of the fix that found it rather than bundled in
unreviewed. No further M18 work is queued.

**M16 progress:**

- [x] **#361 (P2, security) — COMPLETE, MERGED** — `agent_checkpoints_
  compactor` (live since #357) holds read+delete on `agent-checkpoints-*`
  with no document-level restriction (Basic license, no DLS); nothing at
  the ES layer stopped that credential from deleting a live claim doc
  directly, after which `claim_approval()`'s `op_type=create` grants a
  fresh claim unconditionally — reopening the at-most-once execution gate.
  `metric_stuck_approval_claims()`/`metric_orphaned_claims()` both read
  *healthier*, not worse, when this happens.
  [PR #375](https://github.com/voltron-1/Suburban_SOC/pull/375) merged
  2026-08-16 (squash), auto-closing #361 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (17/17 CI green,
  parallel security-auditor + code-reviewer sub-agent review, plus two
  tester-debugger live-verification rounds against the real stack).
  Added a new `vanished_claims` SLO metric: each run persists a snapshot
  of every CLAIMED-or-RESOLVED claim doc's identity; the next run `_mget`s
  the prior snapshot to catch any that no longer exist at all. RESOLVED
  was added alongside CLAIMED — beyond the issue's own literal scope — after
  a tester-debugger live-verification finding: `claim_approval()`'s
  `op_type=create` only checks doc *existence*, not phase, so deleting a
  RESOLVED doc (a confirmed-successful execution that must never be
  re-winnable) is exploitable the same way, and arguably worse — a real
  second dispatch of a completed containment action. RELEASED is
  deliberately excluded: the compactor's own 90-day retention already
  deletes those routinely, by design.
  Two parallel review rounds independently converged on the same root
  defect in the first draft: Elasticsearch's `exists` query doesn't match
  a field indexed as `[]`, so keying the baseline lookup on the snapshot
  field itself silently skipped every quiet run (the common case — claims
  resolve in seconds). Fixed by keying on an always-non-empty companion
  timestamp instead, bounded both past (a freshness window, default 2
  days) and future (rejects a forged baseline dated ahead of `now`).
  Also fixed: `slo_metrics_reader` never had `read` on `soc-slo-metrics`
  (only `create_index`/`create` — write-only by design until this metric
  needed to read its own history back), so the new metric would 403 under
  the real service account despite passing every mocked test — live
  confirmed 403-then-200 across the fix. A missing-index cold start now
  uses `ignore_unavailable=true` instead of 404ing into a spurious P1
  alert on the first-ever run. `_mget` per-doc errors (e.g. a whole tenant
  index gone) raise instead of being silently counted as vanished. The
  persisted snapshot is validated before it can reach a real `_mget`
  request body, since any `soc-slo-metrics` writer other than the
  compactor credential could otherwise shape it.
  Filed [#373](https://github.com/voltron-1/Suburban_SOC/issues/373)
  (no dashboard panel, no durable per-run record of which claim vanished)
  and [#374](https://github.com/voltron-1/Suburban_SOC/issues/374)
  (`soc_admin`'s `soc-*` wildcard can itself write/erase this same SLO
  history) as new M16-adjacent follow-ups, deliberately out of scope.
  M16 down to its 2 remaining issues: #358 (next up) and #265 (still
  deferred, gated on a real endpoint this environment doesn't have).
- [x] **#358 (P3, low) — COMPLETE, MERGED** — two related threat-intel
  pipeline gaps: no detection if `threat-intel-indicators` empties
  unexpectedly, and `compact_threat_intel.py`'s `_delete_by_query` client
  timeout doesn't cancel the server-side ES task if exceeded.
  [PR #377](https://github.com/voltron-1/Suburban_SOC/pull/377) merged
  2026-08-17 (squash), auto-closing #358 — same review-bypass basis as
  every prior session fix (17/17 CI green, parallel security-auditor +
  code-reviewer sub-agent review, plus a tester-debugger live-verification
  pass against the real stack).
  Root-cause finding that changed Part 1's shape: `rules/elastic_watcher/
  intel_feed_stale.json` — the pre-existing Watcher this issue's own text
  assumed was live — has **never actually fired** on this deployment.
  Live-confirmed: `xpack.license.self_generated.type=basic`, and every
  Watcher API call (including a brand-new trivial watch) is rejected with
  `security_exception: current license is non-compliant for [watcher]`
  (403) — `deploy_dashboards.sh`'s watcher-install step has silently
  absorbed this since WS1.3. Confirmed with the repo owner: migrated
  detection into `slo_metrics.py`'s SLO-metric framework (same proven
  ntfy-alerting/indexed-history pipeline as #361's `vanished_claims`)
  instead of adding a second, equally dead Watcher. Two new metrics:
  `intel_feed_stale_heartbeats` (reimplements the retired Watcher's exact
  condition) and `intel_indicator_count_drop_pct` (the actual new ask —
  real index count vs. the latest heartbeat's belief). `intel_feed_stale.json`
  retired the way #267 retired `soar_quarantine_alert.json`.
  security-auditor found the wipe-detection metric itself could be
  blinded by the exact credentials named in the issue's own threat model:
  `threat_intel_compactor` holds `delete` on `threat-intel-meta` itself
  (wiping every heartbeat silences the heartbeat-based comparison), and
  `intel_writer` holds `index` on the same index (forging one
  `indicator_count:0` heartbeat does the same). Closed by adding a second,
  independent baseline — this run's real actual count persisted onto its
  own `soc-slo-metrics` doc, which neither credential can write — and
  taking the worse of the two comparisons. Also found and fixed:
  `slo_metrics_reader` had no grant at all on either `threat-intel-*`
  index (both new metrics would 403 in production despite passing every
  mocked test — the same #275/#361 bug shape); `threat_intel_compactor`
  had no `cluster:monitor` privilege (the new task-polling would 403 on
  every scheduled run); a failed async delete task could report
  `completed:true` with neither `response` nor `error`, silently read as
  "0 deleted, clean success"; a single transient poll failure used to
  abort the whole wait immediately without reconciliation guidance; a
  non-numeric heartbeat field (`intel_writer`-forgeable) would have
  crashed the entire metrics run. tester-debugger live-verified both
  role-grant fixes (403→200), a real async delete + task-poll round trip
  including two independently-reproduced real task failures, and the
  worse-of-two-baselines fix against real persisted data.
  Filed [#376](https://github.com/voltron-1/Suburban_SOC/issues/376)
  (`compact_agent_checkpoints.py` has the identical async-delete gap) as a
  new follow-up, deliberately out of scope.
  **M16 down to just #265**, still deferred (gated on a real endpoint this
  environment doesn't have) — no actionable work remains in this milestone.

**M17 progress:** 2 of 8 open issues (#283, #333) are not actionable right
now — #283 is externally blocked on real Windows telemetry (same shape as
#265), #333 is a speculative OpenSSH-version investigation the issue itself
flags as low-priority/optional. Working the remaining 6 smallest/most-
contained first. **M17 down to 3 open** after #332 — #283 and #333 remain
not actionable; #331 (scan-detection.zeek's SYN-only/spoofable Port_Scan)
is the last actionable candidate.

- [x] **#281 (P3, bug) — COMPLETE, MERGED** — `build_attack_coverage.py`'s
  `navigator_layer()` built one ATT&CK Navigator technique object per rule
  with no dedup; two rules tagging the same technique under the same
  tactic produced two `techniqueID` objects, which Navigator renders as
  one, silently dropping the other's score/comment. Published coverage was
  108 rule-mappings reported as "108 techniques" when only 75 are unique.
  [PR #381](https://github.com/voltron-1/Suburban_SOC/pull/381) merged
  2026-08-17 (squash), auto-closing #281 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  The issue's own suggested fix ("group by techniqueID alone") turned out
  to be wrong: T1078.003 legitimately appears under BOTH Initial Access
  (`auth_linux_ssh_root_login.yml`) and Privilege Escalation
  (`auth_linux_su_session_opened.yml`) — two real, distinct ATT&CK tactic
  mappings for the same sub-technique, which Navigator's layer schema
  scores per TACTIC COLUMN, not globally. Fixed by grouping on the
  `(techniqueID, tactic)` pair instead; security-auditor independently
  re-derived Navigator's layer-format semantics to confirm this is the
  real uniqueness constraint. Review found the new regression test file
  was never wired into any CI workflow (the guard was inert, now runs in
  `detections.yml`) and that the real-corpus duplicate check would still
  pass under the issue's own wrong fix (closed with a corpus-independent
  pair-set-equality test pinning both directions). Also closed: a rule
  title containing `|`/`;` would corrupt generated docs (now fails loudly
  at harvest time); an unresolvable tactic tag silently rendered a dead
  "Unknown" Navigator cell (now fails loudly too); a naive comment merge
  bloated a 5-rule real case to a 949-character tooltip (now 609).
  Filed [#378](https://github.com/voltron-1/Suburban_SOC/issues/378)
  (`harvest()` keeps only the first tactic/technique tag per rule, 21/6
  secondary tags dropped), [#379](https://github.com/voltron-1/Suburban_SOC/issues/379)
  (`slo_metrics.py`'s `metric_coverage()` inherits the same legitimate
  76-vs-75 multi-tactic double-count), and
  [#380](https://github.com/voltron-1/Suburban_SOC/issues/380) (README/SOP
  quote long-stale 37/9/35 coverage numbers) as follow-ups, all
  deliberately out of scope.
- [x] **#365 (P3, low, detection) — COMPLETE, MERGED** — `net_zeek_
  executable_download.yml`/`net_zeek_smtp_attachment_executable.yml`
  never matched a downloaded shell script — Zeek reports
  `text/x-shellscript`, not the `application/x-sh`/`application/x-
  shellscript` strings the rules' `mime_type` list used.
  [PR #385](https://github.com/voltron-1/Suburban_SOC/pull/385) merged
  2026-08-17 (squash), auto-closing #365 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (17/17 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  The issue also asked to check the rest of the list for similar
  staleness rather than assume it was accurate — live-verified all 9
  original entries against the real pinned `zeek/zeek` image (real
  payloads served over HTTP, captured to a real pcap, replayed through
  the pinned image, `files.log`'s real `mime_type` read back). Found Zeek
  does NOT use general-purpose libmagic at all for file-analysis MIME
  detection — its own independent, much narrower signature engine
  confirmed 5 of the 9 original entries are structurally dead (never
  producible): `application/x-msdownload`, `application/vnd.microsoft.
  portable-executable`, `application/x-elf`, `application/x-pie-
  executable`, `application/x-sh`. Most notable: `application/x-pie-
  executable` (#228) was added on general libmagic's behavior for PIE
  executables, but Zeek's own detector can't distinguish a PIE executable
  from a shared library and reports both as `application/x-sharedlib` —
  #228's own test case was already covered the whole time; the dedicated
  entry it added was dead weight, not a fix. Both rules cut from 9
  entries to 4, all live-confirmed: `application/x-dosexec`,
  `application/x-executable`, `application/x-sharedlib`, `text/x-
  shellscript`.
  security-auditor (working from static analysis only, no shell access in
  that session) still found real gaps in the evidence: a citation to a
  nonexistent `docker-compose.yml` zeek pin (fixed); a now-stale precedent
  in the image-bump SOP still citing the disproven #228 addition (fixed);
  a pre-existing false claim that an emulation script exercises this rule
  when it fetches over HTTPS, invisible to Zeek (disclosed, filed as
  [#383](https://github.com/voltron-1/Suburban_SOC/issues/383)); a
  single-file grep insufficient to prove "never producible" (broadened to
  the whole image tree, still zero matches); and — most substantively —
  that the original PE test used a hand-crafted header rather than
  genuine compiler output. Closed by re-testing against three REAL
  Windows binaries pulled from this WSL host's own mounted `C:\Windows`
  (notepad.exe, kernel32.dll, a genuine .NET assembly) — all three landed
  `application/x-dosexec`, identically confirming the original finding.
  code-reviewer independently found (and, via a reverted mutation test,
  proved) that the new regression test omitted `application/x-
  shellscript` itself — the exact original wrong string #365 was filed
  over — from its dead-mime-type denylist; fixed and re-verified via the
  same mutation. A late CI failure (`SIEM_KQL_Documentation.md` stale)
  turned out to be the same still-open #330 unpinned-toolchain-drift class
  this repo has hit before — my local `sigma-cli` bundled an older
  `pysigma-backend-elasticsearch` than CI's unpinned install pulls;
  regenerated against a venv replicating CI's exact install.
  Filed [#382](https://github.com/voltron-1/Suburban_SOC/issues/382)
  (SMTP-specific mime_type behavior inferred from HTTP testing, never
  independently confirmed), #383 (above), and
  [#384](https://github.com/voltron-1/Suburban_SOC/issues/384)
  (Python/Perl/archive/container payload classes never covered by either
  rule, old or new list) as follow-ups, all deliberately out of scope.
- [x] **#351 (P3, low, detection, tech-debt) — COMPLETE, MERGED** —
  `tests/detections/sigma_eval.py`'s `_match_one()` had no handling for an
  event field whose VALUE is a Python list — every field previously
  selected by a rule in this corpus is scalar. `dns.answers` (Zeek's
  `answers`, #292) is the corpus's first genuinely multi-valued field: real
  Elasticsearch evaluates a query against a multi-value keyword field
  per-element (OR — a doc matches if ANY element matches), but the old code
  stringified the whole list via `str(value)` and regex-matched against
  that repr blob (`"['a', 'b']"`) instead — silently benign for #292's own
  rule only because its `.*`-wrapped pattern and scalar fixture never
  exposed the gap. [PR #388](https://github.com/voltron-1/Suburban_SOC/pull/388)
  merged 2026-08-17 (squash), auto-closing #351 — no GitHub-side human
  review, same review-bypass basis as every prior session fix (12/12 CI
  green, parallel security-auditor + code-reviewer, then tester-debugger
  for independent validation).
  Fixed with per-element OR recursion in `_match_one()`. security-auditor
  (round 2) found the fix needed more than a blanket recursion: Sigma's
  `all` modifier expands one selector into several ANDed query clauses,
  each independently evaluated per-element against the SAME field — real
  Elasticsearch computes AND-over-targets(OR-over-elements), not
  OR-over-elements(AND-over-targets), which is what a naive per-element
  recursion gives (one element required to satisfy every target). Not
  live-exploitable today (no rule combines `contains|all`/`all` with a
  genuinely multi-valued field in this corpus), but wrong in exactly the
  code this fix adds, so corrected rather than shipped latent. Also closed:
  a dict-shaped value now raises `TypeError` instead of silently
  regex-matching its repr (the same bug class #351 fixed, one level down,
  for the ECS-canonical `dns.answers.data/type/ttl` object shape this
  evaluator deliberately doesn't model); an empty-list value no longer
  bypasses this file's rule-authoring shape guards (`re`+list-target,
  numeric+list-target `ValueError`s — `any([])` previously short-circuited
  before those checks ever ran); a docstring overclaim ("first genuinely
  multi-valued field") corrected after it was found to contradict the
  module's own SCOPE note about `process.args` array semantics.
  Two successive review rounds caught that the regression-pinning tests
  didn't actually pin anything: code-reviewer and security-auditor
  independently found the first draft relied on #292's own rule, whose
  `.*pattern.*` shape absorbs a Python list repr's punctuation well enough
  that the pre-fix buggy code passed the test too; replaced with a
  bare-equality `_match_one()`-level test. tester-debugger then found the
  *replacement* `all`-modifier test used `contains`, whose substring search
  also happened to pass against the real pre-fix code (whole list
  stringified to one blob, both target substrings trivially present
  regardless of which element they came from) — replaced with bare
  equality again. Every regression test in the final diff was empirically
  confirmed via `git stash` mutation testing to fail against the real
  pre-fix committed code and pass with the fix, not just reasoned about.
  Filed [#386](https://github.com/voltron-1/Suburban_SOC/issues/386)
  (`cidr`/numeric modifiers silently ignore `all` against a target list,
  pre-existing) and [#387](https://github.com/voltron-1/Suburban_SOC/issues/387)
  (`re` modifier's newline/DOTALL behavior vs. real Lucene regexp, needs
  live-fire confirmation) as follow-ups, both deliberately out of scope.
- [x] **#352 (P3, low, detection, tech-debt) — COMPLETE, MERGED** —
  a Zeek `dns.answers` element over the template's `ignore_above:8191`
  (#292) was silently unindexed with no error and no visibility tag —
  `dns.answers` is a flat ARRAY, structurally excluded from
  `configs/logstash.conf`'s existing `long_fields` truncation-visibility
  mechanism (String-only byte-clamp). [PR #391](https://github.com/voltron-1/Suburban_SOC/pull/391)
  merged 2026-08-17 (squash), auto-closing #352 — no GitHub-side human
  review, same review-bypass basis as every prior session fix (17/17 CI
  green, two full rounds of parallel security-auditor + code-reviewer,
  plus a tester-debugger pass).
  Fixed with a new ruby filter block tagging `pipeline.oversized_dns_answer`
  (visibility only, no clamp/raise, per the issue's own scope), paired with
  a new `metric_oversized_dns_answer_count()` SLO metric matching the
  established `field_truncation_count`/`field_byte_clamp_count` precedent
  (#252/#263) rather than shipping a write-only tag. Two review rounds
  found real gaps beyond the literal ask: the first draft only checked
  Array values, silently skipping a SCALAR `dns.answers` — this corpus's
  own established fixture convention, and the exact shape an
  unauthenticated `:5514` POST actually produces; fixed, then a second
  round found a NESTED array (`[["<9000 chars>"]]`) was *also* silently
  skipped — live-confirmed against the real running Elasticsearch that it
  flattens arrays-of-arrays for a keyword field exactly like a flat array —
  fixed with `.flatten`. A dedicated test pinning the block's field
  path/output field name/tag name (this repo's established #263/#228/#217
  typo-regression class) initially missed two of the three literals
  because its scoping marker sat below the new guard/flatten lines; fixed
  by moving the marker earlier.
  **Major finding**: a tester-debugger agent crafted a real, wire-verified
  DNS packet (a TXT resource record built from 40 distinct 250-byte
  character-strings) and replayed it through the real pinned
  `zeek/zeek:8.2.1` image. Zeek joins the character-strings into one
  `answers[]` element as expected, but hard-truncates that joined string
  at ~4096 characters with NO truncation marker anywhere in `dns.log` —
  meaning the `>8191` check this fix is built around is structurally
  unreachable for real TXT-record traffic today. Disclosed honestly in
  four places rather than silently shipping a check with a disproven
  premise; kept as defense-in-depth (correct for any non-Zeek producer,
  including the same unauthenticated `:5514` input). Filed
  [#389](https://github.com/voltron-1/Suburban_SOC/issues/389) (Zeek's own
  silent truncation — the actual, more directly exploitable blind spot
  this review uncovered, needs a Zeek-side fix) and
  [#390](https://github.com/voltron-1/Suburban_SOC/issues/390) (sibling
  array fields — `related.user`/`related.hosts`/`threat.feed.name` — with
  the same shape) as follow-ups, both deliberately out of scope.
  Live-verified end to end against the real pinned
  `docker.elastic.co/logstash/logstash:9.3.2` image (full config parse +
  runtime behavior for 11+ event shapes via a throwaway stdin/stdout
  pipeline) and against the real running dev-stack Elasticsearch (nested-
  array flattening behavior and the new live-fire test both confirmed
  live, not just reasoned about). **M17 now 4/8 closed** — #283 and #333
  remain the only open issues not currently actionable (externally
  blocked / speculative-optional, per NEXT UP above); the 2 smallest/
  most-contained remaining candidates are #332 and #331.
- [x] **#332 (detection) — COMPLETE, MERGED** — `policy/protocols/ssh/
  detect-bruteforcing` (#261) fires at 30 failed auths from one source
  within 30 minutes; 29 attempts in 30 minutes (or a distributed set of
  sources each staying under 30) produced zero T1110 signal anywhere in
  this pipeline. [PR #394](https://github.com/voltron-1/Suburban_SOC/pull/394)
  merged 2026-08-17 (squash), auto-closing #332 — no GitHub-side human
  review, same review-bypass basis as every prior session fix (13/13 CI
  green after a transient GitHub-infrastructure outage on the CodeQL
  upload step required two retries — the analysis itself was clean, 0
  findings, both times; not a real code issue), two full rounds of
  parallel security-auditor + code-reviewer.
  Added `rules/sigma/net_zeek_ssh_session_cadence.yml` (single-event
  logic-of-record, `status: experimental`, matching this repo's
  established threshold-companion pattern) + `rules/elastic/threshold/
  net-zeek-ssh-session-cadence.ndjson` (5+ SSH sessions from one source
  within a 6-minute lookback), reading `zeek.ssh` session records
  directly rather than the aggregated `zeek.notice` the pipeline's T1110
  tag reads. Live-verified via a real captured SSH session (client/server
  on separate docker network namespaces over a real bridge network,
  replayed through the pinned `zeek/zeek:8.2.1` image) that Zeek's
  `auth_success` field is entirely absent, not false, on failed-auth
  `ssh.log` records — confirming why the rule deliberately does not key
  on it. Also added a `field-mapping-zeek-ssh` transformation (first
  `zeek/ssh` Sigma rule in the corpus, so the established 4-tuple
  invariant applies), an `emulation_telemetry.map` entry pairing the
  existing `sim_brute_ssh.sh` script with the new rule, a fixtures.json
  entry, and regenerated `docs/detections/*`.
  Two review rounds found the rule's original framing overclaimed what it
  actually improves — 5 sessions/6 minutes and 30/30 minutes are the SAME
  steady-state rate (~1/min), so this rule improves detection latency for
  a burst-shaped attack and drops the `auth_success` dependency, but does
  NOT lower the sustained rate an attacker can pace under to evade both
  rules indefinitely; corrected in both files' descriptions rather than
  left overclaimed. Also found and documented: `SSH::Info$client` is
  `&optional` in Zeek's own schema (a session on a lossy vantage can write
  an ssh.log row with `client` absent, silently undercounted); the
  "mutually exclusive by construction" claim needed correction (disjoint
  datasets, but `metric_raw_alert_volume()` sums both sub-counts into one
  combined value); a fixture true_negative wasn't actually discriminating
  the `startswith` boundary (and a first replacement candidate turned out
  to be a real false negative — a lowercase variant that's actually a
  TRUE positive under Sigma's case-insensitive default, caught by
  checking directly against `sigma_eval.py` before landing the fixture).
  A CI failure on the first PR run (`SIEM_KQL_Documentation.md` stale)
  turned out to be a NEW, more precise root cause than the already-
  tracked #330 toolchain-drift class: not cross-version package drift,
  but Python 3.11 (CI's runner) vs 3.12 (local) producing different
  Lucene escaping for 2 unrelated pre-existing rules with the identical
  `pysigma-backend-elasticsearch` version — regenerated under a real
  `python:3.11.15` container to match CI exactly; correction posted to
  #330.
  Filed [#392](https://github.com/voltron-1/Suburban_SOC/issues/392) (a
  long-window companion for genuinely sustained low-and-slow coverage,
  since #332's own rule doesn't lower the rate floor) and
  [#393](https://github.com/voltron-1/Suburban_SOC/issues/393)
  (threshold-rule test hardening: the 1-minute overlap window doesn't
  fully close the straddle gap it claims to, on this file and the
  pre-existing Windows precedent it copied the pattern from;
  `ThresholdLiveFireTests` only live-fire-exercises one of three
  threshold rules) as follow-ups, both deliberately out of scope.
  **M17 now 5/8 closed** — #283 and #333 remain not actionable; #331
  (scan-detection.zeek's spoofable SYN-only Port_Scan) is the last
  actionable candidate.
- [x] **#331 (detection metric) — COMPLETE, MERGED** — `metric_raw_alert_
  volume()`'s `zeek_notices` sub-count is gameable: `scan-detection.zeek`'s
  `Scan::Port_Scan` fires on the initial SYN alone (no completed
  handshake), so a spoofed-source SYN sweep can generate one notice per
  forged source with zero real network presence, inflating the count in a
  way a before/after tuning comparison can't tell apart from real
  activity. [PR #395](https://github.com/voltron-1/Suburban_SOC/pull/395)
  merged 2026-08-17 (squash), auto-closing #331 — no GitHub-side human
  review, same review-bypass basis as every prior session fix, 17/17 CI
  green. Two full rounds of parallel security-auditor + code-reviewer,
  spanning three complete design attempts.
  Design 1 (rejected): moved TCP port-counting from `new_connection` to
  `connection_established`/`connection_rejected` (only count once the
  responder's reply was observed). security-auditor found this doesn't
  actually defend against spoofing at THIS deployment's capture topology —
  `zeek-host-capture.service` captures at the monitored host's OWN
  interface, so that host's real reply to a spoofed SYN (RST or SYN-ACK,
  sent to the forged address per standard TCP/IP behavior — the same
  mechanism behind SYN-flood reflection attacks) is exactly as visible to
  Zeek as a reply to a genuine one — and it cost real detection recall
  (filtered-host scans and non-SYN scan types stopped counting entirely).
  Design 2 (rejected): reverted to `new_connection` (full recall restored)
  and added a global per-window notice-volume cap
  (`port_scan_notice_budget`) plus a manual table-size cap
  (`ports_per_src_cap`, since Zeek has no `&max_size` attribute — confirmed
  via a genuine parser error against the pinned image). security-auditor
  found this introduced TWO new silent denial-of-detection primitives: a
  sub-second burst of spoofed sources exhausts the notice budget (blinding
  the sensor to a real concurrent scan for the rest of the window, with
  zero telemetry marking the loss), and an identical refuse-on-full policy
  on the per-source tracking table — and 30/hour didn't even bound the
  metric's real 7-day evaluation window. The reviewer's own recommendation
  — fix the metric's interpretability instead of fighting the sensor —
  became design 3.
  Design 3 (shipped): `scan-detection.zeek` fully reverted to its exact
  original, pre-#331 content (confirmed byte-identical, then re-verified
  live against the pinned `zeek/zeek:8.2.1` image after a comment-only
  history block was added). The actual fix lives entirely in
  `slo_metrics.py`: a new `_cardinality()` helper runs an Elasticsearch
  `cardinality` aggregation, and `metric_raw_alert_volume()` gained a
  `zeek_notices_distinct_sources` field scoped to the identical query as
  `zeek_notices` — a flood from many distinct (forged or real) sources now
  reads differently from a few real repeat scanners, the exact
  discrimination a sensor-side volume cap could never provide.
  A third review round (this design) found it sound with no further
  structural break, plus 3 MEDIUM/4 LOW findings, all fixed before merge:
  `_cardinality()` silently undercounted on a partial shard failure (now
  raises `MetricUnavailable` instead); the docstring's `precision_threshold`
  claim was wrong (the issue's own ~15k-source scenario exceeds the
  default 3000, making the aggregation approximate, not exact — harmless
  in practice, ~1-2% error still separates 15k from 5); the new signal had
  no documented consumer (added a "Known limitation" paragraph to the
  docstring plus matching SOP-022/SOP-147 notes: a small, FIXED number of
  forged sources sustained over the window can still evade this signal —
  it catches wide floods, not narrow high-volume ones); `scan-detection.
  zeek` carried zero record of this history (added a comment-only block);
  and a missing non-200 test for `_cardinality()` (added, for parity with
  `_count()`'s existing coverage). Also extracted the shared index-pattern
  string into one local variable so the count/cardinality calls can't
  structurally drift apart.
  **Consequence recorded on the issue and here:** `plans/20260811-issue-
  267-network-soar-trigger-coverage.md` framed T1046 staying out of live
  SOAR dispatch as "deferred until #331 is resolved" — with #331 closed
  via a metric-layer fix, that exclusion is now **permanent, not
  deferred**; no source-authenticity signal exists for `Scan::Port_Scan`
  at this deployment's capture vantage point, and two rounds of live
  security review confirm that gap can't be closed without losing real
  detection recall or introducing a new denial-of-detection primitive.
  `docs/SOP-022-anomaly-validation-procedure.md` and `docs/SOP-147-
  evidence-validation-procedure.md` both now say "indefinitely."
  **M17 now 6/8 closed** — #283 (externally blocked) and #333
  (speculative/deprioritized) are the only issues remaining, neither
  currently actionable; no further M17 work is queued.

**M17 resumed 2026-08-17** — the "no further work queued" note above was
written before the project-board milestone-backfill audit (see the audit
entry above NEXT UP) retroactively assigned 7 review-discovered follow-up
issues back to M17 that had been filed without a milestone during M17's
own review cycles: #382, #383, #384, #386, #387, #392, #393. M17 is
actually **9 open, not 2** — #283/#333 remain not actionable; the other 7
are real, working smallest/most-contained first: #386 → #387 → #382 →
#383 → #384 → #392 → #393.

- [x] **#386 (P3, tech-debt, detection) — COMPLETE, MERGED** — `sigma_eval.py`'s
  `_match_one()` accepted the `all` modifier in `_SUPPORTED_MODS` for every
  modifier but only the string/contains/endswith/startswith path actually
  branched on it — `cidr` always ORed across a target list regardless of
  `all` (Sigma's documented semantics are AND), and a numeric modifier
  accepted `all` syntactically without ever validating it.
  [PR #408](https://github.com/voltron-1/Suburban_SOC/pull/408) merged
  2026-08-17 (squash), auto-closing #386 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  Fixed by raising `ValueError` for both combinations rather than
  implementing real AND-cidr semantics — matches this module's established
  fail-loudly convention, and (security-auditor) every other semantic
  branch this file implements under real confidence cites a live probe
  against real Elasticsearch/`sigma convert`, which doesn't exist yet for
  `cidr|all`. code-reviewer live-confirmed the issue's own title
  ("re/cidr modifiers") was right and the first draft was incomplete: `re`
  had the identical gap for a scalar target, missed entirely in the first
  pass — added a third matching guard. security-auditor found a related
  vacuous-truth bypass: an empty target list against a multi-valued event
  field made the #351 list-value-recursion path's `all([])` return `True`
  without ever reaching any of the three new guards — fixed with the same
  "malformed rule shape fails loudly" precedent `_block_match` already
  uses for an empty selection block. Every new guard mutation-tested
  individually (stashed the fix, confirmed each assertion fails; restored,
  confirmed all pass), including through the #351 list-value recursion
  path specifically, not just the direct scalar-value call.
  security-auditor's two remaining MEDIUM findings — modifier-combination
  validation happens at evaluation time inside `_block_match`'s
  first-failing-key short-circuit rather than load time (a malformed key
  can go unvalidated depending on fixture/key order), and the same
  "modifier silently dropped by branch precedence" root cause exists for
  other cross-branch combos this issue didn't ask about (`contains+gt`,
  `re+cidr`) — are real but pre-existing properties of this evaluator, not
  introduced by this fix; filed
  [#407](https://github.com/voltron-1/Suburban_SOC/issues/407) rather than
  expanding this fix's scope. Zero live corpus impact (confirmed via grep:
  no rule combines `all` with `cidr`/numeric/`re` today) — a CI-fidelity
  fix, not a production behavior change. **M17 now 7/15 closed** (8 open
  remaining: #283/#333 not actionable, 6 real follow-ups left) — #387 next.
- [x] **#387 (P3, tech-debt, detection) — COMPLETE, MERGED** — `sigma_eval.py`'s
  `re` modifier used Python's `re.fullmatch(target, s)` with no `re.DOTALL`,
  so `.` could not match a literal newline in the event value — untested
  against whether real Elasticsearch's compiled Lucene `regexp` query
  behaves the same way, only reasoned about.
  [PR #409](https://github.com/voltron-1/Suburban_SOC/pull/409) merged
  2026-08-17 (squash), auto-closing #387 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  Live-verified against the real dev-stack Elasticsearch (pinned 9.3.2):
  indexed a `dns.answers` value with an embedded literal newline,
  constructed so a non-DOTALL match is mathematically impossible (two
  60-char charset runs separated by one `\n` the character class
  excludes, forcing `.*` to cross the newline for `net_zeek_dns_txt_
  answer_abuse.yml`'s pattern to fully match) — confirmed it matches the
  real compiled query. Fixed the `re` modifier's `re.fullmatch` call and
  added a new **permanent live-fire test** (not just a one-off manual
  check) that indexes the same fixture into real Elasticsearch and
  asserts the compiled query matches — ran and passed against the real
  cluster, and will run for real (not skip) in CI since `detections.yml`
  pins the same ES version.
  code-reviewer independently live-verified a real scope gap in the first
  draft: `cmp()`'s `contains`/`endswith`/`startswith`/bare-equality paths
  build the identical `.`/`.*` from Sigma's own `*`/`?` wildcard syntax
  via `_sigma_wildcard_to_regex()`, with the same missing-DOTALL gap —
  live-confirmed a Lucene wildcard query (`msg:ab?cd`) also crosses an
  embedded newline the same way. Fixed all four call sites (independently
  re-confirmed live against real ES outside the test suite too). Zero
  live corpus impact either way — confirmed via grep that no rule embeds
  a bare `*`/`?` wildcard in a contains/endswith/startswith/bare-equality
  target today, and only 1 of the 4 `re`-modifier rules in the corpus
  targets a newline-plausible field (the other 3 target DNS query names).
  security-auditor hit 5 consecutive infra 500 errors across every retry
  for this specific issue — worked around with a general-purpose-agent
  fallback doing an independent live-ES security investigation (its own
  control experiments: an anchoring probe and a doc-value/normalization
  probe, both ruling out false-positive match mechanisms other than
  DOTALL itself; verdict "merge as-is"). Every new guard mutation-tested
  (both the `re` modifier and all four wildcard-path call sites).
  **M17 now 8/15 closed** (7 open remaining: #283/#333 not actionable, 5
  real follow-ups left) — #382 next (SMTP `mime_type` live verification).
- [x] **#382 (P3, detection) — COMPLETE, MERGED** — #365's `mime_type`
  live-verification for `net_zeek_executable_download.yml`/`net_zeek_smtp_
  attachment_executable.yml` served every payload over HTTP; this rule's
  own SMTP-specific behavior (source tagging, whether a declared
  Content-Type header can influence detection when content-magic is
  inconclusive) had never been independently confirmed.
  [PR #412](https://github.com/voltron-1/Suburban_SOC/pull/412) merged
  2026-08-17 (squash), auto-closing #382 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  Built a throwaway raw-socket SMTP client/server, captured a real pcap
  (first attempt split tcpdump into a separate `--net=host` container and
  captured 0 packets — this sandbox's shell network namespace is isolated
  from a separate container's namespace; fixed by running capture+client
  +server all inside one container), replayed through the same pinned
  `zeek/zeek:8.2.1` image #365 used. 4 scenarios against a real Windows PE
  binary (notepad.exe, pulled from this WSL host's own mounted
  `C:\Windows`): full binary → `source:SMTP`, `mime_type:application/x-
  dosexec` (identical to #365's HTTP result); 16-byte truncation → still
  recognized (didn't reach the inconclusive case intended); 200 zero-bytes
  → `mime_type` field entirely absent, not a declared-header fallback;
  quoted-printable encoding → correctly decoded, still typed correctly
  (not a bypass for this one alternate encoding). Confirms
  `application/x-msdownload` stays correctly excluded from this rule's
  list — no detection-logic changes needed.
  Two review rounds found the first draft overclaimed and underdisclosed:
  code-reviewer found "no declared-header fallback path exists" needed
  scoping to the one all-zero-byte test actually run, and the failed
  16-byte-truncation attempt needed disclosing (silently dropped in the
  first draft) — both fixed. security-auditor (working this time — no
  infra 500s) found the absent-`mime_type` result was framed only as
  reassurance when it's itself a real, disclosed-nowhere evasion primitive
  (archive/packed/script-interpreter payload classes, already tracked as
  #384) — added a `fixtures.json` true_negative pinning the observed
  shape and disclosed the gap explicitly; flagged only base64
  Content-Transfer-Encoding was tested, prompting a 4th live scenario
  (quoted-printable) with the existing harness before finalizing — came
  back clean, a genuinely useful additional data point, not a box-check.
  Full methodology, SHA-256 hashes, and raw `files.log` JSON records
  preserved in `findings/20260817-382-smtp-mime-verification.md` (no raw
  pcap committed, matching `evidence/README.md`'s hash-only convention).
  Filed [#410](https://github.com/voltron-1/Suburban_SOC/issues/410) (the
  STARTTLS-plaintext-only scope caveat is invisible in every downstream
  rendering — generated docs, Kibana — move it into the rule title) and
  [#411](https://github.com/voltron-1/Suburban_SOC/issues/411) (no
  permanent CI regression owner for Zeek's own MIME-detection behavior,
  unlike this repo's `test_live_fire.py`/`test_field_truncation.py`
  precedent for this class of claim) as follow-ups, both deliberately out
  of scope. **M17 now 9/15 closed** (6 open remaining: #283/#333 not
  actionable, 4 real follow-ups left) — #383 next (false EXPLOITATION
  emulation pairing).
- [x] **#383 (P3, bug, detection) — COMPLETE, MERGED** — `net_zeek_
  executable_download.yml`'s description already disclosed (#365 review)
  that `sim_malware_download.sh`'s default sample never exercises this
  rule; the same false "wired" claim survived in `emulation_telemetry.map`
  and `coverage_checklist.md`.
  [PR #416](https://github.com/voltron-1/Suburban_SOC/pull/416) merged
  2026-08-17 (squash), auto-closing #383 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  Chose disclosure (#383's own option (b)) over building a new working
  emulation (option (a) — real design/live-fire work, out of scope for a
  priority:low docs-accuracy bug, explicitly valid per the issue's own
  acceptance criteria). Both reviewers approved the scope call but found
  the disclosure didn't reach far enough: `validate_emulation_map.py`
  parses comment lines out entirely before any section/key parsing, so a
  comment-only disclosure never reached the CI step literally named
  "purple-team loop is real" or SOP-147 Step 0.4's "expect 22/22 green" —
  both still showed a bare, indistinguishable PASS. Fixed by renaming the
  section itself (`EXPLOITATION` → `EXPLOITATION_UNVERIFIED`) so the gap
  reaches every automated rendering (console/`--json`/`--markdown`), live-
  confirmed via the real validator; added a SOP-147 pointer; marked the
  checklist checkbox itself, not just its indented note; cross-referenced
  `test_live_fire.py`'s real-ES coverage so the disclosure doesn't read as
  "this rule is unverified" (only the emulation payload is).
  Filed [#413](https://github.com/voltron-1/Suburban_SOC/issues/413) (the
  disclosure still doesn't reach 5 more operator-facing locations — the
  sim script's own output, its README, SOP-147's evidence step, the
  evidence log, `verify_detections.py`), [#414](https://github.com/voltron-1/Suburban_SOC/issues/414)
  (`coverage_checklist.md` is one pairing short of the map and 3 ATT&CK
  technique IDs disagree between the two files — pre-existing, surfaced
  during review) and [#415](https://github.com/voltron-1/Suburban_SOC/issues/415)
  (build a genuinely working emulation, option (a)) as follow-ups, all
  milestoned, all deliberately out of scope. **M17 now 10/15 closed** (5
  open remaining: #283/#333 not actionable, 3 real follow-ups left) —
  #384 next (mime_type coverage expansion for script interpreters/
  archives/containers).
- [x] **#384 (P3, detection) — COMPLETE, MERGED** — live-measured every
  "unconfirmed" mime_type class the issue asked about (Python/Perl/Ruby
  scripts, batch, PowerShell/VBScript/JS/WSF, HTA, ISO/archives, LNK
  shortcuts, MSI installers, Mach-O binaries) for `net_zeek_executable_
  download.yml`/`net_zeek_smtp_attachment_executable.yml`.
  [PR #419](https://github.com/voltron-1/Suburban_SOC/pull/419) merged
  2026-08-18 (squash), auto-closing #384 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green,
  parallel security-auditor + code-reviewer sub-agent review).
  13 real payloads (real genisoimage/msitools/clang output where a real
  tool exists, spec-accurate hand-built structures only where none does)
  over real plaintext HTTP, captured to a real pcap, replayed through
  the pinned zeek/zeek:8.2.1 image, cross-checked against Zeek's own
  signature source. Added 6 new confirmed entries to both rules, kept in
  sync: text/x-python, text/x-perl, text/x-ruby, text/x-msdos-batch,
  application/x-ms-shortcut, application/x-mach-o-executable.
  Deliberately did NOT add text/plain (too broad, what 4 of the asked-
  about classes plus text/html all produce) or application/msword (what
  a real MSI produces, per Zeek's own signature comment "non-specific
  and terrible" — filed #417). Both exclusions pinned by a new negative
  regression test.
  code-reviewer approved clean; security-auditor found 1 HIGH + 6 MEDIUM
  in the first draft's evidence chain, each closed with more live-fire
  work, not just wording: Mach-O only tested a thin binary (fat/
  universal, the dominant modern macOS form, has a separate signature) —
  built a REAL universal binary via `llvm-lipo` combining genuine
  arm64+x86_64 clang objects and live-confirmed the same mime_type;
  only 4 of 6 new values were spot-checked against real Elasticsearch —
  closed perl/ruby too; the batch-signature disclosure had an uncited
  prevalence claim contradicted by real evasions (`@setlocal` misses
  `@set ` by one space, leading whitespace/labels) — rewritten with the
  actual counterexamples; the shebang-gating for Python/Perl/Ruby and
  the .hta/text/html gap weren't disclosed at parity with the batch
  caveat, and the ".hta already covered" claim was checked and found
  wrong (`proc_creation_win_mshta_remote.yml` requires a CommandLine
  argument this delivery chain doesn't produce) — both fixed; the LNK
  entry's "dominant vector" framing contradicted the same description's
  own archive-gap paragraph (the dominant LNK chain wraps it in an ISO,
  which produces no mime_type at all) — now says it only covers the
  non-dominant bare-file case; falsepositives lists were stale and
  ATT&CK tags had no recorded non-change rationale — both fixed.
  Self-inflicted bug caught during this same pass: an earlier
  description draft's prose literally contained the string
  "attack.t1059.003", which `build_attack_coverage.py`'s whole-file
  regex scan (not a strict tags: parse) picked up as a real tag,
  silently reassigning this rule's coverage-doc technique from T1105 —
  caught by re-running the doc build before finalizing, not shipped.
  Full methodology, SHA-256 hashes, raw files.log records, and verbatim
  signature-source grep transcripts in
  `findings/20260817-384-mime-type-coverage.md`.
  Filed [#417](https://github.com/voltron-1/Suburban_SOC/issues/417)
  (MSI/Word ambiguity, security-relevant, needs its own solution) and
  [#418](https://github.com/voltron-1/Suburban_SOC/issues/418) (flat
  severity across a 10-value OR-block spanning very different real-
  world base rates) as follow-ups, both milestoned, both deliberately
  out of scope. **M17 now 11/15 closed** (4 open remaining: #283/#333
  not actionable, 2 real follow-ups left) — #392 next (long-window SSH
  cadence companion).
- [x] **#392 (P3, detection) — COMPLETE, MERGED** — #332's own review
  found its 5-session/6-minute rule normalizes to the same steady-state
  rate as detect-bruteforcing (~1/min) — doesn't lower the sustained
  rate an attacker can pace under to evade both rules indefinitely.
  [PR #422](https://github.com/voltron-1/Suburban_SOC/pull/422) merged
  2026-08-18 (squash), auto-closing #392 — no GitHub-side human review,
  same review-bypass basis as every prior session fix (13/13 CI green
  after one transient CI infra hang — a "Reporting Plane Coverage" job
  stuck 36 minutes on an unrelated apt-dependency step with zero
  prior-run precedent, cancelled and re-run cleanly in 41s second time —
  parallel security-auditor + code-reviewer sub-agent review).
  Added a third SSH threshold rule pair (own Sigma UUID — the pairing
  invariant requires strict 1:1) detecting 15+ sessions/30min, a
  genuinely lower 0.5/min rate vs the existing rules' 1/min.
  security-auditor found a HIGH-severity design flaw in the first draft
  and held for a fix rather than approving: the initial windowing
  (interval 30m, from now-31m, matching every other threshold rule's
  flat +1-minute-overlap convention) only fully captures a real
  15-session/28-minute campaign in a single evaluation ~10% of the time
  (independently re-derived and confirmed: containment band / interval
  = 3/30) — the other ~90% splits the campaign across two evaluations,
  neither crossing the threshold alone, silently missing the rule's own
  stated purpose almost all the time. Fixed directly rather than
  deferred to #393 (which covers only the two pre-existing threshold
  files): interval 5m / from now-35m guarantees full containment for
  any campaign phase — live-verified both the original containment
  failure and the corrected guarantee against a real Elasticsearch
  terms aggregation. Also corrected the HONEST FRAMING section to state
  the binding evasion floor (14 sessions/31min, ~162 guesses/hour, a
  ~10% throughput reduction) rather than a looser illustrative example;
  carried forward two caveats the first draft dropped from the sibling
  rule (SOAR non-wiring, SLO metric inflation); added the SOC's own
  containment-broker SSH traffic as a disclosed false-positive source;
  fixed the emulation_telemetry.map disclosure, which itself
  reintroduced a zero-margin defect (bumped 15→20 words) and didn't
  address that the documented TARGET_HOST default is loopback,
  invisible to every real capture path in this repo.
  Filed [#420](https://github.com/voltron-1/Suburban_SOC/issues/420)
  (two Sigma files now share identical detection logic with no
  consistency test — also folded in ndjson-query-vs-compiled-Sigma-
  query drift and missing alert_suppression) and
  [#421](https://github.com/voltron-1/Suburban_SOC/issues/421) (whether
  detect-bruteforcing's own notice has ever actually fired on this
  pipeline — the number this rule's own justification is built on) as
  follow-ups, both milestoned, both deliberately out of scope.
  **M17 now 12/15 closed** (3 open remaining: #283/#333 not actionable,
  1 real follow-up left) — #393 next (threshold-rule test hardening),
  the last actionable M17 item.
- [x] **#393 (M17) — COMPLETE, MERGED** — the same window-math class of
  bug this issue was filed for existed on ALL 8 threshold files, not
  just the 2 named in the issue title: `lookback >= interval +
  detection_window` (guarantees full containment of any campaign phase)
  applied corpus-wide, correcting the flat `interval+1m` convention
  (partial containment only, as low as ~10% for window-width-comparable
  campaigns) on auth-win-bruteforce-{failed-logons,source-spray},
  auth-win-explicit-cred-account-sweep, all 3 disc-win-*-repeat files,
  and net-zeek-ssh-session-cadence (the -sustained sibling was already
  fixed in #392). Generalized `ThresholdLiveFireTests` from 1 hardcoded
  file to all 8, which caught a real, previously-undetected drift:
  auth-win-bruteforce-source-spray.ndjson's #370 IP-sentinel exclusion
  had never been back-ported into its paired Sigma file's own
  `detection:` block — fixed, and the ndjson's query is now the literal
  `sigma convert` output going forward instead of hand-typed. Building
  the generalized test also surfaced and fixed two live-fire test bugs:
  `source.ip`'s `ignore_malformed: true` silently drops non-IP-shaped
  test values from aggregation, and the two zeek-ssh threshold files
  (identical compiled query + aggregation field) had entity-value
  cross-contamination between test cases (18 counted instead of the
  expected <5). Parallel security-auditor + code-reviewer review of the
  full diff: code-reviewer found stale "6-minute" prose left over from
  before the window correction in 2 files, fixed; security-auditor (2
  consecutive infra connection failures on the dedicated agent, resolved
  via a general-purpose fallback) found a third instance of the same
  staleness plus a real gap — no test proved the *new* window was what's
  deployed, as opposed to merely proving *some* window existed — closed
  by adding a compile-time regression guard
  (`test_lookback_guarantees_full_containment_of_the_documented_detection_window`),
  mutation-tested against two revert scenarios. [PR
  #423](https://github.com/voltron-1/Suburban_SOC/pull/423). CI's
  `pytest-cov` job hung twice in a row on the unrelated "Install
  WeasyPrint native dependencies" step (same symptom, same workflow, as
  the #422 precedent) — confirmed against `gh run list` history (every
  prior run of this workflow completes in under 2 minutes) before
  cancel+rerun; the third attempt passed. No new follow-up issues filed
  — every finding from both reviews was fixed inline in this same PR.
  **M17 now 13/15 closed against the corrected count** — but re-checking
  the milestone directly (not just this doc's own running tally) surfaced
  that fixing #386/#387/#382/#383/#384/#392 across this resumed run had
  filed 10 real follow-up issues (#407, #410, #411, #413, #414, #415,
  #417, #418, #420, #421), each properly milestoned to M17 at creation
  time per this repo's own convention, none previously reflected in this
  doc's per-issue narrative or NEXT UP table. **True current state: M17
  is 13/25 closed, 10 real actionable issues still open, 2 permanently
  not actionable (#283, #333).** Continuing the same resumed run through
  this corrected queue, smallest/most-contained first, same cycle as
  before — not stopping to report completion, since M17 demonstrably
  still has real, milestoned, actionable work.
- [x] **#410 (M17) — COMPLETE, MERGED** — the smallest/most-contained item
  in the corrected queue: `net_zeek_smtp_attachment_executable.yml` and
  `net_zeek_smtp_mass_outbound.yml` both carry a real, load-bearing scope
  caveat (Zeek can only see SMTP content in plaintext — STARTTLS/implicit
  TLS sessions are invisible) that was buried in `description:` and
  didn't survive into any title-only downstream rendering. Moved the
  caveat into both titles. Parallel review: both reviewers independently
  caught the same adjacent pre-existing bug (a description claiming "the
  title says outbound" when that word has only ever been in the
  filename) — fixed. code-reviewer also caught a title-segment-ordering
  inconsistency against house convention — fixed. security-auditor
  exhaustively confirmed no consumer in the repo keys on rule title text
  (all key by filename/id) and the ATT&CK-coverage SLO is provably
  title-independent, then surfaced 3 out-of-scope pre-existing findings:
  [#424](https://github.com/voltron-1/Suburban_SOC/issues/424) (M20,
  MEDIUM — hardcoded ntfy notification titles containing an em dash
  likely silently drop the SOAR approval-request push, latin-1 header
  encoding),
  [#425](https://github.com/voltron-1/Suburban_SOC/issues/425) (M17,
  LOW — the coverage-doc generator's own em-dash delimiter can collide
  with an em-dash-containing title in a multi-rule grouping), and
  [#426](https://github.com/voltron-1/Suburban_SOC/issues/426) (M17 — a
  sibling rule, net_zeek_dns_doh_non_standard.yml, has the exact same
  class of buried-scope-caveat bug #410 itself fixed). Unpinned
  sigma-cli in CI was already tracked as #330 (M19) — no duplicate
  filed. [PR #427](https://github.com/voltron-1/Suburban_SOC/pull/427),
  all 12 CI checks green, no infra flakiness this time. **M17 now 14/27
  closed** (11 real follow-ups open, 2 not actionable) — continuing the
  same resumed run, smallest/most-contained next.
- [x] **#426 (M17) — COMPLETE, MERGED** — the sibling fix #410's own review
  flagged: `net_zeek_dns_doh_non_standard.yml` only catches the plaintext
  hostname lookup a DoH client performs before establishing its encrypted
  channel; a host with a hardcoded resolver IP skips that lookup entirely
  and is invisible to it. Moved into the title. security-auditor review
  reworded the first draft ("Hostname-Lookup Phase Only," named WHEN the
  rule sees traffic) to state the exploitable gap directly instead
  ("Blind to Hardcoded-IP DoH Clients"). Filed
  [#428](https://github.com/voltron-1/Suburban_SOC/issues/428) (M17) for
  an out-of-scope pre-existing gap the review found — unanchored
  `endswith` suffixes let a lookalike domain (`evilquad9.net`) match.
  Corrected #425's own framing via comment: its em-dash-delimiter
  collision isn't hypothetical, it's already live on `main` today (T1110
  is a 5-rule technique group with 2 colliding em-dash titles) — no code
  change, just re-scoped severity. [PR
  #429](https://github.com/voltron-1/Suburban_SOC/pull/429), all 12 CI
  checks green. **M17 now 15/28 closed** (11 real follow-ups open, 2 not
  actionable) — continuing the same resumed run, smallest/most-contained
  next.
- [x] **#425 (M17) — COMPLETE, MERGED** — filed during #410's own review:
  `build_attack_coverage.py`'s `_merged_comment()` used `" — "` (em dash)
  as its title<->rule Navigator-tooltip delimiter, the same character
  several rule titles legitimately contain — confirmed already ambiguous
  in a live, shipped tooltip (T1110, 5 rules, 2 em-dash titles) before
  the fix. Changed to `" :: "`, coupled to a named constant instead of
  duplicating the literal three separate times (the exact decoupling
  that let the original bug survive #281 → #410 → #425 unnoticed).
  Parallel review: code-reviewer caught the new regression test only
  exercising `_merged_comment()`'s short-circuit path, not the `else`
  branch the real bug actually lived in — fixed. security-auditor found
  the fix was correct but fragile, and (explicitly asked to be folded
  into this same PR) added a structural non-ambiguity test plus an
  ordering-independent assertion inside `_merged_comment()` itself, and
  a validation error message that names the offending character instead
  of a bare "rename it." Filed 3 more milestoned follow-ups from the
  same review:
  [#430](https://github.com/voltron-1/Suburban_SOC/issues/430) (network-
  path tactic validation gap — could silently drop a real technique from
  the coverage matrix),
  [#431](https://github.com/voltron-1/Suburban_SOC/issues/431) (same
  bug class, prospective — markdown table has no `|` escaping),
  [#432](https://github.com/voltron-1/Suburban_SOC/issues/432)
  (`run_hunts.py`'s composite ES `_id` has no delimiter guard — a
  colliding hunt id would silently overwrite another hunt's stored
  findings via upsert, the worst-consequence instance of this bug class
  found, though not currently live). [PR
  #433](https://github.com/voltron-1/Suburban_SOC/pull/433), all 12 CI
  checks green. **M17 now 16/31 closed** (13 real follow-ups open, 2 not
  actionable) — continuing the same resumed run, smallest/most-contained
  next.
- [x] **#428 (M17) — COMPLETE, MERGED** — filed during #426's own review:
  `net_zeek_dns_doh_non_standard.yml`'s `query|endswith` used bare
  suffixes with no leading dot, so `evilquad9.net` matched despite not
  being a real Quad9 hostname. Split into `selection_bare` (exact) OR
  `selection_subdomain` (dot-anchored). security-auditor review found
  the IDENTICAL bug live in the sibling `net_zeek_dns_crypto_mining_pool.yml`
  at a higher severity tier (`level: medium`) — fixed directly in this
  same change per the standing no-public-disclosure convention for live
  gaps, not filed separately. Also independently found and fixed a
  same-class bug in `sigma_eval.py`'s shared `endswith` handling (bare
  `"$"` vs `r"\Z"`, same divergence-from-Lucene class as #387) —
  mutation-tested. Added permanent live-fire regression coverage for
  both rules against a real Elasticsearch (not just this session's
  manual verification), and an explicit emission-vs-registration caveat
  after confirming the fix narrows but doesn't eliminate query forgery
  (both rules match the observed query, not the response — filed
  [#434](https://github.com/voltron-1/Suburban_SOC/issues/434) (M17) for
  the actual mitigation, a design decision not a live-gap disclosure).
  [PR #435](https://github.com/voltron-1/Suburban_SOC/pull/435), all 12
  CI checks green. **M17 now 17/32 closed** (13 real follow-ups open, 2
  not actionable) — continuing the same resumed run, smallest/most-
  contained next.
- [x] **#430 (M17) — COMPLETE, MERGED** — filed during #425's own review:
  the Sigma-rule path already failed loudly on an unresolvable
  `attack.<tactic>` tag (#281); the network path (parsing
  `[threat][tactic][name]` out of `configs/logstash.conf`) had none.
  security-auditor review found the initial name-only validation was
  incomplete and folded 3 more fixes into the same change: the field-
  pairing regex used unanchored `.*?` that could cross an `add_field`
  block boundary and silently mis-pair or drop entries (mutation-tested
  — reverted to `.*?`, confirmed the exact predicted mis-pairing,
  restored the `[^}]*?` fix); only the tactic *name* was validated, not
  the *id* (now validates both as a pair, and resurrects `TACTICS`' own
  previously-dead ATT&CK-ID data); the network technique id had no
  format check or normalization unlike the Sigma path (now matched and
  uppercased consistently); comments weren't stripped before parsing
  (a commented-out example mapping could be harvested as live
  coverage). 5 new regression tests plus a real-corpus row-count
  invariant. Filed
  [#436](https://github.com/voltron-1/Suburban_SOC/issues/436) and
  [#437](https://github.com/voltron-1/Suburban_SOC/issues/437) (both
  M17) for two smaller, genuinely separate design gaps the review
  surfaced. [PR #438](https://github.com/voltron-1/Suburban_SOC/pull/438),
  all 12 CI checks green. **M17 now 18/34 closed** (14 real follow-ups
  open, 2 not actionable) — continuing the same resumed run,
  smallest/most-contained next.

<details>
<summary>M15 history (complete) — click to expand</summary>

**Milestone: [M15 — Detection Correctness & Pipeline Fidelity](https://github.com/voltron-1/Suburban_SOC/milestone/19).**
Started 2026-08-09, immediately after M14 closed (8/8 issues, plus #252).
Whether the *existing* rule corpus behaves as written, as distinct from
M13's rule-count goal. M12/M13/M14 sections below are retained as history,
not active work. Multi-phase execution gating applies: each issue is its
own gated unit, no unattended multi-issue runs.

- [x] **#263 (P1, security) — COMPLETE, MERGED** — `ignore_above: 8191` let
  `proc_creation_win_powershell_encoded.yml`/`posh_ps_obfuscated_scriptblock.yml`
  be bypassed by payload length (PowerShell 4104 chunks routinely run
  ~20000 chars, well past the old ceiling). Raised to 32766 (Lucene's own
  per-term byte ceiling) for `process.args`/`process.parent.args`/
  `winlog.event_data.ScriptBlockText`/`winlog.event_data.ImagePath` (added
  to scope — security-auditor found `system_win_suspicious_service_binpath_
  lolbin.yml` shares the identical bypass shape via `ImagePath`) and the
  `long_command_fields` dynamic_template. Applied live, all 6
  `logstash-security-*` data streams rolled over.
  [PR #329](https://github.com/voltron-1/Suburban_SOC/pull/329) merged
  2026-08-10 (squash, `fea5c24`), auto-closing #263 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner (17/17 CI
  green, sub-agent review only, same basis as M13's #298/#300/#301 and
  M14's session-initiated fixes).
  CI on the PR broke *after* the fix was otherwise ready: the `detections`
  job failed on `build_kql_docs.py --check`, reproducing identically
  against `main`'s own already-committed docs/rules — an unpinned
  `sigma-cli`/`pysigma-backend-elasticsearch` install (no version lock)
  had drifted to a newer release that renders multi-word Lucene terms as
  quoted strings instead of backslash-escaped spaces, on 2 rules untouched
  by #263 (`auth_win_priv_group_membership_change.yml`,
  `create_remote_thread_win_susp_target.yml`) — same drift class as the
  unpinned-`ruff` break M12 Phase 0 hit (fixed via PR #255). Unblocked by
  regenerating the doc via the project's own generator (no manual edits),
  verified by replicating the full `detections` job locally post-fix.
  Follow-up filed: [#330](https://github.com/voltron-1/Suburban_SOC/issues/330)
  (pin the sigma toolchain versions in CI so this can't recur on an
  unrelated PR).
  A parallel security-auditor + code-reviewer pass on the first draft,
  independently converging on the same finding, caught that the naive fix
  shipped a worse bug than the one it closed: `ignore_above` is a
  *character* ceiling, but Lucene's own per-term hard limit is a UTF-8
  *byte* ceiling — a value under the char ceiling but byte-heavy (multi-byte
  content, e.g. Unicode identifier/homoglyph obfuscation in
  `ScriptBlockText`, a real T1027 technique) crashed the *whole document* at
  index time instead of gracefully dropping the field. Live-confirmed: HTTP
  400, Lucene "immense term" rejection. Fixed with a byte-safety clamp in
  the ruby truncation filter (tagged `pipeline.byte_clamped`, its own new
  `metric_field_byte_clamp_count()` SLO metric), mutually exclusive with the
  char-ceiling tag by construction. The same review found — and
  live-confirmed via a spliced-pipeline replay of the real filter — that
  truncation tagging had silently never worked for `process.args`/
  `process.parent.args` on real Sysmon-sourced events at all: the Sysmon
  `mutate.rename` block targets bare dotted strings, which Logstash creates
  as flat literal fields rather than the nested structure the filter's
  lookups expected. Worked around locally with a fallback lookup; the
  rename block itself (9 fields across the whole Sysmon rule surface) is
  deliberately left for its own dedicated regression pass, filed as
  [#328](https://github.com/voltron-1/Suburban_SOC/issues/328). Also: the
  "keep `ceiling` in lockstep with the template's `ignore_above`" invariant,
  previously enforced only by a comment, is now a CI-enforced test; fixed 3
  pre-existing, unrelated `test_slo_metrics.py` failures (local
  `SLO_COVERAGE_MIN` env mismatch, same pattern 2 sibling tests already
  worked around — confirmed via a clean pre-diff snapshot comparison that
  they fail identically without this change, so not a regression). Every
  claim live-verified against the real running stack by a tester-debugger
  agent (real compiled Sigma query, real scratch index, real template; the
  actual `logstash` binary for both the byte-clamp and field-path-fallback
  checks) — not just reasoned about. Known, deliberately out-of-scope
  residual gaps noted in the PR: `*uri` → `url.path` still falls through to
  `ignore_above: 1024` (separate field, separate rule, lower severity); #326
  (wildcard-typed multi-field decision) untouched, still gated on real
  telemetry data.
- [x] **#261 (P1) — COMPLETE, MERGED** — T1110's pipeline tag matched every
  Zeek `auth_success=false` event, not an aggregated notice (unlike T1046,
  its own sibling branch) — an unauthenticated actor could inflate
  `raw_alert_volume` at will with a failed-login burst. Fixed to match
  `[note] in ["SSH::Password_Guessing", "SSH::Login_By_Password_Guesser"]`,
  mirroring T1046's pattern.
  [PR #334](https://github.com/voltron-1/Suburban_SOC/pull/334) merged
  2026-08-11 (squash, `d500961`), auto-closing #261 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner, 17/17 CI green.
  Root-cause investigation found the naive fix would have silently regressed
  T1110 to zero detections: `policy/protocols/ssh/detect-bruteforcing`, the
  Zeek policy that emits those notices, was not loaded by any real capture
  invocation — `configs/zeek/local.zeek`, which the Sigma rule's own
  docstring assumed loaded it, is dead config unused by any real capture
  path since #286. Same failure class as T1046/`Scan::Port_Scan`, which
  needed its own custom reimplementation (`scan-detection.zeek`) for the
  identical reason. Scope expanded (confirmed with the repo owner) to wire
  `detect-bruteforcing` into the two real capture entry points
  (`scripts/setup/stream_capture.sh`,
  `configs/systemd/zeek-host-capture.service`) alongside the existing
  `scan-detection.zeek` load, rather than ship a precision fix that could
  never actually fire.
  security-auditor (0 CRITICAL/HIGH) + code-reviewer (Approve) ran in
  parallel; both independently found the same regression-test brittleness
  (fixed). tester-debugger live-verified both halves against the real
  stack, not just reasoned about: a spliced-pipeline replay against the
  real `docker.elastic.co/logstash/logstash:9.3.2` image (matches this
  repo's own pin) confirmed the compiled filter tags a synthetic notice and
  not a synthetic raw `auth_success` event; a real two-container Docker
  bridge-network SSH brute force (not loopback), captured and replayed
  through `zeek` with `detect-bruteforcing` loaded, fired a genuine
  `SSH::Password_Guessing` notice. Re-evaluated promoting
  `net_zeek_ssh_bruteforce.yml`/`net_zeek_port_scan.yml` out of
  `experimental` (the issue's 3rd acceptance criterion): confirmed staying
  `experimental` is correct — promoting now would guarantee a clean
  double-count against the now-precise pipeline tag. Fixed 6 stale
  references across `slo_metrics.py`, both `net_zeek_*.yml` docstrings,
  `emulation_telemetry.map`, and `coverage_checklist.md` that pointed at the
  dead `local.zeek` or the old per-event behavior — the exact drift that let
  this bug hide. CI failed once after the initial push on an unrelated
  validator (`tests/validate_emulation_map.py`, the "purple-team loop is
  real" check) — a doc-field edit pointed at a path that only exists inside
  the Docker image, not the repo; fixed to reference the real in-repo wiring
  file instead, reverified clean.
  Follow-ups filed, deliberately out of scope:
  [#331](https://github.com/voltron-1/Suburban_SOC/issues/331) (T1046's own
  `scan-detection.zeek` is SYN-only and source-spoofable, a *cheaper*
  `raw_alert_volume` inflation vector than the SSH path just fixed —
  pre-existing, not touched by this diff),
  [#332](https://github.com/voltron-1/Suburban_SOC/issues/332) (session-cadence
  SSH threshold rule for low-and-slow/distributed coverage below
  `detect-bruteforcing`'s 30-attempt threshold),
  [#333](https://github.com/voltron-1/Suburban_SOC/issues/333) (Zeek's SSH
  auth-outcome inference may be blind to very recent OpenSSH clients,
  10.2p1 observed live during verification; root cause unconfirmed). Also
  commented on the already-open
  [#293](https://github.com/voltron-1/Suburban_SOC/issues/293) (pin
  `zeek/zeek`) noting this PR adds a new dependency on that image's internal
  script-path structure.
- [x] **#267 (P1) — COMPLETE, MERGED** — the live SOAR trigger
  (`configs/logstash.conf`, superseding the dead `soar_quarantine_alert.json`
  Watcher, #220) only ever covered 1 of the Watcher's original 3 conditions
  (`zeek.intel` IOC hits) — T1046/T1110 network detections were
  pipeline-tagged for dashboards but never reached automated SOAR response.
  [PR #335](https://github.com/voltron-1/Suburban_SOC/pull/335) merged
  2026-08-12 (squash, `77a04c7`), auto-closing #267 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner, 13/13 CI
  green. Wired T1110 into live dispatch (both the filter-stage HMAC-signing
  condition and the separate output-stage http-dispatch condition, kept in
  lockstep by a new regression test), plus a `source.ip` fallback rename
  for `zeek.notice` events that set Zeek's `Notice::Info$src` without
  `$conn` (stock `detect-bruteforcing.zeek`'s `Password_Guessing` notice
  does this — the existing `id.orig_h` rename never fires for it).
  T1046 was originally planned to be wired in too, but security-auditor
  review found `scan-detection.zeek` fires on a bare SYN with no completed
  handshake — wiring it into live dispatch, with no rate limiting anywhere
  in the agent's `/alert` path (`severity` hardcoded `"critical"`,
  concurrency capped at `--workers 1 --threads 4`), would have turned a
  spoofed-source SYN sweep into an automated-containment amplifier against
  an attacker-chosen victim IP. Left T1046 dashboard-tagged only, unchanged
  from before this fix, deferred until
  [#331](https://github.com/voltron-1/Suburban_SOC/issues/331) (a
  source-spoofing defense) exists — commented on that issue to record the
  new blocking relationship. Retired `soar_quarantine_alert.json` for real:
  moved to `rules/elastic_watcher/retired/` so `deploy_dashboards.sh`'s
  install glob stops PUTting it (it was still being installed on every
  deployment despite being dead code since #220), and added an idempotent
  `DELETE` step to `deploy_dashboards.sh`/`.ps1` so already-deployed
  clusters actually converge. security-auditor (1 HIGH, resolved by the
  T1046/T1110 split above) + code-reviewer (1 Must-Fix:
  `tests/anomaly_simulation/preflight.sh` still hard-gated on the
  now-never-installed Watcher, would have permanently broken the SOP-022
  live-lab harness — fixed) ran in parallel; tester-debugger independently
  re-verified via a second spliced-pipeline replay exercising the real
  `http` output plugin against a local fake server, not just a
  textual-identity check — confirmed real dispatch for tagged events, none
  for untagged ones. Swept 5 docs that described the retired Watcher as
  live or claimed all 3 conditions dispatch.

All 3 of M15's P1 issues (#263, #261, #267) are complete. Checked the
GitHub milestone directly rather than assume that closed the milestone: it
does not — 9 more issues were tagged to M15 (#328, #297, #295, #292, #291,
#290, #288, #287, #283), never individually triaged into this doc before
now. All P2/P3, no P1 remaining.

- [x] **#328 (P2, bug) — COMPLETE, MERGED** — `configs/logstash.conf`'s
  Sysmon `mutate.rename` block targeted bare dotted strings as rename
  destinations (e.g. `"[winlog][event_data][CommandLine]" => "process.args"`),
  which Logstash treats as a FLAT field literally named `"process.args"`
  (dot as a literal character), not the nested `[process][args]`
  structure — the same footgun this file already documented at its
  network-rename block, just never applied to the Sysmon block. 9 fields
  affected. Live-verified during #263's own review (2026-08-09):
  `event.get("[process][args]")` returned nil for real Sysmon-sourced
  events, silently dead-coding #252/#263's truncation-tagging filter for
  `process.args`/`process.parent.args` — worked around at the time with a
  flat-key fallback lookup; this issue tracked the actual root cause.
  [PR #340](https://github.com/voltron-1/Suburban_SOC/pull/340) merged
  2026-08-12 (squash, `f3a1f94`), auto-closing #328, 13/13 CI green
  including `live-fire`. Converted all 9 rename targets to bracket
  notation; removed the truncation filter's flat-key fallback as dead
  code (confirmed via repo-wide grep nothing else produces/consumes the
  flat shape); added a new regression test scanning **every**
  `rename => {...}` block in the file, not just the two already found —
  this exact bug shape has now occurred twice in this file, real risk of
  a third. Live-verified via a spliced-pipeline replay against the real
  `docker.elastic.co/logstash/logstash:9.3.2` image (byte-identical
  excerpts, short + 40000-char synthetic values): all 9 fields land
  correctly nested, zero flat dotted keys anywhere, truncation tagging
  fires via direct bracket lookup with no fallback needed.
  security-auditor (0 CRITICAL/HIGH) + code-reviewer (Approve, no
  Must-Fix) ran in parallel; tester-debugger independently rebuilt the
  splice from scratch and diffed it byte-identical, full PASS. One
  MEDIUM fixed pre-merge: the new regression test missed a second bad
  shape — a dot *inside* one bracket pair (`"[process.args]"`), the
  identical bug via different syntax (this file already uses that exact
  single-bracket-with-a-dot form deliberately elsewhere, but only as a
  rename *source*, never a target). 103/103 relevant tests pass.
  Follow-ups filed, deliberately out of scope:
  [#336](https://github.com/voltron-1/Suburban_SOC/issues/336) (widen the
  hygiene check to `copy`/`replace`/`update` blocks + a
  logstash.conf<->ecs.yml mapping-equivalence test),
  [#337](https://github.com/voltron-1/Suburban_SOC/issues/337) (the
  truncation filter's single hardcoded ceiling can't model 6 of the 9
  fields' actual lower `ignore_above` ceilings; `user.name` has none at
  all — the one genuine immense-term exposure),
  [#338](https://github.com/voltron-1/Suburban_SOC/issues/338) (ABAC
  enrichment now runs on Sysmon events for the first time, but Sysmon's
  `DOMAIN\user` format never matches the bare-username-keyed lookup CSV),
  [#339](https://github.com/voltron-1/Suburban_SOC/issues/339)
  (`file.hash.sha256` stores Sysmon's algorithm-prefixed string verbatim,
  not a parsed hash — latent, no rule consumes it yet).

- [x] **#297 (P2, bug) — COMPLETE, MERGED** — `configs/logstash.conf`'s
  Security-channel block compared `[winlog][event_id] == 4625/4624`
  against BARE INTEGER literals. Winlogbeat's own ECS mapping types
  `winlog.event_id` as `keyword` (a string), so the comparison silently
  never matched — `[event][outcome]` never got stamped for any real
  Windows login event. [PR #343](https://github.com/voltron-1/Suburban_SOC/pull/343)
  merged 2026-08-12 (squash, `5ccc0d1`), auto-closing #297, 17/17 CI
  green. Live-verified against the real `logstash:9.3.2` binary:
  pre-fix, a synthetic `"4625"` string event produced no
  `[event][outcome]`; post-fix, `"4625"` -> failure, `"4624"` -> success,
  a negative-control event id -> no outcome field. Also switched
  `add_field` -> `replace` (matches this field's own established
  convention 60 lines below) and added two regression tests pinning the
  exact quoted comparison set and the correct id->outcome mapping (the
  first test alone would not have caught a transposed 4625/4624 mapping —
  security-auditor finding). security-auditor + code-reviewer ran in
  parallel, both converged independently on the same regex-robustness
  gap (compound conditions); tester-debugger independently rebuilt the
  splice tests from scratch. 468/468 relevant tests passed.
- [x] **#295 (P2, bug) — CLOSED, already resolved** — both of this
  issue's own suggested fixes (raise `ScriptBlockText`'s `ignore_above`
  toward the real PowerShell 4104 chunk size; add a truncation-visibility
  monitor) turned out to already be shipped, via #263
  ([PR #329](https://github.com/voltron-1/Suburban_SOC/pull/329),
  `ignore_above:32766`, Lucene's own byte ceiling) and #252
  ([PR #327](https://github.com/voltron-1/Suburban_SOC/pull/327),
  `pipeline.truncated`/`pipeline.byte_clamped` tagging +
  `metric_field_truncation_count()`) — issues filed and merged after
  #295 but before it was individually triaged into this doc. Verified
  directly against current `main` (not just the PR descriptions) before
  closing: both the template ceiling and the tagging/metric are live in
  the current codebase. Closed 2026-08-12 with evidence, no new PR.
- [x] **#290 (P2, bug) — COMPLETE, MERGED** — 5 Zeek-derived ECS fields
  #228 introduced never got `long_command_fields`'s `lowercase_normalizer`
  treatment, falling through to case-sensitive `strings_as_keyword`.
  Investigated all 5: 4 are genuinely live (`dns.question.name`,
  `url.path`, `tls.validation_status`, plus `tls.client.server_name`,
  found via security-auditor review, not originally named in the issue)
  with real Sigma-rule consumers; `user_agent.original` has NO producer
  anywhere in the pipeline, excluded as speculative.
  [PR #346](https://github.com/voltron-1/Suburban_SOC/pull/346) merged
  2026-08-12 (squash, `3472729`), auto-closing #290, 17/17 CI green.
  Live-verified against a real `elasticsearch:9.3.2` instance, before and
  after, including the "evidence looks present, detection is dead"
  failure mode. security-auditor found a real HIGH during review: raising
  `url.path` to `ignore_above:32766` without adding it to the #263
  byte-clamp `long_fields` hash reintroduced the Lucene immense-term
  whole-document-rejection bug on an attacker-controlled field —
  live-reproduced the crash, fixed it, added a self-enforcing CI test
  deriving the clamp requirement from the template itself. A SECOND,
  separate production-breaking bug was hit live while writing that fix's
  own comment: an apostrophe inside a multi-line ruby `code => '...'`
  block closes Logstash's string literal early and breaks the whole
  pipeline config at startup — fixed, plus a permanent CI guard against
  the whole class. This PR needed a merge-conflict resolution round after
  #297 merged first — see the 2026-08-12 (later) LAST SESSION entry for
  that story, including a real `pysigma`/`pysigma-backend-elasticsearch`
  toolchain-version-drift CI failure it surfaced (commented on
  [#330](https://github.com/voltron-1/Suburban_SOC/issues/330) with the
  concrete version numbers).
  Follow-ups filed: [#341](https://github.com/voltron-1/Suburban_SOC/issues/341)
  (Endpoint dashboard `.keyword`-on-bare-keyword mapping gap, third
  recurrence of this shape), [#342](https://github.com/voltron-1/Suburban_SOC/issues/342)
  (Windows Security block has no IpAddress/TargetUserName ECS rename),
  [#344](https://github.com/voltron-1/Suburban_SOC/issues/344)
  (`long_command_fields` dynamic_template byte-clamp blind spot),
  [#345](https://github.com/voltron-1/Suburban_SOC/issues/345) (automate
  the data-stream rollover step in `apply-templates.sh`).
- [x] **#287 (P2, bug) — COMPLETE, MERGED** — 4 consecutive
  detection-expansion batches (#217, #232, #233/#234, #228) independently
  hit the same bug: a Sigma rule selects a raw Zeek field name that
  `logstash.conf`'s ingest-time renames either never produce or produce
  under a different ECS target, compiling fine and passing its fixture
  test while being a silent no-op in production. New
  `tests/pipeline/test_field_mapping_drift.py` parses both files' real
  content (brace-depth-counting for `logstash.conf`'s Category 0 block,
  plus `filebeat.yml`'s own input-processor rename) and cross-references
  every `product: zeek` mapping's raw_field -> target pair against what
  the pipeline actually does.
  [PR #348](https://github.com/voltron-1/Suburban_SOC/pull/348) merged
  2026-08-12 (squash, `2013956`), auto-closing #287, 17/17 CI green.
  security-auditor found the drift checker had its own version of the
  drift bug it exists to catch (a compound conditional defeated the
  scope-detection regex — code-reviewer independently found the identical
  bug), plus 6 more MEDIUM findings, all fixed — including one real,
  currently-existing gap the new checker surfaced and this PR fixed in
  the same commit: `field-mapping-zeek-files` was silently missing the
  connection 4-tuple its own file's documented invariant requires, since
  #217. 17 tests total (up from an initial 3), each mutation-tested to
  confirm it fails on the bug shape it exists to catch. Follow-up filed:
  [#347](https://github.com/voltron-1/Suburban_SOC/issues/347) (extend
  to the Sysmon process_creation/file_event renames).
- [x] **#291 (P3, performance/correctness) — COMPLETE, MERGED** — several
  zeek/* Sigma rules compiled to leading-wildcard/regex queries with no
  ES seek optimization; separately, no rule had anything in its compiled
  query confirming a match came from its own logsource's Zeek stream
  rather than a sibling stream sharing the same connection 4-tuple (a
  single physical connection can produce multiple Zeek log records for
  the same 4-tuple, so an under-qualified rule could double-alert on one
  real event). Added one generic pySigma `add_condition` transformation
  (`template: true` + `$service`) covering all 7 zeek services, injecting
  `event.dataset:zeek.<service>`.
  [PR #350](https://github.com/voltron-1/Suburban_SOC/pull/350) merged
  2026-08-13 (squash, `c4c6abe`), auto-closing #291, 17/17 CI green.
  security-auditor found 3 real HIGH issues: (1) `zeek_run_pcap.sh`'s
  offline-PCAP-replay workflow named logs so Category 0's grok captured
  the whole underscore-joined stem as the stream name — harmless before
  this fix, would have silently blinded every zeek rule against replay
  data with this fix; root-caused and fixed (bonus: also fixed a second,
  independent mis-scoping the old naming caused in `filebeat.yml`'s
  host-header rename). (2) `SIEM_KQL_Documentation.md` was stale,
  blocking the required `detections` CI gate — regenerated (twice: the
  first regeneration used a stale local `pipx` toolchain instead of
  matching CI's unpinned always-latest install, itself a live instance of
  the #330 drift class, caught and corrected). (3) A missing
  `logsource.service` on a future zeek rule would silently compile to
  `event.dataset:zeek.None` — turned into a loud, CI-gated failure wired
  into a new required `detections` job step, plus a second guard against
  a *present but wrong* service value (a typo). Merging main into this
  branch (after #290/#287 merged) surfaced one more real regression: 3 of
  #290's own live-fire test methods called `translate_fixture()` directly
  without the new required `logsource` stamp, which would have silently
  broken them — found and fixed live against a real cluster before
  pushing. Follow-up filed: [#349](https://github.com/voltron-1/Suburban_SOC/issues/349)
  (no monitoring on `_zeek_path_nomatch` — a pre-existing gap this fix
  makes consequential).

- [x] **#292 (P3, detection gap) — COMPLETE, MERGED** — Zeek `dns.log`'s
  `answers` field was never mapped to ECS, so TXT-based DNS C2's download
  direction (payload in the answer, short/unremarkable query name —
  Cobalt Strike's DNS-TXT channel, Empire, Merlin) was structurally
  undetectable; the pre-existing `net_zeek_dns_txt_record_abuse.yml` only
  ever selects on the query label (upload direction).
  [PR #353](https://github.com/voltron-1/Suburban_SOC/pull/353) merged
  2026-08-13 (squash, `2563d22`), auto-closing #292, 17/17 CI green.
  Added the `answers` -> `dns.answers` rename (both `logstash.conf`
  branches + `suburban-soc-ecs.yml`) and a new companion rule,
  `net_zeek_dns_txt_answer_abuse.yml` (`qtype_name:TXT` + a base64-charset
  length-as-entropy-proxy regex on `answers`). security-auditor found a
  real gap in the fix's own first pass: `dns.answers` had no explicit
  `ignore_above`, falling to the default 1024-char ceiling — unlike
  `dns.question.name`, a Zeek TXT answer has no protocol-level length
  bound, so that default was a live, silent evasion path for the exact
  rule this fix exists to build. Fixed with an explicit
  `ignore_above:8191` template property, live-proven to fail pre-fix and
  pass post-fix against a real Elasticsearch 9.3.2 index. Two rounds of
  parallel security-auditor + code-reviewer review; a follow-up
  verification round on the fixes themselves caught two inaccuracies my
  own comment fixes had introduced (corrected before merge). One finding
  — the unauthenticated `:5514` HTTP input can forge or suppress Zeek
  Sigma detections by spoofing `log.file.path` — was filed as a private
  draft Security Advisory (`GHSA-qq8v-48c2-j5xx`) rather than a public
  issue, since it's a live, unpatched gap in a public repo. Follow-ups
  filed: [#351](https://github.com/voltron-1/Suburban_SOC/issues/351)
  (`sigma_eval.py` has no array-value semantics — first multi-valued
  field in the rule corpus), [#352](https://github.com/voltron-1/Suburban_SOC/issues/352)
  (no visibility when a `dns.answers` element exceeds the new 8191
  ceiling — residual, non-urgent); cross-referenced already-filed
  [#345](https://github.com/voltron-1/Suburban_SOC/issues/345) (this fix
  is also blocked on that same rollover-automation gap operationally).

- [x] **#288 (P3, resource guard) — COMPLETE, MERGED** — #228's
  per-connection OpenSSL cert-chain verification had no aggregate resource
  guard; the real capture path (`tcpdump | docker run zeek -r -`) has no
  load shedding, so CPU pressure surfaces as packet drops with nothing
  reading Zeek's own `capture_loss.log` to notice.
  [PR #354](https://github.com/voltron-1/Suburban_SOC/pull/354) merged
  2026-08-13 (squash, `892b399`), auto-closing #288. Added
  `@load policy/misc/capture-loss` to `configs/intel/config.zeek`
  (live-verified against the real `zeek/zeek` image: fails "unknown
  identifier" without the `@load`, a real PCAP run produces a genuine
  `capture_loss.log` entry with `percent_lost` landing as a JSON float);
  a new `metric_capture_loss_percent()` in `slo_metrics.py` using its own
  short window rather than the shared 7-day `WINDOW` (a `max` over 7 days
  polled every 15 min would pin one transient spike in breach for ~672
  consecutive runs), with a staleness-qualified fallback distinguishing
  "no Zeek data yet" from "Zeek is flowing but capture-loss reporting
  itself died"; explicit `percent_lost`/`gaps`/`acks`/`ts_delta` mapping
  properties in `logstash-security-template.json` (closes a #275-class
  false-healthy risk under `ignore_malformed:true`). Also fixed the
  issue's own bundled finding: all 4 real Zeek capture invocations
  swallowed a failed `configs/intel/*` copy with `|| true` with nothing
  verifying the deployed `config.zeek` matched the repo — added post-copy
  verification plus symlink guards + `--remove-destination` (previously
  only on the systemd unit) to the 3 shell scripts.
  Three rounds of parallel security-auditor + code-reviewer review closed
  6 real findings, including a regression where the new systemd
  `ExecStartPre` check silently swallowed a pre-existing (#222) `intel.dat`
  fallback failure (fixed with `set -e;`) and a liveness check that would
  have false-triggered on this repo's own offline-PCAP-replay/short-manual-
  stream workflows (fixed with a 30-min staleness qualifier). One finding
  — the pre-existing unauthenticated `:5514` HTTP input can forge a
  `capture_loss.log` event to suppress the new liveness check — was routed
  into the existing private Security Advisory (`GHSA-qq8v-48c2-j5xx`,
  filed during #292 for the same root gap) rather than a public fix.
  112 pipeline tests (was 106), 87 slo_metrics tests (was 83);
  ruff/shellcheck/systemd-analyze all clean.

1 issue remains in the M15 backlog:

- #283 (P3 — T1562.004 firewall-rule-added detection could use Security
  4946 — explicitly blocked on real Windows telemetry verification this
  environment can't provide).

M15 is otherwise exhausted of unblocked work. A new milestone,
[M16 — Endpoint Onboarding & Threat-Intel Integrity](https://github.com/voltron-1/Suburban_SOC/milestone/20),
has appeared with 4 open P3 issues.

- [x] **#293 (P3, supply-chain) — COMPLETE, MERGED** — all 4 real Zeek
  capture invocations pulled `zeek/zeek` with no tag (implicitly `:latest`)
  — an unpinned image lets an upstream rebuild silently change an
  OpenSSL/Zeek-generated string a Sigma rule depends on, already happened
  once live during #228's review (OpenSSL's `"self signed certificate"`
  wording changed to `"self-signed certificate"` between builds).
  [PR #356](https://github.com/voltron-1/Suburban_SOC/pull/356) merged
  2026-08-15 (squash, `5ebbe1f`), auto-closing #293, 13/13 CI green.
  Pinned all 4 (`zeek-host-capture.service`, `stream_capture.sh`,
  `zeek_connect_host.sh`, `zeek_run_pcap.sh`) to
  `zeek/zeek:8.1.1@sha256:f3d539d68e2a68897b02bfa302df9c7f8bcb89f338399625686fca9cc30c85f3`
  — tag+digest, not tag alone: a Docker Hub tag is a mutable pointer the
  publisher can re-push, and separately anyone with local Docker socket
  access can `docker tag <anything> zeek/zeek:8.1.1`; only the
  content-addressed digest closes both (security-auditor finding). New
  regression test `tests/pipeline/test_zeek_image_pin.py` (13 tests)
  enforces all 4 stay pinned to the exact reviewed tag+digest and in
  lockstep — regex anchored both sides so a registry-prefixed or
  typosquatted lookalike (`evil.example.com/zeek/zeek`, `notzeek/zeek`,
  `zeek/zeek-dev`) can't be misread as the real reference, and comment-only
  mentions are excluded so neither a swapped real invocation can hide
  behind a stale comment nor an explanatory comment can register as a
  second, unpinned "invocation" — both directions caught live while
  authoring the file, now locked in as self-tests. security-auditor +
  code-reviewer + tester-debugger ran in parallel; tester-debugger
  live-verified both the offline-PCAP-replay and streaming `docker run`
  patterns end to end against real production PCAP data through the pinned
  image, not just `--version`. Also fixed a real downstream break the pin
  itself creates: SOP-147's evidence-validation commands filtered
  `docker ps` on `ancestor=zeek/zeek` (bare, implicitly `:latest`) —
  empirically confirmed (removed the local `:latest` tag, retested) this
  stops matching the instant `:latest` and the pinned tag diverge, i.e. the
  first time the documented bump process is exercised; fixed to filter on
  the pinned tag, added to the bump checklist. Fixed a now-stale comment in
  `net_zeek_ssl_self_signed_c2.yml` asserting the image was still unpinned,
  and pinned the tutorial doc's example in `Zeek_ELK_Pipeline.md` for
  consistency. Follow-up filed:
  [#355](https://github.com/voltron-1/Suburban_SOC/issues/355) (the now-
  frozen image sits outside the repo's Trivy scanning coverage — real
  coverage gap, not a known live vulnerability, needs its own CI workflow
  change, deliberately out of scope for "pin the image").

- [x] **#271 (P3, data hygiene) — COMPLETE, MERGED** — `refresh_intel.sh`'s
  ES bulk-index step upserted every indicator on every 6h run but never
  deleted one a feed had since removed; `threat-intel-meta` had the same
  problem in a more acute form (a brand-new heartbeat doc every run, no
  natural cap). [PR #360](https://github.com/voltron-1/Suburban_SOC/pull/360)
  merged 2026-08-16 (squash, `b50d48b`), auto-closing #271, 17/17 CI green.
  Added a periodic TTL-retention compactor
  (`scripts/setup/ai_agent/compact_threat_intel.py`), modeled on
  `compact_agent_checkpoints.py`'s (#256) pattern: a dedicated
  `threat_intel_compactor` read+delete identity split from the writer.
  Two review rounds (security-auditor + code-reviewer + tester-debugger,
  parallel) found and fixed real bugs confirmed against a live stack with
  real accumulated data: the original design keyed retention on a new
  `threat.indicator.last_seen` field, which no pre-fix doc had — an ES
  range query never matches a missing field, so the exact backlog #271
  exists to retract would have been permanently undeletable (live-confirmed
  170/728 real docs affected; fixed to key on `@timestamp`, already
  re-stamped on every run since #222, correctly deleted exactly those 170).
  Added a blast-radius guard (refuses >50% of an index in one run without
  `--force`) since, unlike the checkpoints sibling's multi-clause phase
  filter, this script's delete has a single predicate. Found 3 compactor/
  reader passwords (including this PR's own) bypassing docker-compose.yml's
  placeholder-rejection gate entirely — fixed, plus a generalized
  regression test. Most significantly: `intel-refresh.service` (installed
  and actively running on this host) had the exact `systemd
  Environment=${VAR}`-doesn't-expand bug #259 already fixed once for
  `slo-metrics.service` — empirically reconfirmed live via `systemd-run
  --user`; its scheduled runs have very likely never successfully
  authenticated to ES until this fix. Also added `threat-intel-*` to
  `slm-policy.json` (previously excluded, making the new timer's own
  "bad delete has a snapshot to recover from" claim false) and raised
  default retention from the issue's suggested 7d to 30d (7d would have
  collided with the feed-health dashboard's own saved `now-7d` window).
  Follow-ups filed: [#357](https://github.com/voltron-1/Suburban_SOC/issues/357)
  (`checkpoints-compact.service` has the identical broken `Environment=`
  pattern — not installed on this host, lower urgency but same bug class),
  [#358](https://github.com/voltron-1/Suburban_SOC/issues/358) (no
  detection if `threat-intel-indicators` itself is wiped; a client timeout
  doesn't cancel a running server-side delete), [#359](https://github.com/voltron-1/Suburban_SOC/issues/359)
  (Elasticsearch `:9200` bound to all host interfaces, not just localhost).

- [x] **#357 (P2, bug) — COMPLETE, MERGED** — `checkpoints-compact.service`
  (#256) had the identical broken `Environment=${VAR}` pattern #259
  already fixed once and #271 fixed twice more this session
  (`intel-refresh.service`, `threat-intel-compact.service`) — the fourth
  occurrence of the same bug class.
  [PR #362](https://github.com/voltron-1/Suburban_SOC/pull/362) merged
  2026-08-16 (squash, `aa73b63`), auto-closing #357, 13/13 CI green.
  Fixed with the same proven pattern; live-verified end to end, including
  provisioning `agent_checkpoints_compactor` for the first time on this
  host and a real delete against a synthetic aged-out checkpoint doc.
  security-auditor + code-reviewer review found two further real gaps:
  `EnvironmentFile=` is empirically last-wins on a duplicate `.env` key
  (confirmed live via `systemd-run --user`), so a botched password
  rotation leaving two `PASSWORD=` lines could let a valid first line
  mask a bad one that's what actually gets exported — fixed with
  `| tail -n 1` in all 3 affected units, live-verified the guard now
  correctly fails on that case. Also found each unit's own regression
  test pinned the broken line's absence but never asserted the
  `ExecStartPre` that actually produces the secret exists at all —
  deleting it would silently 401 every scheduled run forever with the
  full suite green; added content+ordering pins to both affected test
  files (mutation-tested) and a new repo-wide test
  (`tests/setup/test_systemd_environment_no_expansion.py`) scanning every
  `configs/systemd/*.service` file for the bug *shape*, not one string
  per unit — closes the gap that let this recur 4 times with no
  generalized guard. Follow-up filed:
  [#361](https://github.com/voltron-1/Suburban_SOC/issues/361)
  (activating this credential for the first time here has no detection
  coverage — its own SLO metrics get greener, not worse, if a `CLAIMED`
  doc is maliciously deleted).

- [x] **#355 (P3, supply-chain) — COMPLETE, MERGED** — the `zeek/zeek`
  image #293 pinned sat entirely outside `security-scan.yml`'s Trivy
  coverage (that matrix only scanned the 2 self-built images), so pinning
  it also meant freezing it indefinitely with no automated path back to a
  patched build. [PR #363](https://github.com/voltron-1/Suburban_SOC/pull/363)
  merged 2026-08-16 (squash, `6f0bb1e`), auto-closing #355. Added a
  `zeek-image` Trivy job that resolves its scan target by importing
  `tests/pipeline/test_zeek_image_pin.py`'s `EXPECTED_TAG`/`EXPECTED_DIGEST`
  directly rather than duplicating the value, so it can never scan a stale
  reference. Live-verified with a real Trivy install against the actual
  pinned reference (not just YAML syntax) — found **7 real, fixed CRITICAL
  CVEs** on the currently-pinned `8.1.1` (libgnutls30t68, libssl3t64/
  openssl, libnode115/nodejs). Confirmed with the repo owner before
  landing: the new job ships as a hard failure on the current pin, by
  design, rather than starting green — makes the exposure impossible to
  ignore. Confirmed via `gh api .../branches/main/protection` that none of
  the 3 Trivy image-scan jobs (including the 2 pre-existing ones) are
  actually required branch-protection checks, so this is visible-but-
  non-blocking, consistent with its siblings rather than a harder gate
  than precedent. Also confirmed a clean fix path exists
  (`zeek/zeek:latest` has moved to `8.2.1`, 0 CRITICAL CVEs) — tracked
  separately as [#364](https://github.com/voltron-1/Suburban_SOC/issues/364)
  since a version bump needs its own live-fire verification pass per
  #293's own documented process, not bundled into a scanning-coverage
  change.

- [x] **#364 (P0→resolved, security) — COMPLETE, MERGED** — #355's new
  Trivy job found 7 real CRITICAL CVEs on the `zeek/zeek:8.1.1` pin
  (libgnutls30t64, libssl3t64/openssl, libnode115/nodejs).
  [PR #366](https://github.com/voltron-1/Suburban_SOC/pull/366) merged
  2026-08-16 (squash, `67ff28b`), auto-closing #364, 18/18 CI green
  including the previously-red `zeek-image` Trivy job, now clean. Bumped
  to `zeek/zeek:8.2.1` (OpenSSL 3.5.6) following #293's documented
  process. security-auditor review found the original verification's
  "grep for validation_status" approach was too narrow (missed
  SSH::Password_Guessing, Intel::ADDR/DOMAIN, files.log mime_type/source)
  — all re-verified live against the new image (enum checks, real
  HTTP-download fixtures for an ELF binary and a shell script, diffed
  byte-identical against the old image). Also found and fixed a real,
  currently-broken evidence-collection command: SOP-147's
  `ancestor=zeek/zeek:<tag>` filter doesn't reliably match a container
  started via `repo:tag@digest` (confirmed empirically) — switched to
  `--filter name=zeek-` (added `--name zeek-stream` to
  `stream_capture.sh`), permanently removing this filter from the bump
  checklist. Follow-up filed:
  [#365](https://github.com/voltron-1/Suburban_SOC/issues/365) (a
  pre-existing, bump-unrelated shell-script `mime_type` detection gap
  found during verification).

M15 is COMPLETE — see the 2026-08-16 restructure note in NEXT UP above for
where its last item (#283) and every other scattered follow-up landed.

</details>

---

<details>
<summary>M14 history (complete) — click to expand</summary>

**Milestone: [M14 — SOAR Approval-Plane Operability & Hardening](https://github.com/voltron-1/Suburban_SOC/milestone/18).**
Started 2026-08-08, immediately after M13 closed (35 → 105 Sigma rules, all 7
user stories merged). Multi-phase execution gating applied: each issue was
its own gated unit, no unattended multi-issue runs.

- [x] **#275 (P0, bug) — COMPLETE, MERGED** — `slo_metrics_reader` never
  granted `soc-agent-health-*`. Live-verified against a real, security-
  enabled, native Elasticsearch (not just reading the role file) that the
  actual failure mode is a SILENT false-healthy 0, not the loud exit-3 the
  issue assumed. [PR #307](https://github.com/voltron-1/Suburban_SOC/pull/307)
  merged 2026-08-08 (squash), 15/15 CI green. Filed 4 follow-ups from
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
  - [x] **#303 — COMPLETE, MERGED**, fixed 2026-08-09: root cause was
    actually TWO bugs, not just apostrophes — Compose's variable-
    interpolation pass (runs before shell-word-splitting, no concept of "this
    is a comment") also choked on a bare `$` in explanatory comment text.
    [PR #317](https://github.com/voltron-1/Suburban_SOC/pull/317) merged
    2026-08-09 (squash), 13/13 CI green including the new `docker compose
    config (interpolation/syntax)` job this PR itself introduced — the first
    real run of that check against the fully-combined M14 batch content,
    since every other M14 PR branched before it existed on `main`.
    Live-verified: `docker compose up -d` now runs clean end-to-end on a real
    host (every one-shot provisioning container exits 0, every long-running
    service comes up healthy) — this was blocking `docker compose up`
    entirely before the fix. Filed
    [#318](https://github.com/voltron-1/Suburban_SOC/issues/318) for 3
    further follow-ups from that review (cleartext argv exposure for most
    `provision` passwords, no error handling on provisioning failures,
    fragile YAML folded-scalar indentation), deliberately deferred.
- [x] **#277 (P0, security) — COMPLETE, MERGED** — broker's
  `/webhook/dispatch` response was completely unauthenticated; an on-path
  attacker could forge a confirmed success (falsely closing a case) or
  force an unsafe retry. [PR #310](https://github.com/voltron-1/Suburban_SOC/pull/310)
  merged 2026-08-08 (squash), 16/16 CI green. 4 review rounds, 2 found real
  HIGH gaps in earlier drafts (each empirically confirmed exploitable, then
  empirically confirmed closed, not just reasoned about): round 2 found no
  domain separation between request- and response-signing, so the agent's
  own signed request verified successfully if reflected back as a fake
  response — fixed with a domain-separating byte prefix. Round 3 found the
  signature alone didn't bind a response to the specific request that
  produced it, so a captured genuine response could be replayed against a
  *different* dispatch (same IP under a different tenant, or the same IP
  redispatched later) — fixed with a per-request nonce (`request_id`,
  signed inside the request so an attacker can't choose or rewrite it).
  Round 4 found the fix itself had regressed the repo's own #177/AC-4
  masking policy (raw attacker IP pushed unmasked to ntfy.sh) — fixed.
  Every new security property mutation-tested (fails without its fix,
  passes with it). One CodeQL false positive hit post-review (same
  clear-text-logging-heuristic shape as #246 — a variable near something
  named `*_secret` flagged despite holding only a label string; renamed,
  fixed). Follow-ups filed, deliberately out of scope: #308 (P0-adjacent —
  the broker's non-200 HTTPException error responses are still unsigned,
  a narrower variant of the same bug class) and #309 (request_id
  sanitization/bounding, audit-trail correlation, a detection rule for the
  two new tamper-indicator audit actions, redirect-following hardening).
- [x] **#276, #278 (P1) — COMPLETE, MERGED** — no operator tool for a
  stuck claim; an `unknown` isolation outcome has no reconciliation path.
  [PR #311](https://github.com/voltron-1/Suburban_SOC/pull/311) merged
  2026-08-09 (squash) — added `manage_stuck_claims.py`, a CLI to inspect/
  release/resolve a stuck claim, with optimistic-concurrency (if_seq_no/
  if_primary_term) protection and idempotent blocking so a retried
  reconciliation can't double-execute. #276/#278's SOP-005 OpenWrt UCI
  `config include` syntax check remains genuinely untestable in this
  environment (no real OpenWrt/fw4 hardware) — reconfirmed, not newly
  unblocked. A genuine pre-existing mypy bug (`_transition_claim()`'s
  `doc`/`params` dict typing — mypy couldn't narrow `if_primary_term`
  through the function's own XOR guard) was found and fixed during the
  merge-to-main pass, unrelated to the feature logic; 88/88
  claim-transition tests pass unchanged.
- [x] **#286 (P2) — COMPLETE, MERGED** — MAC-based device quarantine is
  non-functional (two stacked pipeline breaks: no `orig_l2_addr`→
  `source.mac` rename in the reachable Logstash branch, and no
  conn.log↔intel.log join even after that).
  [PR #313](https://github.com/voltron-1/Suburban_SOC/pull/313) merged
  2026-08-09 (squash) — added the rename plus a uid-keyed correlation via
  a new dedicated `logstash_enrich_reader` read-only identity (least
  privilege, separate from `logstash_writer`, which holds no read at
  all). Filed [#312](https://github.com/voltron-1/Suburban_SOC/issues/312)
  as a deferred policy decision (AUTONOMOUS_ISOLATION gate), deliberately
  out of scope. The PR's own `Conn::IN_RESP` live-runtime test-plan item
  was resolved by the repo owner choosing to accept the existing
  static-analysis verification (direct Zeek source-code tracing) rather
  than restart the just-stabilized zeek-host-capture sensor again.
- [x] **#256 (P2) — COMPLETE, MERGED** — agent-checkpoints TTL retention.
  [PR #314](https://github.com/voltron-1/Suburban_SOC/pull/314) merged
  2026-08-09 (squash) — a new `agent_checkpoints_compactor` least-privilege
  identity (read+delete only, deliberately separate from the live agent's
  own no-delete credential) plus a scheduled systemd timer, matching the
  `slo-metrics` pattern. Hit a real merge conflict against `main` (both
  this and #313 added independent env-var/role-provisioning blocks to
  `docker-compose.yml`/`.env.example` at the same insertion point) —
  resolved by keeping both blocks intact, each with its own `if`/`fi`;
  mypy clean, 43 source files.
- [x] **#257 (P2) — COMPLETE, MERGED** — hardening follow-ups from #245's
  review (placeholder-secret rejection, `logstash_writer` cluster-
  privilege reduction, claim-squatting detection).
  [PR #315](https://github.com/voltron-1/Suburban_SOC/pull/315) merged
  2026-08-09 (squash).
- [x] **#259 (tech-debt) — COMPLETE, MERGED** — `slo_metrics.py`'s `.env`
  parser breaks on inline comments; also fixed `run_hunts.py`'s identical
  bug, and a more severe issue this one's fix exposed —
  `slo-metrics.service`'s systemd `EnvironmentFile=` stayed broken
  regardless of the Python-level fix, and separately `ES_PASS` was never
  actually being set at all (`Environment=` doesn't expand `${VAR}`,
  verified empirically). [PR #316](https://github.com/voltron-1/Suburban_SOC/pull/316)
  merged 2026-08-09 (squash) — another real merge conflict (#315 and #316
  independently added test classes to the same insertion point in
  `test_slo_metrics.py`), resolved by keeping both classes; 4/4 of the
  directly-affected tests pass post-resolution.

- [x] **Session-initiated, no issue — `zeek-host-capture.service`
  crash-loop — COMPLETE, MERGED** — the SOC's only network sensor had
  been crash-looping in production since #222 (a `chown` `ExecStartPre`
  added without the matching `CAP_CHOWN` in #209's
  `CapabilityBoundingSet=`). Found and fixed live across 4 rounds:
  restored `CAP_CHOWN`; redesigned root/tjlam directory sharing as
  chgrp+sticky-bit (a one-time `chown` silently became a permanent no-op
  after the first restart); added `CAP_SETUID`/`CAP_SETGID` for
  tcpdump's own default privilege-drop to its unprivileged system user,
  found live only after the first fix was already confirmed working;
  closed a CWE-59 symlink-follow gap (HIGH, from an emergency
  security-auditor review) with a fail-closed guard + `cp
  --remove-destination`, and added `set -o pipefail` so a dead tcpdump
  leg can't hide behind docker's exit status. Live-verified at every
  stage on the production sensor, not just `systemd-analyze verify` —
  real traffic into `conn.log`, `ps` confirming tcpdump drops to its
  unprivileged user, directory ownership matching the design exactly.
  [PR #324](https://github.com/voltron-1/Suburban_SOC/pull/324) merged
  2026-08-09 (squash) — no GitHub-side human review, explicit
  review-bypass confirmed by the repo owner (green CI, sub-agent review
  only, same basis as M13's #298/#300/#301). Residual, tracked
  separately: [#270](https://github.com/voltron-1/Suburban_SOC/issues/270)
  (config.zeek's own co-location in a tjlam-writable tree) not closed by
  this fix.
- [x] **Session-initiated, no issue —
  `scripts/setup/install_intel_refresh_timer.sh` off-by-one repo path —
  COMPLETE, MERGED** — `REPO="$(cd "$HERE/.." && pwd)"` resolved to
  `scripts/`, not the repo root (should be `$HERE/../..`, matching the
  sibling `redeploy_systemd_units.sh`), breaking a fresh install
  (`cannot stat 'configs/systemd/intel-refresh.service'`).
  [PR #323](https://github.com/voltron-1/Suburban_SOC/pull/323) merged
  2026-08-09 (squash). Live-verified once fixed: fetched 5 Feodo Tracker
  + 555 Emerging Threats indicators, wrote `intel.dat` into the capture
  directory — also incidentally proving the zeek-capture ownership fix
  chain above works end-to-end.
- [x] **Session-initiated, no issue — version `CLAUDE.md` + custom
  agent/slash-command definitions — COMPLETE, MERGED** — `CLAUDE.md`
  (blue-team analysis conventions) and
  `.claude/agents/ir-report-reviewer.md` +
  `.claude/commands/{sigma-validate,sigma-rule,triage}.md` existed only
  locally, uncommitted. [PR #325](https://github.com/voltron-1/Suburban_SOC/pull/325)
  merged 2026-08-09 (squash), same review-bypass basis as PR #324.

**M14 is COMPLETE** — all 8 milestone issues closed 2026-08-09 (#276,
#278, #286, #256 merged via squash without an auto-close keyword —
`Part of #XXX` phrasing, same recurring shape as M12/M13's PRs — closed
manually with the merging PR cited as evidence; #275/#277/#257/#259
auto-closed). All 7 PRs from this session (#311, #313, #314, #315, #316,
#317, #323) merged squash, no GitHub-side human review — explicit
review-bypass confirmed by the repo owner as one batch covering all 7,
each branch updated to `main` and green on all required CI immediately
before its own merge. Three PRs
(#314, #316, and the zeek-capture branch earlier) hit real merge
conflicts as `main` advanced between merges — all textually-additive
(independent blocks/test classes landing at the same insertion point,
no semantic overlap), resolved by keeping both sides' content intact and
re-verifying mypy/tests after each resolution, not just re-running
`systemd-analyze verify`-style syntax checks. `main` post-merge: mypy
clean across 45 source files, 434/437 tests pass (the 3 failures are
pre-existing and unrelated — a mocked `coverage_techniques` value
tripping an unrelated SLO threshold, confirmed via `git stash` comparison
against unmodified `HEAD`).

- [x] **#252 (P2, bug) — COMPLETE, MERGED** — `ScriptBlockText`'s
  `ignore_above:8191` (#249/#250) may still be below real PowerShell 4104
  chunk sizes, silently dropping obfuscated payloads from the index while
  they stay visible in `_source` — exactly what
  `posh_ps_obfuscated_scriptblock.yml` exists to catch. Scoped to making
  this measurable (not guessing a bigger ceiling with no data):
  `configs/logstash.conf` tags `pipeline.truncated` (+ which field) when
  `process.args`/`process.parent.args`/`ScriptBlockText` exceed the
  ceiling; `metric_field_truncation_count()` in `slo_metrics.py` is the
  new `NO_TARGET` SLO baseline. [PR #327](https://github.com/voltron-1/Suburban_SOC/pull/327)
  merged 2026-08-09 (squash), 17/17 CI green including `live-fire`,
  auto-closed #252. Live-verified, not just reasoned about: the exact
  production ruby filter run on the real JRuby engine correctly tagged an
  over-ceiling synthetic event and correctly left an exactly-at-boundary
  (8191 chars) event untagged; separately, a synthetic 8516-char
  `ScriptBlockText` containing a real obfuscation indicator
  (`FromBase64String`) was confirmed unqueryable via the exact wildcard
  pattern the Sigma rule selects on, while remaining intact in `_source`,
  against a scratch index carrying the real production template. Live
  verification required restarting `logstash` for the first time since
  #286 merged, which surfaced two unrelated pre-existing outages that
  crash-looped the whole pipeline — both fixed in the same PR since they
  blocked verification entirely: `LOGSTASH_ENRICH_PASSWORD` was never in
  `scripts/setup/.env` (`logstash_enrich` had never actually been
  provisioned), and a stray apostrophe in a `docker-compose.yml` comment
  (introduced by #257/PR #315 earlier this same session) silently
  truncated the `provision` service's entire bootstrap script after its
  third command — the same interpolation-fragility class #303 fixed on
  Compose's variable-interpolation pass, but on the runtime shell-parsing
  side, which #303's own `compose-config` CI check does not cover
  (confirmed: that check still passes on the buggy version).
  `logstash_enrich_reader`'s role also lacked `cluster:[monitor]`, needed
  by the `elasticsearch` filter plugin's own startup connectivity check —
  ES's own 403 error named the exact fix. Follow-up filed, deliberately
  out of scope: [#326](https://github.com/voltron-1/Suburban_SOC/issues/326)
  (#252's original suggested `wildcard`-typed unbounded multi-field for
  `ScriptBlockText`, gated on real data from the new metric — 0 real
  `ScriptBlockText` docs exist in this environment today).

Next unstarted item: none — M14 and #252 are both done; M15 (including
#263) is the active milestone, tracked in NEXT UP at the top of this file,
not here.

</details>

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

**M13 milestone note:** [#252](https://github.com/voltron-1/Suburban_SOC/issues/252),
deferred since US1 (2026-08-02) as separate scope from M13's rule-count
goal, is now **COMPLETE, CLOSED** — see NEXT UP at the top of this file
for full detail ([PR #327](https://github.com/voltron-1/Suburban_SOC/pull/327)).

M14 started 2026-08-08 — see NEXT UP at the top of this file for its live
status.

</details>

---

## MILESTONE BACKLOG — M15/M16, opened 2026-08-05 (M14 moved to NEXT UP, started 2026-08-08)

13 open issues had accumulated with **no milestone at all** — every one filed as
a follow-up during an M11/M12 security review, real but deliberately out of
scope for the issue being fixed at the time. Triaged into three milestones so
they stop being invisible.

M14 is complete and M15 is now IN PROGRESS — see NEXT UP at the top of this
file, not here.

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

## LAST SESSION — 2026-08-18

- **#393 closed (M17) — threshold-rule sliding-window containment math was
  wrong corpus-wide, not just on the 2 files named in the issue title.**
  [PR #423](https://github.com/voltron-1/Suburban_SOC/pull/423) merged
  (squash), all 12 CI checks green after two cancel+rerun cycles on an
  infra-flaky `pytest-cov` job (same "Install WeasyPrint native
  dependencies" hang as the #422 precedent, confirmed via `gh run list`
  history before retrying). Corrected `lookback >= interval +
  detection_window` on all 8 `rules/elastic/threshold/*.ndjson` files;
  generalized `ThresholdLiveFireTests` from 1 hardcoded file to all 8,
  which caught a real drift (auth-win-bruteforce-source-spray.ndjson's
  #370 IP-sentinel exclusion never back-ported to its paired Sigma file)
  and 2 live-fire test bugs (source.ip `ignore_malformed` silent-drop;
  entity-value cross-contamination between the two identical-query
  zeek-ssh threshold files). Parallel review added a compile-time
  regression guard for the window-math fix itself (nothing previously
  proved the *new* window was deployed vs. merely proving some window
  existed) — mutation-tested, both revert scenarios caught. Full detail
  in `findings/20260817-393-threshold-window-and-live-fire.md`.
- **M17 discovered NOT complete on re-check.** This resumed run's own
  fixes for #386/#387/#382/#383/#384/#392 had filed 10 real follow-up
  issues (#407, #410, #411, #413, #414, #415, #417, #418, #420, #421),
  each properly milestoned to M17 at creation, none previously reflected
  in this doc's running tally (which had been tracking only the original
  15-issue corrected set, not issues discovered mid-run). Corrected via
  `gh issue list --search 'milestone:"M17 - Detection Rule Coverage &
  Correctness"'` (the ground truth, not this doc's own prior narrative).
  **True M17 state: 13/25 closed, 10 real actionable issues still open,
  2 permanently not actionable (#283, #333).** Continuing the same
  resumed run through the corrected queue — not reporting completion to
  the user yet, since real work remains.
- **#410 closed (M17) — SMTP rule titles now disclose plaintext-only
  scope.** [PR #427](https://github.com/voltron-1/Suburban_SOC/pull/427)
  merged (squash), all 12 CI checks green with no infra flakiness this
  time. Parallel review fixed an adjacent pre-existing description bug
  both reviewers caught independently, and surfaced 3 out-of-scope
  findings, all filed and milestoned: #424 (M20), #425 (M17), #426
  (M17). Full detail in `findings/20260818-410-smtp-title-plaintext-
  scope.md`. **M17 now 14/27 closed** (11 real follow-ups open, 2 not
  actionable) — continuing the resumed run.
- **#426 closed (M17) — DoH rule title now discloses hardcoded-IP blind
  spot.** [PR #429](https://github.com/voltron-1/Suburban_SOC/pull/429)
  merged (squash), all 12 CI checks green. security-auditor review
  reworded the title's first draft to name the exploitable gap directly;
  filed #428 (M17) for an out-of-scope pre-existing gap (unanchored
  `endswith` domain matching); corrected #425's severity framing via
  comment (its collision is already live on `main`, not hypothetical).
  Full detail in `findings/20260818-426-doh-title-scope.md`. **M17 now
  15/28 closed** (11 real follow-ups open, 2 not actionable) —
  continuing the resumed run.
- **#425 closed (M17) — build_attack_coverage.py's Navigator-tooltip
  delimiter fixed.** [PR #433](https://github.com/voltron-1/Suburban_SOC/pull/433)
  merged (squash), all 12 CI checks green. Confirmed the em-dash
  delimiter bug was already live on `main` (T1110's tooltip), not
  hypothetical. Parallel review folded a structural non-ambiguity test
  and a delimiter/guard-coupling refactor directly into this PR (both
  explicitly requested by security-auditor rather than deferred); filed
  #430/#431/#432 (M17) for related-but-out-of-scope gaps the same review
  found, one of which (#432) is a silent-data-loss risk via upsert, not
  just a display-ambiguity bug. Full detail in
  `findings/20260818-425-merged-comment-delimiter.md`. **M17 now 16/31
  closed** (13 real follow-ups open, 2 not actionable) — continuing the
  resumed run.
- **#428 closed (M17) — DNS rules' unanchored endswith suffix matching
  fixed.** [PR #435](https://github.com/voltron-1/Suburban_SOC/pull/435)
  merged (squash), all 12 CI checks green including the real live-fire
  ES job. security-auditor review found the identical bug live in a
  higher-severity sibling rule (net_zeek_dns_crypto_mining_pool.yml,
  level: medium) and it was fixed directly in this same change rather
  than filed publicly, per the standing no-disclosure convention for
  live gaps. Also fixed a same-class bug in sigma_eval.py's shared
  endswith handling, added permanent live-fire regression tests for
  both rules, and filed #434 (M17) for the emission-vs-registration
  design gap the fix doesn't close. Full detail in
  `findings/20260818-428-dns-unanchored-suffix-fix.md`. **M17 now 17/32
  closed** (13 real follow-ups open, 2 not actionable) — continuing the
  resumed run.
- **#430 closed (M17) — build_attack_coverage.py's network-path tactic
  validation fixed.** [PR #438](https://github.com/voltron-1/Suburban_SOC/pull/438)
  merged (squash), all 12 CI checks green. security-auditor review found
  the initial fix incomplete — a regex block-boundary anchoring bug
  could silently mis-pair or drop entries (mutation-tested to confirm),
  tactic id was unvalidated, technique id was unnormalized, comments
  weren't stripped — all fixed in the same change with new regression
  coverage. Filed #436/#437 (M17) for two smaller separate gaps. Full
  detail in `findings/20260818-430-network-tactic-validation.md`. **M17
  now 18/34 closed** (14 real follow-ups open, 2 not actionable) —
  continuing the resumed run.

---

## LAST SESSION — 2026-08-16

- **Backlog restructured into 6 new milestones (M17–M22), M13/M14/M15
  closed.** 37 open issues had accumulated, 33 with no milestone at all —
  real review follow-ups filed across M12–M16 and never triaged. Sorted
  by theme into M17 (detection-rule correctness), M18 (ECS
  pipeline/field-mapping integrity), M19 (platform credential hygiene),
  M20 (SOAR response-path hardening), M21 (Zeek sensor resilience), M22
  (compliance/docs accuracy). M13 (25/25), M14 (8/8), M15 (11/11) closed
  outright — M15's one open item (#283) moved to M17, its true thematic
  home. Full detail above in NEXT UP.
- **README, wiki, and project board synced to the restructuring.**
  README's Project Status table and Recent Enhancements updated
  ([commit `ff56977`](https://github.com/voltron-1/Suburban_SOC/commit/ff56977)),
  also fixing a stale "docker compose is broken" note (#303 closed
  2026-08-09, not reflected in prose until now). Wiki `Home.md` mirrored
  the same table (pushed to the separate `Suburban_SOC.wiki` repo). GitHub
  Projects v2 board verified structurally accurate: all 37 open issues
  present as Backlog with Milestone auto-synced to the new split (M16=3,
  M17=8, M18=11, M19=6, M20=3, M21=3, M22=3), all closed issues as Done.
- **#344 closed — long_command_fields dynamic_template byte-clamp gap.**
  Full detail in NEXT UP's "M18 progress" above.
  [PR #368](https://github.com/voltron-1/Suburban_SOC/pull/368) merged
  2026-08-16 (squash), auto-closing #344. M18 now 1/11 closed. Filed
  [#367](https://github.com/voltron-1/Suburban_SOC/issues/367) (deferred
  structural fix) as a new M18 Backlog item.
- **#341 closed — dashboard panels bucketing on nonexistent `.keyword`
  fields.** Full detail in NEXT UP's "M18 progress" above.
  [PR #369](https://github.com/voltron-1/Suburban_SOC/pull/369) merged
  2026-08-16 (squash), auto-closing #341. M18 now 2/11 closed. Grew from
  a 4-field fix into a repo-wide sweep (22 total fields fixed across 8
  dashboard files) plus a new CI-enforced regression test
  (`tests/dashboards/test_dashboard_field_mapping.py`).
- **#342 closed — Windows Security-channel events get ECS source
  attribution.** Full detail in NEXT UP's "M18 progress" above.
  [PR #371](https://github.com/voltron-1/Suburban_SOC/pull/371) merged
  2026-08-16 (squash), auto-closing #342. M18 now 3/13 closed. Two
  security-auditor review rounds plus a code-reviewer pass hardened the
  fix well beyond its original scope (sentinel/`::ffff:` guards,
  copy-direction test coverage); CI's CodeQL gate then caught a
  ReDoS in the review's own remove_field-detection regex, fixed with a
  linear scan before merge. Filed
  [#370](https://github.com/voltron-1/Suburban_SOC/issues/370) (raw-field
  threshold-rule sentinel gap) as a new M18 Backlog item.
- **#337 closed — user.name had no ignore_above; truncation filter
  restructured to per-field ceilings.** Full detail in NEXT UP's "M18
  progress" above. [PR #372](https://github.com/voltron-1/Suburban_SOC/pull/372)
  merged 2026-08-16 (squash), auto-closing #337. M18 now 4/13 closed.
  Two security-auditor rounds (related.user array-clamp trap, gsub
  ordering, Ruby-vs-Java UTF-16 counting, guard generality, plus 3 more
  minor follow-up gaps) — all fixed and mutation-tested.
- **#361 closed (M16) — a deleted CLAIMED-or-RESOLVED claim doc is now
  detected instead of silently reopening the at-most-once execution
  gate.** Full detail in NEXT UP's new "M16 progress" above.
  [PR #375](https://github.com/voltron-1/Suburban_SOC/pull/375) merged
  2026-08-16 (squash), auto-closing #361. New `vanished_claims` SLO
  metric; scope grew from CLAIMED-only to CLAIMED+RESOLVED after a
  tester-debugger live-verification finding that deleting an
  already-RESOLVED claim is exploitable the same way and arguably worse
  (re-dispatches a completed containment action). Two parallel review
  rounds (security-auditor + code-reviewer) independently found the same
  root defect in the first draft — Elasticsearch's `exists` query doesn't
  match `[]`, silently skipping every quiet run's baseline — plus a
  separate `slo_metrics_reader` role gap (missing `read` on
  `soc-slo-metrics`) that would have 403'd the new metric in production
  despite every mocked test passing. Both tester-debugger live-verification
  passes confirmed the fixes hold against the real stack, not just mocks.
  Filed [#373](https://github.com/voltron-1/Suburban_SOC/issues/373)
  (dashboard panel / durable per-run record) and
  [#374](https://github.com/voltron-1/Suburban_SOC/issues/374)
  (`soc_admin`'s `soc-*` wildcard) as new, deliberately out-of-scope
  follow-ups. M16 down to #358 (next up) and #265 (still deferred).
- **#358 closed (M16) — threat-intel wipe detection now live; async
  delete_by_query no longer orphans a server-side task on client
  timeout.** Full detail in NEXT UP's "M16 progress" above.
  [PR #377](https://github.com/voltron-1/Suburban_SOC/pull/377) merged
  2026-08-17 (squash), auto-closing #358. Root-cause finding: the
  pre-existing `intel_feed_stale.json` Watcher this issue's own text
  assumed was live has never fired here (Watcher is unlicensed, Basic
  license) — migrated detection into `slo_metrics.py`'s SLO-metric
  framework instead of adding a second dead Watcher, confirmed with the
  repo owner first. security-auditor found the resulting wipe-detection
  metric could be blinded by the exact credentials the issue names —
  closed with a second, credential-untouchable baseline persisted to
  `soc-slo-metrics`, taking the worse of both comparisons. Also closed:
  two missing ES role grants (`slo_metrics_reader` on `threat-intel-*`,
  `threat_intel_compactor`'s missing `cluster:monitor`) that would have
  403'd the whole fix in production despite every mocked test passing —
  same #275/#361 bug shape, live-confirmed 403→200. tester-debugger
  reproduced two real async-delete task failures against the live
  cluster to validate the failure-handling path, not just the happy path.
  Filed [#376](https://github.com/voltron-1/Suburban_SOC/issues/376)
  (`compact_agent_checkpoints.py` has the identical async-delete gap) as
  a new follow-up. **M16 down to just #265** (still deferred) — no
  actionable work left in this milestone.
- **#281 closed (M17, first issue) — ATT&CK coverage matrix no longer
  overstates coverage by publishing 108 rule-mappings as "108
  techniques."** Full detail in NEXT UP's new "M17 progress" above.
  [PR #381](https://github.com/voltron-1/Suburban_SOC/pull/381) merged
  2026-08-17 (squash), auto-closing #281. The issue's own suggested fix
  (dedup by techniqueID alone) turned out to be wrong — would have
  silently dropped a real, legitimate Navigator cell (T1078.003 spans two
  tactics) — caught by live-deriving ATT&CK Navigator's actual layer-format
  semantics rather than trusting the issue's suggestion at face value.
  Fixed by grouping on `(techniqueID, tactic)` instead. security-auditor
  found the new regression tests were never wired into CI (inert guard)
  and that the strongest invariant wasn't pinned — both closed. Filed
  [#378](https://github.com/voltron-1/Suburban_SOC/issues/378),
  [#379](https://github.com/voltron-1/Suburban_SOC/issues/379), and
  [#380](https://github.com/voltron-1/Suburban_SOC/issues/380) as
  follow-ups. M17 now 1/8 closed; #365 in progress next.
- **#365 closed (M17) — Zeek's `mime_type` list corrected to what Zeek
  actually produces, not what general-purpose libmagic would.** Full
  detail in NEXT UP's "M17 progress" above. [PR #385](https://github.com/voltron-1/Suburban_SOC/pull/385)
  merged 2026-08-17 (squash), auto-closing #365, 17/17 CI green after a
  toolchain-drift fix (same #330 class as before — regenerated
  `SIEM_KQL_Documentation.md` against a venv matching CI's unpinned
  install exactly). Live-verified all 9 original mime_type entries
  against the real pinned zeek/zeek image; found Zeek uses its own
  independent signature engine, not system libmagic, and that 5 of 9
  entries were structurally dead. security-auditor (no shell access that
  session) still found real evidence gaps via static analysis — closed by
  broadening a single-file grep to the whole image tree and re-testing
  against 3 genuine Windows binaries (pulled from this WSL host's own
  mounted C:\Windows) instead of the original hand-crafted PE. code-
  reviewer proved (via a reverted mutation test) the new regression test
  was missing the exact original bug string. Filed #382, #383, #384 as
  follow-ups. M17 now 2/8 closed.
- **#351 closed (M17) — `sigma_eval.py`'s Sigma-detection evaluator had no
  array-value semantics; a multi-valued Zeek field (dns.answers) was
  silently matched against its own Python `str(list)` repr instead of
  per-element.** Full detail in NEXT UP's "M17 progress" above.
  [PR #388](https://github.com/voltron-1/Suburban_SOC/pull/388) merged
  2026-08-17 (squash), auto-closing #351, 12/12 CI green. Fixed with
  per-element OR recursion; security-auditor (round 2) caught that a naive
  version of this fix gets the `all` modifier backwards (OR-over-elements
  (AND-over-targets) instead of real Elasticsearch's AND-over-targets
  (OR-over-elements)) — not live-exploitable today, fixed anyway since it's
  wrong in exactly the code this issue adds. Two rounds of review
  (code-reviewer/security-auditor, then tester-debugger) each caught that
  the regression-pinning test didn't actually discriminate old vs. fixed
  behavior — both replaced with bare-equality-based tests, each confirmed
  via `git stash` mutation testing to fail pre-fix and pass post-fix. Filed
  #386, #387 as follow-ups. **M17 now 3/8 closed; #352 next.**
- **#352 closed (M17) — a Zeek dns.answers element over
  ignore_above:8191 was silently unindexed with zero visibility.**
  Full detail in NEXT UP's "M17 progress" above. [PR #391](https://github.com/voltron-1/Suburban_SOC/pull/391)
  merged 2026-08-17 (squash), auto-closing #352, 17/17 CI green. Added a
  visibility tag + paired SLO metric; two review rounds found the first
  draft silently skipped both a scalar `dns.answers` (the shape an
  unauthenticated `:5514` POST actually produces) and a nested array
  (live-confirmed against real Elasticsearch to flatten and silently drop
  exactly like a flat array) — both fixed. A tester-debugger agent's
  wire-verified DNS-packet replay against the real pinned `zeek/zeek:8.2.1`
  image found the fix's own `>8191` premise is structurally unreachable
  for real TXT traffic — Zeek itself silently truncates at ~4096 chars
  first, with no marker — disclosed honestly rather than hidden, kept as
  defense-in-depth. Filed #389 (the actual, more significant blind spot
  this uncovered — Zeek's own silent truncation) and #390 (sibling array
  fields with the same shape) as follow-ups. **M17 now 4/8 closed; #332
  or #331 next** (#283/#333 remain not actionable).
- **#332 closed (M17) — session-cadence SSH brute-force threshold rule
  added, closing the recall gap below detect-bruteforcing's 30-attempts/
  30-minutes default.** Full detail in NEXT UP's "M17 progress" above.
  [PR #394](https://github.com/voltron-1/Suburban_SOC/pull/394) merged
  2026-08-17 (squash), auto-closing #332, 13/13 CI green (after two
  retries on a transient GitHub-infrastructure outage affecting CodeQL's
  SARIF upload step specifically — the analysis itself was clean both
  times, not a real code issue). Live-verified via a real captured SSH
  session (docker bridge network, replayed through the pinned
  zeek/zeek:8.2.1 image) that auth_success is entirely absent on
  failed-auth ssh.log records. Two review rounds corrected an overclaim
  (5-in-6-minutes and 30-in-30-minutes are the SAME steady-state rate —
  this rule improves detection latency, not the rate floor), documented
  a known limitation (SSH::Info$client is &optional, undercounts on a
  lossy vantage), and caught a fixture true_negative that was actually a
  true positive under Sigma's case-insensitive default (verified directly
  against sigma_eval.py before landing). A CI failure traced to a new,
  more precise root cause than #330's tracked toolchain-drift class:
  Python 3.11 (CI) vs 3.12 (local) render Lucene escaping differently for
  the same pysigma-backend-elasticsearch version — regenerated under a
  real python:3.11.15 container to match CI exactly; correction posted
  to #330. Filed #392 (long-window companion for genuinely sustained
  low-and-slow coverage) and #393 (threshold-rule test hardening) as
  follow-ups. **M17 now 5/8 closed; #331 next** (#283/#333 remain not
  actionable).

---

## LAST SESSION — 2026-08-17

- **#331 closed (M17) — `metric_raw_alert_volume()`'s `zeek_notices`
  sub-count was gameable by a spoofed-source SYN sweep (one notice per
  forged source, zero real network presence).** [PR #395](https://github.com/voltron-1/Suburban_SOC/pull/395)
  merged 2026-08-17 (squash), auto-closing #331, 17/17 CI green. Two full
  rounds of parallel security-auditor + code-reviewer across three design
  attempts. Design 1 (gate counting on `connection_established`/
  `connection_rejected`) and design 2 (a global notice-volume cap) were
  each found broken by live security review — neither actually defends
  against spoofing at this deployment's host-based capture topology
  (`zeek-host-capture.service` watches the monitored host's OWN interface,
  so its real reply to a spoofed SYN is exactly as visible to Zeek as a
  reply to a genuine one), and each cost real detection recall or
  introduced its own silent denial-of-detection primitive. Design 3
  (shipped): `scan-detection.zeek` fully reverted to its original,
  unchanged form (plus a comment-only history block); the real fix is a
  new `zeek_notices_distinct_sources` cardinality signal in
  `slo_metrics.py`, scoped to the same query as `zeek_notices` — a
  spoofed flood now reads as an interpretable metric anomaly instead of
  being fought (unsuccessfully) at the sensor. A third review round on
  this final design found it sound with no further structural break, plus
  3 MEDIUM/4 LOW polish findings, all fixed before merge (shard-failure
  detection in the new `_cardinality()` helper, a corrected
  `precision_threshold` docstring claim, a documented known limitation, a
  missing non-200 test, and the scan-detection.zeek history note).
  Consequence recorded on the issue and in NEXT UP: T1046 staying out of
  live SOAR dispatch — previously framed as "deferred until #331" — is now
  permanent, not deferred; no source-authenticity signal exists for
  `Scan::Port_Scan` at this deployment's vantage point.
  **M17 now 6/8 closed** — #283 (externally blocked) and #333
  (speculative/deprioritized) are the only issues remaining, neither
  currently actionable. No further M17 work is queued.

---

## LAST SESSION — 2026-08-15

- **#288 closed — capture-loss/resource guard now live on the real
  capture path.** Full detail in NEXT UP above.
  [PR #354](https://github.com/voltron-1/Suburban_SOC/pull/354) merged
  2026-08-13 (squash, `892b399`), 3 review rounds, 6 real findings closed
  — not yet reflected in this doc before now. M15 down to its 1
  already-known-blocked P3 (#283). A new milestone,
  [M16 — Endpoint Onboarding & Threat-Intel Integrity](https://github.com/voltron-1/Suburban_SOC/milestone/20),
  has appeared on the tracker with 4 open P3 issues (#293, #271, #270,
  #265) — none individually triaged into this doc before now. Recommending
  #293 (pin `zeek/zeek`) as the next pick: smallest fully-scoped, no
  dependency on hardware this environment lacks.
  Session also confirmed nothing was unpushed: the working branch
  (`fix/288-capture-loss-resource-guard`) was already up to date with its
  merged remote counterpart, no push needed.

- **#293 closed — all 4 real Zeek capture invocations now pin
  `zeek/zeek` to a specific tag+digest, not `:latest`.** Full detail in
  NEXT UP above. [PR #356](https://github.com/voltron-1/Suburban_SOC/pull/356)
  merged 2026-08-15 (squash, `5ebbe1f`), 13/13 CI green. security-auditor +
  code-reviewer + tester-debugger ran in parallel; two review rounds
  hardened the new regression test itself (regex anchoring against
  registry/typosquat lookalikes, comment-exclusion so a stale comment
  can't mask a swapped real invocation) and caught that the pin's own
  existence breaks SOP-147's evidence-validation `docker ps` filter the
  moment `:latest` and the pinned tag diverge — confirmed empirically
  (removed the local `:latest` tag, retested) before fixing it, not just
  reasoned about. Follow-up filed:
  [#355](https://github.com/voltron-1/Suburban_SOC/issues/355) (the now-
  frozen image has no Trivy scanning coverage — a real gap, not a known
  live vulnerability, tagged to M16). M16 down to 3 open P3s (#271, #270,
  #265) plus #355; recommending #271 next — smallest remaining, no
  cross-service synchronization needed unlike #270.

- **#271 closed — threat-intel-indicators/threat-intel-meta now retract
  removed indicators via a periodic TTL compactor.** Full detail in NEXT UP
  above. [PR #360](https://github.com/voltron-1/Suburban_SOC/pull/360)
  merged 2026-08-16 (squash, `b50d48b`), 17/17 CI green. The session's
  most consequential finding: `intel-refresh.service`, installed and
  actively running on this host, had the exact `systemd Environment=${VAR}`-
  doesn't-expand bug #259 already fixed once for `slo-metrics.service` —
  its scheduled runs have very likely never successfully written to ES
  until this fix, discovered only because live verification against the
  real stack surfaced a discrepancy (a delete_by_query the compactor
  script reported succeeding didn't change ES's count until a manual
  `_refresh`, which led to re-checking the whole write path). Also found
  live: the original retention design keyed on a field (`threat.indicator.
  last_seen`) this same PR introduced, making the pre-existing backlog it
  was meant to clean up permanently undeletable — caught by re-querying
  real data (170/728 docs lacked the field), fixed to key on `@timestamp`
  instead. This session also required restarting a wedged Docker Desktop
  WSL backend twice (with explicit user confirmation each time) before any
  live verification against a real stack was possible — see mid-session
  troubleshooting; resolved via Docker Desktop's own "Restart the WSL
  integration" action, not a repo change. Follow-ups filed:
  [#357](https://github.com/voltron-1/Suburban_SOC/issues/357)
  (`checkpoints-compact.service` has the identical `Environment=` bug, not
  installed here so lower urgency), [#358](https://github.com/voltron-1/Suburban_SOC/issues/358)
  (no detection if `threat-intel-indicators` is wiped; delete_by_query
  timeout doesn't cancel server-side), [#359](https://github.com/voltron-1/Suburban_SOC/issues/359)
  (Elasticsearch `:9200` bound to all interfaces, not just localhost).
  M16 down to 2 of its original 3 P3s (#270, #265) plus 4 accumulated
  follow-ups (#355, #357, #358, #359); recommending #357 next — the fix
  pattern is now proven twice, applying it a third time is the smallest,
  most mechanical remaining pick.

- **#357 closed — checkpoints-compact.service's identical `Environment=${VAR}`
  bug fixed (the fourth occurrence of this class), plus a repo-wide guard
  added so it can't recur a fifth time undetected.** Full detail in NEXT
  UP above. [PR #362](https://github.com/voltron-1/Suburban_SOC/pull/362)
  merged 2026-08-16 (squash, `aa73b63`), 13/13 CI green. security-auditor +
  code-reviewer found two gaps beyond the third mechanical fix
  application: `EnvironmentFile=` is empirically last-wins on a duplicate
  `.env` key (confirmed live via `systemd-run --user`), closed with
  `| tail -n 1` across all 3 affected units; and each unit's own
  regression test pinned the broken line's absence but never asserted the
  `ExecStartPre` that produces the secret exists — closed with
  content+ordering pins (mutation-tested) plus a new repo-wide test
  scanning every `configs/systemd/*.service` file for the bug shape
  itself, not one string per unit. Follow-up filed:
  [#361](https://github.com/voltron-1/Suburban_SOC/issues/361)
  (activating the `agent_checkpoints_compactor` credential for the first
  time here has no detection coverage — its own SLO metrics get greener,
  not worse, if abused). M16 backlog: #270, #265 (original) plus #355,
  #358, #359, #361 (accumulated follow-ups); recommending #355 next —
  well-specified, self-contained, no design judgment call needed unlike
  #358/#359/#361.

- **#355 closed — Trivy scanning now covers the pinned `zeek/zeek` image.**
  Full detail in NEXT UP above. [PR #363](https://github.com/voltron-1/Suburban_SOC/pull/363)
  merged 2026-08-16 (squash, `6f0bb1e`). Live-verifying the new job (not
  just its YAML) against the real pinned reference surfaced a genuine,
  currently-live finding: 7 real CRITICAL CVEs on `zeek/zeek:8.1.1`. Asked
  the repo owner how the new gate should handle that before implementing —
  confirmed: ship it as a hard failure on the current pin rather than
  starting green, so the exposure can't be silently absorbed. Confirmed a
  clean fix exists (`:latest` has moved to 8.2.1, 0 CRITICAL) and filed it
  as [#364](https://github.com/voltron-1/Suburban_SOC/issues/364)
  (`priority:critical`) rather than bundling a version bump into a
  scanning-coverage PR. #364 now supersedes the rest of the M16 queue —
  it's the only critical-severity item open anywhere in the repo.

- **#364 closed — zeek/zeek bumped to 8.2.1, closing all 7 CRITICAL CVEs.**
  Full detail in NEXT UP above. [PR #366](https://github.com/voltron-1/Suburban_SOC/pull/366)
  merged 2026-08-16 (squash, `67ff28b`), 18/18 CI green including the
  previously-red `zeek-image` Trivy job. security-auditor review found
  the original bump verification's search key (grep for
  `validation_status`) was too narrow to answer "did anything version-
  dependent break" — expanded live to cover Zeek notice enums, Intel
  types, and files.log mime_type/source via real synthetic-but-genuine
  HTTP-download fixtures, diffed byte-identical against the old image.
  Also found and fixed a real, live bug the pin's own existence exposes:
  SOP-147's evidence-collection filter doesn't reliably match a
  `repo:tag@digest`-started container, switched to name-based filtering
  that never needs updating again. Follow-up filed:
  [#365](https://github.com/voltron-1/Suburban_SOC/issues/365) (unrelated
  pre-existing mime_type gap found during verification).
  Per the repo owner's direct request, next: read every remaining open
  issue and restructure the scattered M16-catch-all pile into properly-
  scoped milestones, rather than continuing ad-hoc "next unstarted item"
  picks from an unsorted backlog.

- **Backlog restructured — 37 open issues, 33 of them previously
  unmilestoned, sorted into 6 new thematic milestones (M17–M22); M15
  closed outright.** Full milestone-by-milestone breakdown in NEXT UP
  above. Read all 37 open issues' bodies (not just titles/labels) before
  grouping, to avoid mis-categorizing on a misleading title alone.
  Themes: M17 detection-rule logic correctness (8), M18 ECS pipeline/
  field-mapping integrity (11 — the largest single theme, and a direct
  continuation of what M15 itself was about), M19 platform credential/
  secret hygiene (6), M20 SOAR response-path hardening (3), M21 Zeek
  sensor operational resilience (3), M22 compliance/documentation
  accuracy (3). M16 narrowed back to its original 3 (endpoint onboarding
  + threat-intel), stripped of the 4 unrelated issues that had
  accumulated in it this session purely because it was the only open
  milestone to file follow-ups against. #283 (M15's last open item, still
  blocked on unavailable real-Windows-telemetry) moved to M17, its actual
  thematic home — this let M15 close for real (11/11 done) rather than
  staying open for one item that was never really "M15 work." No new
  code changes this pass — pure GitHub milestone/issue metadata (`gh api
  repos/.../milestones`, `gh issue edit --milestone`) plus this doc.

## LAST SESSION — 2026-08-13

- **#292 closed — DNS TXT-based C2 download direction now has field
  mapping and rule coverage.** Full detail in NEXT UP above.
  [PR #353](https://github.com/voltron-1/Suburban_SOC/pull/353) merged
  squash (`2563d22`), 17/17 CI green. security-auditor's review caught a
  real gap the fix's own first pass introduced (the new `dns.answers`
  field defaulting to a 1024-char ignore_above ceiling — a live, silent
  evasion path since, unlike the query-label field, a TXT answer has no
  protocol-level length bound); fixed with an explicit `ignore_above:8191`
  property, live-proven to fail pre-fix/pass post-fix against a real
  Elasticsearch index. A second follow-up verification round (confirming
  the fixes actually closed what the first review found) caught two
  inaccuracies introduced by the fix's OWN corrective comments — worth
  noting as a pattern: fixing a reviewer finding can introduce a fresh
  one, so a fix-then-reverify loop matters even on the second pass, not
  just the first. One finding didn't get a public GitHub issue: the
  unauthenticated `:5514` HTTP input can forge or suppress Zeek Sigma
  detections by spoofing `log.file.path` — filed as a private draft
  Security Advisory (`GHSA-qq8v-48c2-j5xx`) instead, since this repo is
  public and the gap is live/unpatched. 2 new follow-ups filed (#351,
  #352); cross-referenced against already-filed #345 rather than
  duplicating it.
  Also swept the repo for local branches with commits not yet on GitHub —
  found 9 stale branches that looked unpushed but were already
  squash-merged (different local SHAs than what landed on main, confirmed
  via `gh pr list --head <branch> --state all` against each), cleaned up;
  #292's branch was the only one with genuine unpushed work.

## LAST SESSION — 2026-08-12 (later)

- **5 more M15 issues closed (#297, #295, #290, #287, #291) — M15's P2
  tier complete, only P3 (#292, #288, #283) remains.** Full detail on each
  in NEXT UP above. Highlights: #295 turned out already resolved by
  earlier PRs, closed with evidence rather than re-implemented. #290 and
  #287's security-auditor reviews each caught a real HIGH the fix itself
  hadn't anticipated — #290's review found the fix's own byte-clamp gap
  would have reintroduced a Lucene immense-term whole-document-rejection
  bug on an attacker-controlled field, PLUS a separate apostrophe-inside-
  a-Logstash-string bug that breaks the entire pipeline config at
  startup; #287's new drift-checker had its own version of the exact
  drift bug it was built to catch (found independently by both
  security-auditor and code-reviewer), and surfaced a real, currently-
  existing config gap (`field-mapping-zeek-files` missing its 4-tuple
  since #217) that got fixed in the same PR. #291's review found 3 real
  HIGH issues, the standout being a genuine regression to the offline-
  PCAP-replay operational SOP that this fix's own change would have
  silently caused — root-caused and fixed, with a bonus fix to a second,
  independent bug the same root cause had been quietly triggering since
  #228.
  PR #346 (#290) needed a real merge-conflict resolution after #297
  merged first — mid-resolution, a `git stash` during the unresolved
  merge lost git's `MERGE_HEAD` state; caught immediately via `git
  status`, recovered by resetting and redoing the merge properly rather
  than committing a same-content-but-wrong-ancestry commit. That merge
  also surfaced a REAL, already-broken CI gate on `main` itself
  (`SIEM_KQL_Documentation.md` stale) — and the first fix attempt used
  the wrong local `sigma` toolchain (a stale `pipx` install shadowing the
  intended `.venv-detections` one on `PATH`), a live instance of the
  exact drift class issue #330 already tracks; diagnosed via concrete
  package-version comparison and commented on #330 with the specifics.
  PR #350 (#291) hit the same class of gap again on its own merge (3 of
  #290's live-fire tests needed the same `logsource` fix #291's own
  earlier work had already applied to 2 other call sites, but couldn't
  have covered since #290's tests didn't exist on that branch yet) —
  found and fixed live before pushing, not left for CI to catch. All 4
  PRs (#343, #346, #348, #350) merged squash, no GitHub-side human
  review — explicit review-bypass confirmed by the repo owner per-PR,
  each green on all required CI immediately before its own merge.
  6 follow-up issues filed across the 4 fixes (#341, #342, #344, #345 from
  #290; #347 from #287; #349 from #291): all deliberately out of scope,
  not blocking.

## LAST SESSION — 2026-08-12

- **#267 merged, M15's P1 tier complete.** [PR #335](https://github.com/voltron-1/Suburban_SOC/pull/335)
  merged (squash, `77a04c7`), auto-closing #267 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner, 13/13 CI
  green. The live SOAR trigger only ever covered 1 of the retired Watcher's
  3 original conditions (`zeek.intel` IOC hits) — T1046/T1110 network
  detections were pipeline-tagged for dashboards but never dispatched to
  automated response. Wired T1110 in (handshake-backed, safe); a
  security-auditor HIGH finding caught that wiring T1046 in too would have
  turned its already-known spoofable-SYN weakness (#331) into a real
  automated-containment amplifier against an attacker-chosen IP (no rate
  limiting anywhere in the `/alert` path) — split the fix, left T1046
  dashboard-only, deferred to #331. code-reviewer caught a Must-Fix
  (`preflight.sh` would have permanently broken the SOP-022 harness).
  tester-debugger independently re-verified via a real fake-HTTP-server
  test of the output-stage dispatch, not just a textual check. Retired the
  dead Watcher file for real (moved out of `deploy_dashboards.sh`'s install
  glob, added a `DELETE` step so already-deployed clusters converge).
  Checked the GitHub milestone directly before declaring M15 done — it
  isn't: 9 more issues are tagged to it (never previously tracked in this
  doc), all P2/P3, no P1. See NEXT UP above for the full backlog list and
  full #267 detail.

## LAST SESSION — 2026-08-11

- **#261 merged.** [PR #334](https://github.com/voltron-1/Suburban_SOC/pull/334)
  merged (squash, `d500961`), auto-closing #261 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner, 17/17 CI
  green. T1110's pipeline tag matched every failed SSH auth instead of the
  aggregated notice; root-cause investigation found the naive fix would
  have silently regressed T1110 to zero detections (the notice-emitting
  Zeek policy was never loaded by any real capture invocation), so scope
  expanded to wire it into the two real capture entry points alongside the
  existing T1046 wiring. security-auditor + code-reviewer + tester-debugger
  all ran, both live-fire checks passed against the real stack (spliced
  Logstash 9.3.2 replay; a real two-container SSH brute-force fired a
  genuine Zeek notice). One CI failure after the initial push — an
  unrelated purple-team validator caught a doc field pointing at a
  Docker-image-internal path instead of a real repo file — fixed,
  reverified green. 3 follow-ups filed (#331, #332, #333) plus a comment on
  #293. See NEXT UP above for full detail.

## LAST SESSION — 2026-08-10

- **#263 merged.** [PR #329](https://github.com/voltron-1/Suburban_SOC/pull/329)
  merged (squash, `fea5c24`), auto-closing #263 — no GitHub-side human
  review, explicit review-bypass confirmed by the repo owner (17/17 CI
  green, sub-agent review only). Investigated a CI failure reported on the
  PR first: the `detections` job's `build_kql_docs.py --check` step was
  failing, root-caused to an unpinned `sigma-cli`/`pysigma-backend-elasticsearch`
  install drifting to a newer release that renders Lucene query text
  differently — reproduced identically against `main`'s own committed
  files, confirming it predated and was unrelated to #263's diff (same
  drift class as the unpinned-`ruff` break M12 Phase 0 hit, fixed via
  PR #255). Unblocked by regenerating `SIEM_KQL_Documentation.md` via the
  project's own generator; full `detections` job replicated locally
  post-fix to confirm. Follow-up filed:
  [#330](https://github.com/voltron-1/Suburban_SOC/issues/330) (pin the
  sigma toolchain versions in CI). See NEXT UP above for full detail.

## LAST SESSION — 2026-08-09 (later)

- **#252 fixed, plus two unrelated production outages found live-verifying
  it.** #252 (`ScriptBlockText`'s `ignore_above:8191` may still be below
  real PowerShell 4104 chunk sizes) was scoped to making truncation
  measurable rather than guessing a bigger ceiling — new
  `pipeline.truncated` tag + `metric_field_truncation_count()` SLO metric.
  [PR #327](https://github.com/voltron-1/Suburban_SOC/pull/327) merged
  (squash), 17/17 CI green, explicit review-bypass confirmed by the repo
  owner after their own review. Live-verifying it required the first
  `logstash` restart since #286 merged, which surfaced (and this PR also
  fixed, since they blocked verification entirely): `LOGSTASH_ENRICH_PASSWORD`
  missing from `.env` (`logstash_enrich` never actually provisioned), a
  stray apostrophe in `docker-compose.yml` (from #257/PR #315 earlier
  this same session) silently truncating the `provision` service's whole
  bootstrap script past its third command, and a missing `cluster:[monitor]`
  on `logstash_enrich_reader`'s role. `logstash` confirmed stable
  post-fix (`RestartCount: 0`, held 5+ minutes). Follow-up filed:
  [#326](https://github.com/voltron-1/Suburban_SOC/issues/326) (the
  wildcard-multi-field question #252's own suggested fix deferred to real
  data). See NEXT UP above for full detail.

## LAST SESSION — 2026-08-09

- **`zeek-host-capture.service` crash-loop found and fixed live**, no
  issue filed (discovered while answering a capture-pipeline question,
  not part of any planned batch): the SOC's only network sensor had been
  down since #222 merged, missing `CAP_CHOWN` in #209's
  `CapabilityBoundingSet=`. Fixed across 4 review rounds (restore
  `CAP_CHOWN`; chgrp+sticky-bit ownership redesign; `CAP_SETUID`/
  `CAP_SETGID` for tcpdump's privilege drop, a second crash-loop found
  live only after the first fix was confirmed working; a CWE-59
  symlink-follow fail-closed guard from an emergency security-auditor
  review). [PR #324](https://github.com/voltron-1/Suburban_SOC/pull/324)
  merged (squash), explicit review-bypass confirmed by the repo owner.
  Along the way, also found and fixed an unrelated off-by-one repo-path
  bug in `scripts/setup/install_intel_refresh_timer.sh` — [PR
  #323](https://github.com/voltron-1/Suburban_SOC/pull/323), merged
  later this same session (see below).
  `CLAUDE.md` and 4 custom `.claude/` agent/slash-command definitions
  that existed only locally were versioned — [PR
  #325](https://github.com/voltron-1/Suburban_SOC/pull/325), merged
  (squash), same review-bypass basis. #286's remaining PR #313 test-plan
  item (`Conn::IN_RESP` live serialization) was resolved by the repo
  owner choosing to accept the existing static-analysis verification
  rather than restart the just-stabilized sensor again; #276/#278's
  SOP-005 OpenWrt UCI item was reconfirmed still untestable in this
  environment.

- **All remaining M14 PRs (#311, #313, #314, #315, #316, #317) plus #323
  updated to `main` and merged this same session**, closing out M14
  entirely: each branch was individually re-merged with `main` (not just
  GitHub's "Update branch"), verified green on every required CI check,
  then squash-merged one at a time — never batched into a single
  unattended pass. Two real merge conflicts surfaced as `main` advanced
  between merges (#314 against `.env.example`/`docker-compose.yml`,
  #316 against `test_slo_metrics.py`), both purely additive (independent
  blocks/test classes from different PRs landing at the same insertion
  point) and resolved by keeping both sides' content, re-verifying mypy
  and the directly-affected tests after each. Caught and fixed a genuine
  pre-existing mypy bug in `checkpoints.py`'s `_transition_claim()`
  surfaced only once CI's mypy check ran against the real combined
  content (dict-typing inference couldn't see through the function's own
  XOR guard) — fixed with explicit type annotations + a documenting
  `assert`, verified via `tester-debugger` against the full test suite
  (88/88 claim-transition tests unchanged) before pushing. Chased a
  false-positive local `docker compose config` failure that reproduced
  even on weeks-old, unrelated `main` history — confirmed via GitHub's
  own CI (which passed the equivalent real check on #317) that this was
  a local docker-compose-version artifact, not a defect. #276, #278,
  #286, #256 required manual issue-closing (squash merge, PR body used
  "Part of #XXX" not "Closes", same recurring gap as M12/M13's PRs).
  **M14 is now COMPLETE** — 8/8 milestone issues closed. See NEXT UP
  above for full per-PR detail.

## LAST SESSION — 2026-08-08

- **All 6 remaining M14 issues built end-to-end this session**, back to
  back per explicit instruction — each got its own branch off `main` and
  its own PR; merging remains reserved for the repo owner, requiring
  separate explicit confirmation per PR. #276/#278 (paired):
  [PR #311](https://github.com/voltron-1/Suburban_SOC/pull/311). #286:
  [PR #313](https://github.com/voltron-1/Suburban_SOC/pull/313), filed
  [#312](https://github.com/voltron-1/Suburban_SOC/issues/312) as a
  deferred policy decision. #256:
  [PR #314](https://github.com/voltron-1/Suburban_SOC/pull/314). #257:
  [PR #315](https://github.com/voltron-1/Suburban_SOC/pull/315). #259:
  [PR #316](https://github.com/voltron-1/Suburban_SOC/pull/316) — started
  as a narrow `.env`-inline-comment parser fix, but tracing the actual
  systemd production path (`slo-metrics.service`) surfaced two further,
  more severe bugs in the same credential-loading area: the unit's own
  `EnvironmentFile=` loaded the whole raw `.env` and stayed broken
  regardless of the Python-level fix, and separately `ES_PASS` was never
  actually being set at all (`Environment=` doesn't expand `${VAR}` —
  confirmed empirically via a throwaway systemd unit on this host, before
  and after the fix). Every PR went through 2-3 rounds of parallel
  `security-auditor`/`code-reviewer` review; #257 and #259 each had a
  genuine HIGH finding in an early draft (a claim-squat evasion via
  trusted `_source` fields, and a unit-breaking chicken-and-egg
  `EnvironmentFile=` deadlock respectively), both confirmed fixed via
  mutation testing before landing.

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

# #393 — Threshold-rule window-math fix + generalized live-fire coverage

## Scope
Last actionable M17 item. Two gaps named in the issue, plus a third
discovered by the new test itself:

1. Threshold-rule `from`/`interval` windowing across all 8
   `rules/elastic/threshold/*.ndjson` files used a flat "+1 minute overlap"
   convention that does not guarantee containment when a campaign's own
   duration is comparable to the lookback width.
2. `ThresholdLiveFireTests` (tests/detections/test_live_fire.py) was
   hardcoded to exercise exactly one threshold file
   (auth-win-bruteforce-failed-logons.ndjson); the other 7 files' real
   aggregation/window behavior was asserted only in prose, never by an
   automated test against a real Elasticsearch.
3. (found while building #2) `auth-win-bruteforce-source-spray.ndjson`'s
   deployed query had drifted from its paired Sigma file's `detection:`
   block — #370's IP-sentinel exclusion was added directly to the
   hand-authored ndjson query and never back-ported to the Sigma file.

## Gap 1 — windowing math

`lookback >= interval + detection_window` guarantees full containment of
any campaign phase; the old `interval + 1m` convention only gives partial
containment for a window comparable in width to the interval. Independently
re-derived and confirmed via simulation (3/30 = 10% for a 30m detection
window on a 31m lookback; guaranteed once lookback = 35m). Applied across
all 8 files:

| file | old (from / interval) | new (from / interval) |
|---|---|---|
| auth-win-bruteforce-failed-logons | now-6m / 5m | now-10m / 5m |
| auth-win-bruteforce-source-spray | now-6m / 5m | now-10m / 5m |
| auth-win-explicit-cred-account-sweep | now-6m / 5m | now-10m / 5m |
| disc-win-domain-group-discovery-repeat | now-11m / 10m | now-20m / 10m |
| disc-win-nltest-discovery-repeat | now-11m / 10m | now-20m / 10m |
| disc-win-user-discovery-repeat | now-11m / 10m | now-20m / 10m |
| net-zeek-ssh-session-cadence | now-6m / 5m | now-10m / 5m |
| net-zeek-ssh-session-cadence-sustained | already fixed in #392 | now-35m / 5m (unchanged) |

Live-verified at both the 5m/10m and 10m/20m scales against a real
Elasticsearch (containment failure under the old windowing reproduced, then
confirmed fixed).

## Gap 3 (the real bug the new test caught)

`ThresholdQueryMatchesCompiledSigmaTests` (compile-only, parses
`docs/detections/SIEM_KQL_Documentation.md`) asserts each threshold
ndjson's `query` matches its paired Sigma file's real compiled output.
`auth-win-bruteforce-source-spray.ndjson` failed this on first run — its
query carried #370's IP-sentinel exclusion, but
`rules/sigma/auth_win_bruteforce_source_spray.yml`'s `detection:` block did
not. Fixed by adding an equivalent `filter_ip_sentinel` selection to the
Sigma file and making the ndjson's `query` field the exact `sigma convert`
output going forward (derived, not hand-maintained) — this changed the
literal escaping (`\-` / `\:\:` vs the old hand-typed `"-"` / `"::"`),
which broke an existing substring-match unit test
(`tests/detections/test_threshold_rules.py::test_bruteforce_source_spray_excludes_all_four_ip_sentinels`);
fixed by stripping escaping backslashes before the substring check so the
test pins the semantic exclusion, not one particular escaping convention.
Live-verified the new query still excludes all 4 sentinel values
(`-`, `0.0.0.0`, `::`, empty) and matches a real non-sentinel IP.

## Two bugs the generalized `ThresholdLiveFireTests` itself hit

**`source.ip` `ignore_malformed` silent drop.** `source.ip` is `type: ip`
with `index.mapping.ignore_malformed: true` set template-wide. Writing a
non-IP string (e.g. `"entity.crossed"`) into it returns HTTP 201 and the
value persists in `_source`, but is silently never added to the field's
indexed/doc-values representation — a terms aggregation on it returns zero
buckets. Only affects `source.ip`; `host.name` and the unmapped
`winlog.event_data.*` fields (dynamic `strings_as_keyword`) don't have this
problem. Fixed by giving the two `net-zeek-ssh-session-cadence*` configs a
real-IP-shaped entity generator instead of the generic `entity.<label>`
string.

**Entity-value cross-contamination between the two zeek-ssh files.** Both
`net-zeek-ssh-session-cadence.ndjson` and its `-sustained` sibling compile
to the byte-identical query (`event.dataset:zeek.ssh AND client:SSH\-*`)
and aggregate the same `source.ip` field. An unnamespaced IP generator gave
both files' "notcrossed" case the same value (`10.99.0.2`), so within one
test run the 14 docs indexed for the sustained file's own below-threshold
case were also counted in the plain file's aggregation:
`test_threshold_not_crossed_below_value` failed with `18 not less than 5`
(14 + 4, not a hypothetical). Fixed by namespacing every `entity_for`
generator per rule *file*, not just per label — `_default_entity_for(ns)`
and `_ip_entity_for(octet)` factories, one distinct namespace per
`THRESHOLD_TEST_CONFIGS` entry.

## Parallel review (security-auditor + code-reviewer)

Both reviews ran independently against the full diff.

**code-reviewer** — approve with conditions. Found stale "6-minute"/"5-in-6"
prose left in `net-zeek-ssh-session-cadence.ndjson`'s description and its
paired Sigma file's description, both missed when the window was corrected
from 6 to 10 minutes. Fixed (2 occurrences in the ndjson, 1 in the Sigma
file). Also flagged stale references to the pre-fix single-file scope and
the renamed `_bucket_count` in `test_live_fire.py`'s module docstring;
fixed.

**security-auditor** — two consecutive infrastructure connection failures
on the dedicated agent; completed via a general-purpose fallback agent
briefed with the same security-auditor mandate. Independently re-derived
and confirmed correct: the window-math arithmetic in all 8 files, the
IP-sentinel query fix, sigma/ndjson pairing across all 8 rules (re-ran
`sigma convert` directly rather than trusting the docs), and the
entity-namespacing fix's coverage (checked all 28 file-pairs among the 8
threshold files for shared-query + shared-field collision risk — only the
already-fixed zeek-ssh pair actually collides). Found:
- **Finding A (Medium, addressed)**: no test — live or compile-time —
  actually proved the *new, widened* window was what's deployed, as
  opposed to merely proving some window filtering exists. A silent revert
  to the old `interval+1m` convention (or a new file shipped with it)
  would have passed every existing test in both test files. Fixed by
  adding `test_lookback_guarantees_full_containment_of_the_documented_detection_window`
  to `tests/detections/test_threshold_rules.py` — a compile-time (no ES
  needed) regression guard asserting `from == interval +
  DETECTION_WINDOW_MINUTES[file]` and `meta.from + interval == from` for
  all 8 files, against a new explicit per-file `DETECTION_WINDOW_MINUTES`
  table. Mutation-tested against two regression scenarios (reverting only
  `from`, and reverting `from` + `meta.from` together) — both fail loudly
  with a clear message, confirmed then reverted cleanly.
- **Finding B (Low, addressed)**: `net-zeek-ssh-session-cadence-sustained.ndjson`'s
  description (and its paired Sigma file) still described the sibling
  plain-cadence rule's window as "5 sessions/6 minutes" after that rule's
  own window was corrected to 10 minutes — same staleness class as
  code-reviewer's finding, just in a third file neither pass had checked
  yet. Fixed in both files.
- **Finding C (Informational, no action)**: local `sigma-cli` version
  drift (3.0.2 installed vs 3.1.0 latest) produced 2 unrelated stale doc
  lines during the agent's own diagnostic run, for rules outside this
  issue's scope; not a #393 regression, root-caused to environment
  version skew, no working-tree changes survived (agent confirmed clean
  restore). Not tracked further here — the pinned-CI-toolchain doc
  regeneration step below is the actual safeguard in place.

## Verification
- `tests/detections/test_live_fire.py` full suite: 22 passed, 34 subtests
  passed, against a real Elasticsearch (TLS + real CA cert extracted from
  the `elasticsearch` container, `elastic` user).
- `tests/detections/` full suite: 57 passed, 72 subtests passed.
- `tests/detections`, `tests/dashboards`, `tests/hunts`, `tests/pipeline`,
  `tests/rbac`, `tests/validate_emulation_map.py`: 266 passed, 80 subtests
  passed (no regressions outside detections).
- `docs/detections/SIEM_KQL_Documentation.md` and
  `docs/detections/attack-coverage.{md,json}` confirmed already in sync
  under a pinned `python:3.11.15` / CI-matching `sigma-cli` +
  `pysigma-backend-elasticsearch` toolchain (`--check` clean, 75
  techniques) — checked twice (before and after applying review findings),
  no regeneration needed either time.
- Full re-run after applying both reviews' findings: `tests/detections`,
  `tests/dashboards`, `tests/hunts`, `tests/pipeline`, `tests/rbac`,
  `tests/validate_emulation_map.py` — 267 passed, 80 subtests passed
  (58 in `tests/detections` alone, including the new regression guard).

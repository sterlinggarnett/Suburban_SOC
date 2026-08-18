# #425 — build_attack_coverage.py's Navigator-tooltip delimiter fixed

## Scope
`_merged_comment()` in `scripts/setup/build_attack_coverage.py` builds the
ATT&CK Navigator tooltip text for a (technique, tactic) group's
contributing rules, joining each rule's `title` and `rule` (filepath)
with a delimiter. That delimiter was `" — "` (em dash) — the same
character several rule titles in this corpus legitimately contain
(e.g. `net_zeek_ssh_session_cadence.yml`'s title). This made the
title/rule boundary genuinely ambiguous by inspection wherever an
em-dash-titled rule landed in a multi-rule technique group. Confirmed
already live on `main` before this fix: T1110 is a 5-rule group
containing 2 em-dash titles.

## Fix
- Changed the delimiter to `" :: "` (both `_merged_comment()` call
  sites) and enforced it via `_UNSAFE_TITLE_CHARS` so a future title
  containing `::` fails the build loudly instead of reintroducing the
  same ambiguity.
- Confirmed before choosing `::`: no title, rule filepath, or test-
  description string in the current corpus contains `::`, `->`, or a
  literal colon-space — checked directly against the real corpus, not
  assumed.
- Regenerated `docs/detections/attack-coverage.json` (only `comment`
  fields changed; `.md` is unaffected — `markdown()` never calls
  `_merged_comment()`).

## Parallel review (security-auditor + code-reviewer)

Both agents needed a resume — one dropped a truncated intermediate
message, the other stopped mid-sentence with tool output pending — both
recovered and delivered complete reports on resume.

**code-reviewer** — approve with conditions, one real finding applied:
the delimiter fix was applied to both `_merged_comment()` call sites
correctly, but the new regression test used the shared-test-value
default (`_row()`'s `test="test"`), which only exercises the
`len(tests)==1` short-circuit path — the REAL T1110 bug lives in the
`else` branch (its rules span two distinct `test` values). Fixed: the
test now uses two distinct `test=` values, forcing the `else` branch,
and uses the literal real corpus title verbatim instead of a paraphrase.
Also fixed a one-line stale-wording nit ("either character" → "any of
these characters") directly adjacent to the paragraph already being
edited.

**security-auditor** — approve, no Bash access this run (reconstructed
the diff by reading working-tree state directly); confirmed `--check`
passes and all tests pass via a separate direct run rather than trusting
the agent's own derivation. Found the fix was semantically correct but
structurally fragile — the delimiter literal and its
`_UNSAFE_TITLE_CHARS` guard were three independent, uncoupled string
literals (the same decoupling that let the original `—` bug survive
three review cycles). Two fixes explicitly recommended for this same PR,
both applied:
- **MEDIUM (applied)**: `_TITLE_RULE_DELIM`/`_GROUP_DELIM` are now named
  constants; `_UNSAFE_TITLE_CHARS` derives from them instead of
  duplicating the literal.
- **LOW (applied)**: the new regression test asserted a literal string,
  which would pass trivially for any future delimiter that merely
  doesn't collide with that one test's fixture data, without proving the
  general non-ambiguity property. Added two more tests:
  `test_output_structurally_decomposes_back_to_one_segment_per_rule`
  (splits the output and asserts exactly one title<->rule delimiter per
  segment) and `test_no_real_title_rule_or_test_contains_a_comment_delimiter`
  (checks the invariant against the real corpus via `harvest()`, same
  pattern as `RealCorpusRegressionTests` elsewhere in this file).

Also applied inline (small, same function, directly reinforces the fix):
- `_merged_comment()` now asserts no `title`/`rule`/`test` value in the
  group contains a delimiter, rather than silently trusting that
  `_validate_title()` ran upstream — closes the ordering-assumption gap
  the auditor flagged (a third future ingest path, or an unvalidated
  `rule`/`test` field, would previously have reproduced the exact bug
  this PR fixes).
- `_validate_title()`'s error message now names the offending character
  and states explicitly that the restriction is title-only (this corpus
  is unusually `::`-dense in *descriptions* — Zeek notice names like
  `SSH::Password_Guessing`, Mimikatz syntax like `sekurlsa::` — so a
  future title hitting this ban is a realistic authoring mistake, not
  hypothetical; the old message just said "rename it" with no hint why).

Three more findings filed as follow-ups (all milestoned M17, not
bundled into this PR):
- [#430](https://github.com/voltron-1/Suburban_SOC/issues/430) — the
  network-rule ingest path skips the tactic validation the Sigma path
  already has, risking a silent dead Navigator cell for a technique
  that's actually covered.
- [#431](https://github.com/voltron-1/Suburban_SOC/issues/431) — the
  markdown table has no `|` escaping on `source`/`rule`/`test` columns
  (same bug class as this fix, prospective not yet live).
- [#432](https://github.com/voltron-1/Suburban_SOC/issues/432) —
  `run_hunts.py`'s composite `_id` (`hunt_id:day_bucket`) has no
  delimiter guard on `hunt_id`; because the write is a deliberate
  upsert, a collision would silently overwrite one hunt's results with
  another's — the worst-consequence instance of this bug class found
  during the review, though not currently live (all 5 real hunt ids are
  clean).

## Verification
- `tests/setup/test_build_attack_coverage.py`: 30 passed (28 pre-existing
  + 2 new).
- `tests/detections tests/dashboards tests/hunts tests/pipeline tests/rbac
  tests/setup tests/validate_emulation_map.py`: 336 passed, 90 subtests
  passed — no regressions.
- `python scripts/setup/build_attack_coverage.py --check` confirmed
  byte-identical output after the internal refactor (constants
  extraction, added assertions) — the fix's actual runtime behavior was
  unchanged by the follow-up hardening.

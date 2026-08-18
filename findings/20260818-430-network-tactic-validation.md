# #430 — build_attack_coverage.py's network-path tactic validation fixed

## Scope
`harvest()`'s Sigma-rule ingest path already fails loudly on an
unresolvable `attack.<tactic>` tag (added by #281's own review) — the
network-rule ingest path (parsing `[threat][tactic][name]` out of
`configs/logstash.conf`) had no equivalent, so a typo'd or malformed
tactic value would silently render as a dead ATT&CK Navigator cell
(matching no real tactic column, so Navigator just drops the annotation
with no error).

## Fix
Initial fix: validate the network path's `tactic` value against
`{display_name for display_name, _ in TACTICS.values()}` before
appending a row. `--check` confirmed clean against the real corpus;
mutation-tested directly against the real `configs/logstash.conf`
(corrupted a real value in place, confirmed the guard fires, restored
from backup).

## Parallel review (security-auditor + code-reviewer)

**code-reviewer** — approve with conditions, one real finding applied:
the new comments used plain ASCII hyphens where every other line in
this file (including this file's own #425 history, about exactly this
delimiter convention) uses an em dash. Fixed. Otherwise: guard placement,
validation axis (values vs. keys), error-message quality, and test
construction all confirmed correct.

**security-auditor** — found the initial fix was correct and safe
against the real corpus, but incomplete — three MEDIUM findings, all
folded into this same change:

1. **CVR-01**: the regex pairing technique-id → technique-name →
   tactic-name used unanchored `.*?` between fields, not scoped to the
   enclosing `add_field { }` block. Because Logstash imposes no field
   ordering within an `add_field` hash, a future block (or one inserted
   ahead of an existing one) could let the match cross a block boundary
   and pair a technique with the WRONG tactic, or swallow an entire
   block silently. Both a real-but-wrong pairing (passes #430's own
   validation, since both halves resolve individually) and a silent
   drop are undetectable by the existing count-parity test in
   `test_framework_enrichment.py` (which only counts occurrences, not
   pairings). Fixed: `.*?` → `[^}]*?`, verified this still matches both
   real blocks. Mutation-tested by reverting to `.*?` and confirming a
   new synthetic test (`test_network_pairing_does_not_cross_an_add_field_block_boundary`)
   fails with the exact predicted mis-pairing (T1046 incorrectly paired
   with block 2's Credential Access instead of not matching at all),
   then restored the fix. Also added a real-corpus row-count regression
   test — the one check that would catch a silent drop against real
   data, not just a synthetic fixture.
2. **VAL-01**: only the tactic *name* was validated; the tactic *id*
   (`[threat][tactic][id]`, also present in every real block) was never
   captured or checked, and `TACTICS`' own ATT&CK-ID half was dead data
   referenced by nothing. Fixed: now validates the (name, id) as a PAIR
   against `set(TACTICS.values())`, catching a copy-paste edit that
   changes one half but not the other, not just a wholly-unresolvable
   value.
3. **VAL-02**: the network path's technique ID was taken verbatim, with
   no format check or case normalization, unlike the Sigma path (which
   regex-constrains and uppercases). A malformed or differently-cased
   id would produce a duplicate or unresolvable Navigator cell instead
   of merging with the real technique. Fixed: `re.fullmatch(r"T\d{4}(?:\.\d{3})?", tech)`
   validation plus `.upper()` normalization at append time, matching the
   Sigma path exactly.

Also applied (LOW findings):
- **MSG-01**: the error message now lists the full set of valid (tactic,
  id) pairs, so a near-miss casing/wording typo is a five-second fix
  instead of requiring the maintainer to open the script and read a
  dict.
- **CMT-01**: comments are now stripped from `configs/logstash.conf`'s
  text before matching, so a commented-out example mapping can't be
  silently harvested as live coverage (the same overstatement failure
  mode, via a different route). New regression test confirms a fully
  commented-out block yields zero rows.

Two more findings filed as follow-ups (both milestoned M17, genuine
design/hardening gaps rather than live-gap disclosures, so filed
normally):
- [#436](https://github.com/voltron-1/Suburban_SOC/issues/436) — the
  Sigma-path's own tactic-tag error message reports `found: None` for
  the exact hyphen-typo case its own test asserts (a pre-existing,
  unrelated diagnostic-quality bug found while reading this code
  closely).
- [#437](https://github.com/voltron-1/Suburban_SOC/issues/437) —
  `configs/detections/emulation_telemetry.map`'s ~25 independent
  `threat.tactic.name` declarations are validated against nothing; the
  same drift risk #430 closed for `logstash.conf` remains open there.

## Verification
- `tests/setup/test_build_attack_coverage.py`: 37 passed (32 after the
  first review round + 5 more from the security-auditor's additional
  findings: pair-mismatch, malformed-technique-id, block-boundary
  anchoring, and commented-out-block tests, plus the real-corpus
  row-count regression test).
- `tests/detections tests/dashboards tests/hunts tests/pipeline tests/rbac
  tests/setup tests/validate_emulation_map.py`: 349 passed, 92 subtests
  passed — no regressions.
- `python scripts/setup/build_attack_coverage.py --check` confirmed
  clean against the real corpus after every round of changes.
- Mutation-tested twice: the original network-tactic-validation guard
  against a corrupted copy of the real `configs/logstash.conf`, and the
  block-boundary-anchoring fix against a reverted `.*?` regex — both
  confirmed to fail with the exact predicted symptom, then restored.

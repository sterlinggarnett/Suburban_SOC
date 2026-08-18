# #428 — DNS rules' unanchored `endswith` suffix matching fixed

## Scope
`net_zeek_dns_doh_non_standard.yml`'s `query|endswith` selection used
bare suffixes with no leading dot (`'quad9.net'`, `'dns.google'`, etc.)
— an UNANCHORED match, so `evilquad9.net` (same trailing 9 characters as
`quad9.net`) fired despite not being a real Quad9 hostname. An attacker
could register or use a lookalike domain to burn analyst time on a false
"known DoH provider" hit, or lean on the resulting noise to make a real
hit less noticeable.

## Fix
Split the single selection into `selection_bare` (exact match on each
literal hostname) OR `selection_subdomain` (dot-anchored subdomain
match, e.g. `.quad9.net`), condition `selection_bare or
selection_subdomain`. Preserves every currently-covered real value
(bare hostnames, and the dns9/dns10/dns11.quad9.net subdomains #228's
own round-2 review widened this rule for) while excluding a
same-suffix-but-different-domain lookalike.

Live-verified against a real Elasticsearch before dispatching review:
indexed 5 real documents, ran the actual compiled Lucene query, confirmed
exactly the 3 expected matches (`evilquad9.net`/`www.google.com`
correctly excluded).

## Parallel review (security-auditor + code-reviewer)

**code-reviewer** — approve. Verified the two 9-entry lists are a
character-by-character consistent 1:1 pairing, the new test is
well-placed and non-duplicative, the description is factually accurate.
One "Consider": document the pairing invariant with a comment near
`selection_subdomain` — applied.

**security-auditor** — extensive review, several real findings, all
applied:

1. **MEDIUM (fixed directly, not publicly filed)**: the IDENTICAL
   unanchored-suffix bug was live in the sibling rule
   `net_zeek_dns_crypto_mining_pool.yml`, at `level: medium` — a higher
   severity tier than the DoH rule, and more likely to be actioned
   (host isolation, user contact). Per this project's standing
   no-public-disclosure convention for live gaps in defensive tooling,
   fixed in this same branch rather than filed as a public issue: same
   `selection_bare`/`selection_subdomain` split applied to all 11
   operator-domain entries, new `evilnanopool.org` true_negative fixture
   and unit test, new permanent live-fire regression test.
2. **MEDIUM (caveat added, design work filed as #434)**: the fix closes
   lookalike-*registration* (a different registered domain sharing a
   suffix), not lookalike-*emission* — both rules match on the observed
   query, not the response, so any host that can send a DNS packet can
   forge a hit under a real provider domain (`dig
   <random>.quad9.net` in a loop) with no domain ownership at all. Added
   an explicit `falsepositives` entry and description caveat to both
   rules stating this plainly. Filed
   [#434](https://github.com/voltron-1/Suburban_SOC/issues/434) (M17)
   for the actual mitigation (NXDOMAIN/session correlation or a
   threshold companion) — a genuine design decision, not a live-gap
   disclosure, so filed normally.
3. **LOW (fixed)**: the DoH rule's description overclaimed the fix's
   scope ("neither... can produce a false positive for" read as a
   general unspoofability claim). Reworded to scope the claim precisely
   to the lookalike-registration class, cross-referencing the emission
   caveat above.
4. **LOW (fixed)**: the two-list pairing invariant was enforced only by
   a YAML comment, invisible to CI. Added
   `test_bare_and_subdomain_selections_stay_paired_on_anchoring_fixed_rules`
   in `test_sigma_detections.py` — asserts `selection_subdomain == ["."
   + b for b in selection_bare]` mechanically for both fixed rules.
5. **MEDIUM (fixed)**: no permanent live-fire regression test existed
   for either rule's compiled-query anchoring behavior — this session's
   manual ES verification would otherwise have been a one-off, not
   permanent coverage. Added
   `test_zeek_dns_doh_non_standard_fires_against_real_es` and
   `test_zeek_dns_crypto_mining_pool_fires_against_real_es` to
   `NetworkLiveFireTests`, both using the existing
   `assert_rule_fires_correctly` helper — they automatically pick up the
   new lookalike true_negative fixtures, so the false-positive rejection
   is now permanently pinned against a real Elasticsearch, not just
   `sigma_eval.py`'s Python re-implementation.
6. **LOW (fixed)**: independently found a real, same-class bug in the
   shared eval engine while verifying Lucene's wildcard semantics from
   first principles — `sigma_eval.py`'s `endswith` handling used bare
   `"$"` (matches immediately before a trailing newline in Python `re`)
   instead of `r"\Z"` (true end-of-string). A value ending in a literal
   newline (Zeek's `dns.answers` TXT records can legally carry embedded
   control characters, already documented elsewhere in this module)
   would report "fires" in `sigma_eval.py` while the real compiled
   Lucene keyword-field query — which has no such leniency — does not
   match it: a CI-green/production-blind divergence, the same bug class
   #387 fixed for the `re` modifier. Fixed (`pattern + "$"` →
   `pattern + r"\Z"`), mutation-tested (reverted to the buggy pattern,
   confirmed the new regression test fails; restored the fix, confirmed
   it passes).

Also independently derived and confirmed, not just trusted from the
described live run: Lucene's `WildcardQuery` automaton treats `.` as a
literal single-character transition (only `*`/`?`/`\` are
metacharacters), so `*.quad9.net` genuinely requires a literal dot
immediately before `quad9.net` — `evilquad9.net`'s trailing 10
characters are `lquad9.net`, not `.quad9.net`. Verified the
`dns.question.name` field's `lowercase_normalizer` closes the
mixed-case-evasion angle too (already pinned by an existing live-fire
test on a sibling rule).

## Verification
- `tests/detections`: full suite passes, including 6 new/changed tests
  targeted directly (`test_zeek_dns_doh_non_standard_fires_against_real_es`,
  `test_zeek_dns_crypto_mining_pool_fires_against_real_es`,
  `test_doh_rule_excludes_lookalike_domains_after_the_anchoring_fix`,
  `test_mining_pool_rule_excludes_lookalike_domains_after_the_anchoring_fix`,
  `test_match_one_endswith_does_not_match_before_a_trailing_newline`,
  `test_bare_and_subdomain_selections_stay_paired_on_anchoring_fixed_rules`).
- `tests/detections tests/dashboards tests/hunts tests/pipeline tests/rbac
  tests/setup tests/validate_emulation_map.py`: 342 passed, 92 subtests
  passed — no regressions.
- Live-verified the fix directly against a real Elasticsearch (manual
  index + real compiled query) before dispatching review, and again
  permanently via the two new `NetworkLiveFireTests` methods.
- Mutation-tested the `sigma_eval.py` `\Z` fix: reverted to the buggy
  `$` pattern, confirmed the new regression test fails with a clear
  message; restored the fix, confirmed it passes.
- `docs/detections/SIEM_KQL_Documentation.md` /
  `attack-coverage.{md,json}` regenerated and confirmed in sync under
  the pinned `python:3.11.15` toolchain.

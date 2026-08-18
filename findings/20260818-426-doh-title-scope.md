# #426 — DoH rule title now discloses hardcoded-IP blind spot

## Scope
Sibling fix to #410, same bug class: `rules/sigma/net_zeek_dns_doh_non_standard.yml`
carries a real, load-bearing scope caveat buried in its `description:`
block — it only catches the plaintext hostname-lookup phase a client
performs before establishing an encrypted DoH channel; a host configured
with a hardcoded DoH resolver IP (skipping that lookup entirely) is
completely invisible to it. The old title ("DNS Lookup for a Known Public
DNS-over-HTTPS Provider") read as general DoH-usage detection in any
title-only rendering.

## Fix
Moved the scope caveat into the title. First draft:
`... — Hostname-Lookup Phase Only`; security-auditor review (below)
found this named *when* the rule sees traffic rather than *what it
misses*, so the final title states the exploitable gap directly:

`DNS Lookup for a Known Public DNS-over-HTTPS Provider — Blind to
Hardcoded-IP DoH Clients`

Confirmed before starting: repo-wide grep for the old exact title string
— only the rule file and 3 generated docs referenced it; no
emulation_telemetry.map/coverage_checklist.md reference by title,
filename, or id.

## Parallel review

**code-reviewer** — approve, no findings. Confirmed title accuracy
against the actual (stateless, no session/temporal correlation)
detection logic, no stale references, docs propagated identically
across all 3 artifacts, and that the new title fits the corpus's
established two-track naming convention (interpretive-framing
parentheticals for behavioral rules vs. em-dash scope-limitation
suffixes, the pattern #410 established).

**security-auditor** — approve with one real finding applied:
- **LOW (applied)**: "Hostname-Lookup Phase Only" is readable as a
  connection-stage claim ("phase") rather than a visibility-scope claim,
  and doesn't name the actual exploitable bypass (hardcoded-IP DoH
  clients). Reworded per above.
- **INFO (corrected via issue comment)**: #425 (filed during #410's own
  review) was framed as a hypothetical future collision risk. The
  auditor found it's already realized on `main` — T1110 is a 5-rule
  technique group containing 2 em-dash titles, so the tooltip collision
  is live today, independent of #426. Added a correcting comment to
  #425 with the exact evidence; no code change (that issue's own fix is
  still tracked separately, not bundled here).
- **LOW (filed as follow-up)**: the rule's `query|endswith` selectors use
  unanchored suffixes (`quad9.net`, `dns.google`, `dns.nextdns.io` with
  no leading dot), so a lookalike domain like `evilquad9.net` matches.
  Filed as [#428](https://github.com/voltron-1/Suburban_SOC/issues/428),
  milestoned M17 — pre-existing, explicitly out of scope for this title
  fix, not bundled here.
- Re-confirmed (spot-check against #410's own exhaustive pass, not
  re-derived from scratch) that nothing in the repo keys on this rule's
  title text, the em dash round-trips safely, and the ATT&CK-coverage
  SLO count is title-independent.

## Verification
- `tests/detections`: 58 passed, 72 subtests passed.
- `tests/detections tests/dashboards tests/hunts tests/pipeline tests/rbac
  tests/validate_emulation_map.py`: 267 passed, 80 subtests passed — no
  regressions, before and after applying the title refinement.
- Docs regenerated under the pinned `python:3.11.15` toolchain, confirmed
  identical new title string across `SIEM_KQL_Documentation.md` and
  `attack-coverage.{md,json}`.

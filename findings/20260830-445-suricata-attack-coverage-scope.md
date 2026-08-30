# #445 decision: ATT&CK coverage accounting scoped out for Suricata (for now)

**Date:** 2026-08-30
**Issue:** [#445](https://github.com/voltron-1/Suburban_SOC/issues/445) — Detection-as-code CI lane for Suricata rules

## The choice #445 itself offered

> Extend ATT&CK coverage accounting to include Suricata SIDs, **or**
> explicitly scope it out and say so.

## Decision: scope out, for M23 Stage 2

`scripts/setup/build_attack_coverage.py` (WS1.5) harvests coverage from
`rules/sigma/*.yml` and `configs/logstash.conf` only. This stage does not
extend it to `rules/suricata/*.rules`.

## Why

- `rules/suricata/` carries exactly one file today (`local.rules`), and it
  is empty — Stage 1/2 shipped sensor deployment, ingest, and the CI lane
  itself, no rule content. There is nothing to harvest yet; extending the
  harvester now would be untested against real input.
- The 100-rule university starter set (#446, M23 Stage 3) is the first
  real Suricata content this repo will carry, and it is the natural point
  to design the harvester against: real per-category ATT&CK tags to
  parse, a real question of whether/how a `classtype`- or comment-based
  tag convention maps cleanly onto the existing Navigator-layer shape
  `build_attack_coverage.py` already emits for Sigma (#281's own
  Navigator-layer dedup lesson — a rushed convention here risks the same
  class of drift bug).
- Every Suricata SID is disabled until tuned (#446's own explicit
  decision) — even once landed, an accurate coverage number needs to
  distinguish "covered in principle, still disabled" from "covered and
  enabled," a nuance the current Sigma-only harvester has no equivalent
  for (Sigma rules ship enabled once promoted past `experimental`).

## What this means today

`docs/detections/attack-coverage.md`'s technique/rule counts continue to
reflect Sigma + Zeek-Logstash coverage only. This under-reports true
detection breadth once Suricata rules land and fire, but does not
over-report it — the safer direction for a coverage number decision-makers
read at face value.

## Revisit when

#446 lands real (even if disabled) Suricata rule content. At that point,
decide the actual harvesting convention (most likely: an ATT&CK tag
embedded in each rule's `metadata:` keyword, mirroring how ET rules
already carry `attack_target`/similar metadata) and extend
`build_attack_coverage.py` for real, against real rules — not speculative
code with nothing to verify it against.

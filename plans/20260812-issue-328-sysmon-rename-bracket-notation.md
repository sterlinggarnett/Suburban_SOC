# Plan — Issue #328: Sysmon rename block creates flat fields, not nested

## Issue as filed
`configs/logstash.conf`'s Sysmon `mutate.rename` block (inside
`if [winlog][channel] == "Microsoft-Windows-Sysmon/Operational"`) targets
bare dotted strings as rename destinations (e.g.
`"[winlog][event_data][CommandLine]" => "process.args"`). In Logstash, a
dotted-string rename target (no brackets) creates a FLAT field literally
named `"process.args"` (dot as a literal character in the key), not the
nested `[process][args]` structure. This file already documents this exact
footgun at its network-rename block ("targets MUST use Logstash bracket
notation... a dotted string target creates a flat field") — it was just
never applied to the Sysmon block. 9 fields affected. Live-verified during
#263's own review: `event.get("[process][args]")` returned nil for real
Sysmon-sourced events, silently dead-coding the #252/#263 truncation
filter's tagging for `process.args`/`process.parent.args` — worked around
at the time with a flat-key fallback lookup, root cause deferred as this
issue.

## Investigation
Confirmed the exact block matches the issue description. Grepped the whole
repo (Logstash config, Python, YAML) for any other consumer of the 7
OTHER renamed fields (executable, pe.original_file_name, parent.name,
target.name, file.path, file.hash.sha256) in nested-bracket form, and for
any other producer/consumer of the flat dotted-key shape anywhere —
found none beyond the rename block itself and the truncation filter's
existing fallback. Confirmed via the issue's own reasoning (and would have
independently concluded the same): Elasticsearch's own dot-expansion at
document-parsing time means a flat `{"process.args": "..."}` JSON key and
a nested `{"process": {"args": "..."}}` JSON key both land on the identical
mapped ES field — this bug was purely Logstash-internal filter-to-filter
communication, never a detection-rule bypass or indexing correctness issue
on its own.

## Scope
1. Convert all 9 Sysmon rename targets to bracket notation, matching the
   convention this file already documents and correctly uses at its
   network-rename block.
2. Remove the truncation filter's flat-key fallback lookup (`#252`/`#263`
   ruby block) — confirmed dead code once the root cause is fixed, not a
   compatibility shim worth keeping. Simplified `actual_path` back to
   `bracket_path` throughout.
3. Update `tests/pipeline/test_field_truncation.py`: removed 3
   fallback-specific tests and the `_get_with_fallback` helper; added one
   replacement test confirming a flat key is now correctly NOT picked up
   (guards against a future regression reintroducing both the bug and the
   fallback).
4. Add a new, repo-wide regression test in
   `tests/pipeline/test_framework_enrichment.py`
   (`test_no_rename_block_uses_a_dotted_string_target`) scanning EVERY
   `rename => { ... }` block in the file, not just the two already found —
   this exact bug shape has now occurred twice in this file (network block
   already correctly documented, Sysmon block was broken), suggesting real
   risk of a third occurrence. Verified the check regex directly against
   both the pre-fix (`git show HEAD:configs/logstash.conf`, finds the
   correct 9 bad targets) and post-fix (finds 0) file content before
   trusting it as a real guard, not a vacuous pass.

## Live verification (self-performed splice-pipeline replay)
Spliced the exact Sysmon rename block + the truncation filter block
(byte-identical excerpts via `sed`, not retyped) into a minimal pipeline,
ran it through the real `docker.elastic.co/logstash/logstash:9.3.2` image
with synthetic Sysmon-shaped JSON events (one populating all 9 fields
short, two with a 40000-char long field each testing truncation tagging,
one short-only). Switched from rubydebug to JSON-lines stdout output after
rubydebug's multi-line pretty-printed format proved too fragile to parse
reliably for verification (a lesson worth keeping for future splice
tests). Confirmed via clean structured JSON parsing: all 9 fields land
correctly nested, zero flat dotted keys produced anywhere, and the
truncation filter correctly tags long values via direct bracket lookup
with no fallback needed.

## Review round
`security-auditor` + `code-reviewer` in parallel, `tester-debugger` for
independent verification — same pattern as #261/#267, appropriately
scoped down given this is a smaller, more contained correctness fix (no
new trigger conditions, no security-sensitive behavior change).

- **code-reviewer**: Approve, no Must-Fix. One Should-Fix: no test
  cross-references `configs/logstash.conf`'s actual rename targets against
  `configs/detections/suburban-soc-ecs.yml`'s mapping claims for all 9
  fields (only 2 are checked, and only against ecs.yml alone) — this exact
  bug class (a mapping claim the pipeline doesn't honor) has already
  recurred twice (#233/#234, then #328). Filed as
  [#336](https://github.com/voltron-1/Suburban_SOC/issues/336) alongside a
  related security-auditor finding rather than fixed inline (needs a
  deliberate allowlist design decision, not a small addition).
- **tester-debugger**: full PASS on all 5 checks — splice fidelity
  confirmed (independently rebuilt and diffed byte-identical), all 9
  fields nested correctly on independent re-run, a missing source field
  handled cleanly (no crash, no stray key), the truncation filter's 4-field
  scope confirmed intentional (not a gap — `file.hash.sha256` etc. are
  correctly out of scope per #252/#263's original stated fields), full
  test suite passes. No bugs found in the fix. Self-caught and reported a
  bug in its own first-pass verification tooling (a crude grep-loop
  misread concurrent-worker output ordering as corruption) rather than
  either hiding it or mistaking it for a pipeline bug.
- **security-auditor**: 0 CRITICAL/HIGH. 1 MEDIUM — the new
  `test_no_rename_block_uses_a_dotted_string_target` regex missed a
  second bad shape, a dot INSIDE one bracket pair (`"[process.args]"`),
  which is the identical bug (Logstash treats everything inside one `[ ]`
  pair as one literal field name) and an idiom this file already uses
  deliberately elsewhere as a rename SOURCE — fixed immediately (verified
  no false positives against current content before tightening). 5 LOW,
  none blocking, all filed as follow-ups:
  [#336](https://github.com/voltron-1/Suburban_SOC/issues/336) (widen the
  hygiene check to copy/replace/update blocks, needs an allowlist for 2
  confirmed-intentional dotted targets),
  [#337](https://github.com/voltron-1/Suburban_SOC/issues/337) (the
  truncation filter's single hardcoded ceiling cannot model the 6
  newly-nested fields' actual 1024/8191 ignore_above ceilings;
  `user.name`/`related.user` have no ignore_above at all — the one
  genuine immense-term exposure among the nine),
  [#338](https://github.com/voltron-1/Suburban_SOC/issues/338) (ABAC
  enrichment now runs on every Sysmon event, which #328 makes possible for
  the first time, but Sysmon's `DOMAIN\user` format never matches the
  bare-username-keyed lookup CSV — an unstated blast-radius consequence of
  #328's own fix, needing a deliberate normalize-or-populate decision),
  [#339](https://github.com/voltron-1/Suburban_SOC/issues/339)
  (`file.hash.sha256` stores Sysmon's algorithm-prefixed `Hashes` string
  verbatim, e.g. `"SHA256=..."`, not a parsed bare hash — latent, no rule
  consumes it yet, same shape as #217/#233). Confirmed the security-relevant
  premise directly: ES dot-expansion did make the indexed document correct
  either way (no detection-rule bypass), and removing the fallback lookup
  carries no rollback/reload risk (rename and filter live in the same
  config file, reloaded atomically together).

## Explicitly out of scope
- Fixing any of the 4 follow-ups filed above inline — each needs its own
  design decision or is a genuinely separate concern from #328's specific
  bug (rename-target notation), not a small addition to this fix.
- Bringing up a live ES/Kibana/agent stack — the change is entirely
  contained in Logstash filter logic; splice-replay is sufficient and
  matches the same reasoning #261/#267 used to avoid it.

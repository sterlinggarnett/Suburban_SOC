# #252 — ScriptBlockText's ignore_above:8191 may still be below real PowerShell 4104 chunk sizes

[Issue #252](https://github.com/voltron-1/Suburban_SOC/issues/252). Filed
2026-08-02 during #249/#250's review, tagged to M13 but deliberately deferred
(separate scope from M13's rule-count goal). No milestone assignment beyond
that tag — standalone fix.

## Problem

#249/#250 raised `ignore_above` on command-line/script-block-shaped fields
from 1024 to 8191 (`configs/elasticsearch/logstash-security-template.json`,
explicit properties + the `long_command_fields` dynamic_template). PowerShell
4104 `ScriptBlockText` chunks are commonly cited around ~20,000 characters —
above 8191 — so an obfuscated/encoded payload can silently drop out of the
index (stays in `_source`/Discover, invisible to any query) while remaining
exactly the payload `rules/sigma/posh_ps_obfuscated_scriptblock.yml` exists to
catch. Today this is a purely theoretical failure mode: no measurement exists
to say whether it happens at all in this environment.

## Scope decision

The issue's own suggested fix is two parts, part 2 explicitly conditional on
part 1's data ("if real data shows the ceiling is hit regularly, consider a
multi-field..."). This repo's own culture (every prior entry in
`planned_execution.md`) is evidence-first — no field-type change without a
measured reason. **This plan implements part 1 only**: make truncation
measurable. Part 2 (wildcard-typed unbounded parent multi-field for
`ScriptBlockText`) stays explicitly out of scope until real chunk-size data
justifies it — filed as a new deferred follow-up at close, mirroring #265/
#270's pattern.

This also resolves the acceptance criteria's first disjunct honestly rather
than guessing: "8191 confirmed sufficient" cannot be asserted today (no real
Windows telemetry flows through this pipeline per #253's live-verification
notes — sampling found NTP-only data). The correct honest close is
"truncation is now measurable; sufficiency is unproven and tracked as a
follow-up," not a fabricated confirmation.

## Implementation

1. **`configs/logstash.conf`** — new ruby filter block alongside the existing
   `[pipeline][error]` parse-failure tagging (~line 659), same pattern: checks
   `[process][args]`, `[process][parent][args]`, and
   `[winlog][event_data][ScriptBlockText]` (the three fields carrying
   attacker-controlled long content under the raised 8191 ceiling) for
   `.length > 8191`; on a hit, sets `[pipeline][truncated] => "true"` and
   `[pipeline][truncated_fields]` (array of which field(s) tripped it) and
   tags `pipeline_truncated`.
2. **`configs/elasticsearch/logstash-security-template.json`** — confirm
   `pipeline.truncated`/`pipeline.truncated_fields` land correctly under the
   existing `strings_as_keyword` dynamic_template (short values, no need for
   the 8191 ceiling); add explicit properties only if that dynamic match
   doesn't behave as expected under live verification.
3. **`scripts/setup/ai_agent/slo_metrics.py`** — new
   `metric_field_truncation_count()`, modeled on `metric_raw_alert_volume`
   (#216): windowed count of `pipeline.truncated: "true"`, added to
   `NO_TARGET` (pure visibility, no threshold — matches the issue's own
   "measure before committing to a number" framing). Wired into `main()`'s
   `metric_fns`.
4. **Tests**:
   - `tests/pipeline/` — new filter test (pattern from
     `test_grok_parse_failures.py`) proving a >8191-char `ScriptBlockText`
     gets tagged and a normal-length one does not.
   - `tests/ai_agent/test_slo_metrics.py` — unit test for the new metric
     function (mocked ES response), following the existing
     `MetricFunctionTests` pattern.
5. **Live verification** (stack is up right now — `elasticsearch`,
   `logstash`, `kibana` all running): recreate `logstash` with the new
   pipeline config, submit a synthetic >8191-char `ScriptBlockText` event
   and a normal one, confirm the tag/fields appear on the former only and
   the field is genuinely absent from a `term` query on the truncated one
   (proving the silent-drop is real, not just configured-around). Also
   check whether any real `winlog.event_data.ScriptBlockText` docs already
   exist in `logstash-security-*` and their length distribution — if real
   data already exists this changes the "no data available" framing above
   and may be worth surfacing even though it does not change this plan's
   scope.
6. **Docs**: note the new field/metric in
   `docs/detections/SIEM_KQL_Documentation.md` where `ScriptBlockText` is
   already documented.
7. **Close-out**: file the deferred follow-up issue (wildcard multi-field
   decision, gated on real chunk-size data from this metric), PR body uses
   `Closes #252`.

## Out of scope

- The wildcard-typed unbounded multi-field itself (part 2 of the issue) —
  follow-up issue, gated on data this fix produces.
- Alerting/threshold on the new metric — `NO_TARGET`, same as
  `raw_alert_volume`; a threshold without data would be a guess.

## Phases (gated — stop after each for review, per repo convention)

- Phase 1: Logstash filter + template check (item 1-2)
- Phase 2: SLO metric + tests (item 3-4)
- Phase 3: Live verification against the running stack (item 5)
- Phase 4: Docs + follow-up issue + commit/PR (item 6-7)

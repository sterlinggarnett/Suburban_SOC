# #263 — `ignore_above:8191` payload-length bypass on both PowerShell rules

[Issue #263](https://github.com/voltron-1/Suburban_SOC/issues/263). Filed
during #217's review (M12 era), triaged into
[M15 — Detection Correctness & Pipeline Fidelity](https://github.com/voltron-1/Suburban_SOC/milestone/19)
2026-08-05. First M15 issue worked, 2026-08-09.

## Problem

`process.args`, `process.parent.args`, `winlog.event_data.ScriptBlockText`
are mapped `keyword` + `ignore_above: 8191`. A value longer than that ceiling
is silently absent from the index (stays in `_source`) — any wildcard query
against it, including both `proc_creation_win_powershell_encoded.yml` and
`posh_ps_obfuscated_scriptblock.yml`, matches nothing. A ~3,000-char encoded
loader (a typical size, not an edge case) already exceeds it once
base64/UTF-16LE encoded; PowerShell 4104 script-block chunks commonly run
~20,000 chars.

`#252` (merged via PR #327, 2026-08-09) made this *measurable*
(`pipeline.truncated` tag + `metric_field_truncation_count()`), deliberately
scoped to NOT change the ceiling — "not guessing a bigger ceiling with no
data." `#326` tracks the follow-up decision on a `wildcard`-typed unbounded
multi-field, explicitly gated on real telemetry data that does not exist yet.

## Scope decision

#263's own suggested fix has two options. Option 2 (wildcard multi-field) is
what #326 is gated on — out of scope here, untouched. **This plan implements
option 1**: raise `ignore_above` to 32766, the Lucene keyword term byte
ceiling (the standard "no practical limit" value — a value job right at the
Lucene max avoids both the current silent-drop bug and an indexing exception
from unbounded input). This doesn't need new telemetry to justify, unlike
the wildcard-field decision: Windows' own `CreateProcess` command-line limit
is ~32,767 chars and 4104 chunks (~20,000 chars) both fit comfortably under
32766, so this closes the described bypass window using facts already cited
in the issue, not a guess.

Scoped to exactly the three fields `configs/logstash.conf`'s own truncation
filter already tracks (same boundary the codebase has already drawn):
`process.args`, `process.parent.args`, `winlog.event_data.ScriptBlockText`,
plus the `long_command_fields` dynamic_template that backs any future field
matching the same path pattern (keeping the explicit properties and the
dynamic template consistent, as the `_meta` doc already frames them as one
group). `process.executable`, `process.parent.name`,
`winlog.event_data.ImagePath` are deliberately left at 8191 — not queried by
either PowerShell rule, not tracked by the truncation filter, not part of
the "attacker-controlled long content" class #249/#250/#252 established.

## Implementation

1. **`configs/elasticsearch/logstash-security-template.json`** — `8191` →
   `32766` on the `long_command_fields` dynamic_template, `process.args`,
   `process.parent.args`, `winlog.event_data.ScriptBlockText`. Update `_meta`
   description (currently states "raised ignore_above:8191" — now stale).
2. **`configs/logstash.conf`** — `ceiling = 8191` → `32766` in the #252 ruby
   filter (~line 683), so `pipeline.truncated` stops firing for values that
   are now correctly indexed (8192–32766 chars would otherwise be flagged as
   truncated when they no longer are — a new drift bug if left unsynced).
   Update the surrounding comment.
3. **`tests/pipeline/test_field_truncation.py`** — `CEILING` 8191 → 32766;
   rebase every boundary fixture (`test_exactly_at_ceiling_not_tagged`,
   `test_one_over_ceiling_tagged`, `test_multiple_long_fields_all_listed`,
   `test_long_scriptblocktext_tagged`) onto the new boundary so they still
   test the actual edge, not a value that's now comfortably under ceiling.
4. **`scripts/setup/ai_agent/slo_metrics.py`** — update the `8191` mentions
   in `metric_field_truncation_count()`'s docstring and the line-26 comment;
   no logic change (the function just counts the tag, doesn't hardcode the
   ceiling itself).
5. **Live verification** (stack is up right now — `elasticsearch`,
   `logstash`, `kibana`): apply the updated template via
   `apply-templates.sh`, roll over each `logstash-security-*` data stream
   (matches #253's pattern — data streams only pick up template changes on
   the next backing index), confirm the new write index's mapping via `GET
   .../_mapping/field/process.args`. Per #263's own suggested validation:
   index a synthetic oversized (>8191, <32766 char) `ScriptBlockText`
   containing a real obfuscation indicator (`FromBase64String`) and confirm
   the exact wildcard pattern `posh_ps_obfuscated_scriptblock.yml` selects on
   now matches it — mirrors #252's live-verification method but proves the
   opposite direction (previously-bypassed payload now caught, not just
   "still tagged as truncated").
6. **`README.md`** — check whether the `ignore_above: 8191` mentions in the
   #249/#250/#252 history section need a note that #263 raised it further;
   don't rewrite the historical narrative of what those PRs did at the time.
7. **Close-out**: PR body uses `Closes #263`.

## Out of scope

- The `wildcard`-typed multi-field (#263's option 2) — stays with #326,
  gated on real chunk-size data from `metric_field_truncation_count()`.
- `process.executable` / `process.parent.name` /
  `winlog.event_data.ImagePath` — not implicated in the described bypass.
- Reindexing pre-existing backing indices' historical documents — rollover
  only affects new writes, matching the documented, already-accepted
  `apply-templates.sh` pattern (history ages out under ILM).

## Phases (gated — stop after each for review, per repo convention)

- Phase 1: Template + logstash.conf ceiling change (items 1-2)
- Phase 2: Test fixture rebasing + slo_metrics doc update (items 3-4)
- Phase 3: Live verification against the running stack (item 5)
- Phase 4: README + parallel security-auditor/code-reviewer + commit/PR
  (items 6-7)

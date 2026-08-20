# Plan: Restructure IR_Sigma_Playbook.md to the Playbook-Structure template

**Date:** 2026-08-19
**Status:** awaiting approval — no edits made yet

## Context

Request: apply the structure defined in `~/projects/SIEM/Matrix/Playbook-Structure.md`
to the repo's IR playbook. The path the user gave (`IR_Response_Playbook.md`) does not
exist anywhere; confirmed via AskUserQuestion that the target is
`docs/playbooks/IR_Sigma_Playbook.md`, working from the **current working-tree version**
(6,029 lines — it carries an uncommitted +5,990-line expansion adding a 108-row
detection/response matrix and per-rule response procedures), with extras **folded under
the closest template section** and zero content loss.

The template skeleton (identical to the repo's own `docs/Playbook-Structure.md` and
`governance/playbook_template.md`):

```
# Executive Summary
  ## Name / ## Problem Statement / ## Objectives / ## Compliance
  ## MITRE ATT&CK Framework / ## Assumptions and Limitations
# Analysis
  ## Monitoring and Notifications / ## Playbook Verification
  ## Recommended Response Action(s)
    ### Identification / ### Containment / ### Eradication & Recovery
# References and Resources
```

## Current deviations from the template (5)

| # | Section (working tree) | Location | Size |
|---|---|---|---|
| 1 | `## How to Use This Playbook` | extra H2 inside Executive Summary (lines 15–20) | 6 lines |
| 2 | `# Master Detection & Response Matrix` | extra H1 between Exec Summary and Analysis (35–155) | 108-row table |
| 3 | `## Standard 4-Phase IR Workflow` | extra H2 in Analysis (167–199) | 33 lines |
| 4 | `## Per-Family Response Baselines` | extra H2 in Analysis (200–213) | 8-row table |
| 5 | `# Rule Response Procedures` | extra H1 (226–6,021) | 8 family H2s → 108 rule H3s → 540 part H4s |

Everything else already matches the template exactly (the 68-line HEAD version was
written from this same skeleton).

## Target structure (fold mapping)

```
# Executive Summary
  intro ¶ + "How to use this playbook" folded in as a bold-labeled body list (H2 removed)
## Name … ## Assumptions and Limitations          (unchanged)
# Analysis
## Monitoring and Notifications                    (unchanged)
## Playbook Verification                           (unchanged)
## Recommended Response Action(s)
### Identification                                 (template position)
### Containment                                    (template position)
### Eradication & Recovery                         (template position)
### Standard 4-Phase IR Workflow                   (H2→H3, moved here)
### Per-Family Response Baselines                  (H2→H3, moved here)
### Master Detection & Response Matrix             (H1→H3, moved here)
### Rule Response Procedures                       (H1→H3, moved here)
#### <8 log-source families>                       (H2→H4)
##### <108 rules>                                  (H3→H5)
###### <540 five-part subsections>                 (H4→H6, pure +2 shift)
# References and Resources                         (unchanged)
```

Rationale:
- The template's three canonical H3s stay first, in template order; extras nest after
  them under `## Recommended Response Action(s)` — the closest template home for all
  four relocated blocks (the matrix's columns are response policy and it indexes the
  per-rule procedures that now live beside it).
- The entire Rule Response Procedures subtree is a uniform **+2 heading shift** —
  mechanically verifiable, fully reversible. H6 is markdown's floor and it just fits.
- All internal navigation uses **explicit `<a id>` anchors** (verified: matrix row
  links, How-to-Use links, 108 rule anchors) — heading-level changes break nothing.
- External references are file-level only (`docs/compliance_matrix.md`) — unaffected.

## Prose touch-ups required (layout-describing text)

1. Exec Summary "How to use" steps 2–4 — section names/positions still correct after
   the move; re-verify "below" directionality.
2. Matrix intro (line 38) — "…in the same order as the Rule Response Procedures
   sections **below**" stays true (procedures still follow the matrix).
3. `### Identification`/`### Containment` bodies reference "the standard workflow",
   which now sits *after* them — convert to anchor links
   (`[Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow)`).
4. `## Recommended Response Action(s)` intro (line 215) — "the per-rule sections"
   now live inside this section; reword "below" if needed.
5. Analysis intro (line 157) — "per-rule sections below" still true; verify.

No other content changes. Field names, thresholds, tier definitions, rule text: verbatim.

## Execution phases (gated per Multi-Phase Execution rules)

**Phase 0 — safety snapshot.** The working-tree version is uncommitted and
irreplaceable. Before touching it: `git stash create` is not enough on its own — copy
the file to the scratchpad AND (recommended) commit the existing expansion first as its
own commit (`docs(ir): expand IR Sigma playbook with per-rule response procedures`) so
the restructure diff is reviewable in isolation. → **User decision at gate: one commit
or two.**

**Phase 1 — restructure.** Scripted section-block moves + heading shifts (a small
Python script over heading lines is safer than hand-editing 6k lines), then the 5 prose
touch-ups. Working tree only, no commit.

**Phase 2 — verify** (before showing done):
- Outline: `grep -c '^#'` and ordered outline diff — expect exactly 15 template
  headings in template order/levels + 4 relocated H3s + 8 H4 + 108 H5 + 540 H6
  = **675 headings total** (today: 675 — pure relocation, zero heading loss).
- Anchors: script-check every `](#x)` has a matching `<a id="x">` (expect 0 orphans).
- Content: normalize (strip leading `#` runs), sort, diff vs. pre-edit snapshot —
  only the 5 deliberate prose edits may differ; `wc -l` delta ≈ 0.

**Phase 3 — review.** Parallel `code-reviewer` + `security-auditor` subagents on the
diff (per project config), findings to `./findings/`.

**Phase 4 — commit** (only on explicit go-ahead, with the Phase 0 commit-strategy
decision applied). No CI markdown lint exists; `detections`/`lint` workflows are
unaffected by a docs-only change.

## Open decisions for the user

1. **Commit strategy** — recommend two commits (expansion first, restructure second).
2. **Five-part subsections at H6 vs bold labels** — recommend H6 (pure demotion,
   reversible); switch to bold run-in labels later if H6 renders too small.

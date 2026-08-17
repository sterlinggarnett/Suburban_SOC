# #361 — detect a CLAIMED checkpoint doc that vanishes instead of transitioning

## Problem
`agent_checkpoints_compactor` (live since #357) holds `read`+`delete` on
`agent-checkpoints-*` with no document-level restriction. checkpoints.py's own
CLAIMED/RESOLVED/RELEASED protection is enforced only in Python
(`_transition_claim`, an ES `_update` — the doc's `_id` never changes, its
`phase` field does). Nothing stops that credential from
`_delete_by_query {"term":{"phase":"CLAIMED"}}`ing a live claim doc outright,
after which `claim_approval()`'s `op_type=create` grants a fresh claim
unconditionally — reopening the at-most-once execution gate.
`metric_stuck_approval_claims()`/`metric_orphaned_claims()` both count
CLAIMED docs *up*; deleting one drives both *down* — the dashboard reads
healthier exactly when something is wrong.

## Fix
A new SLO metric, `vanished_claims` (target 0, lower-is-better), in
`scripts/setup/ai_agent/slo_metrics.py`:

- Every run persists a size-capped (200, same precedent as
  `metric_orphaned_claims`) snapshot of every currently-CLAIMED claim doc's
  hit metadata (`_index`/`_id` — never `_source`, same trust boundary
  `metric_orphaned_claims` already established) onto its own `soc-slo-metrics`
  document, under a new top-level `claimed_snapshot` field (outside the `slo`
  bucket so it doesn't get pulled into the generic value/target/breach
  dashboard-rendering loop).
- Each run first reads the PRIOR doc that has a `claimed_snapshot` (search
  `exists`, sort `@timestamp` desc, size 1) and `_mget`s those same
  `_index`/`_id` pairs. checkpoints.py never deletes a `.claim` doc through
  its own API — a doc that was CLAIMED last sample and now returns
  `found: false` can only mean it was deleted directly against
  Elasticsearch. That count is the metric.
- First run (no prior snapshot yet) returns 0, not an error — matches the
  "genuinely no baseline yet" precedent the rest of this file already uses
  (e.g. `metric_mttd`'s empty-window `None`).

## Known residual limitation (documenting, not fixing here)
If an attacker deletes a CLAIMED doc and a legitimate NEW claim for the
*same* `alert_id` lands before the next SLO run (`op_type=create` succeeds
again once the old doc is gone), the `_mget` will find a doc again — this
specific vanish-then-recreate race won't register. Narrowing the SLO cadence
below the claim lifecycle would help but isn't a change this issue asks for;
flagging it in the metric's own docstring rather than silently claiming full
coverage.

## Also (per the issue's own "Suggested fix" bullet 2, not its "Related,
smaller findings")
One-line comment addition to `configs/systemd/checkpoints-compact.service`'s
existing `agent_checkpoints_compactor` rationale block: this credential's own
compromise is explicitly out of the `agent_checkpoints`/
`agent_checkpoints_compactor` split's threat model — point at the new metric
as the compensating detection, so the existing comment doesn't read as a
stronger guarantee than it is.

## Explicitly out of scope (file follow-ups, don't bundle)
The issue's "Related, smaller findings" section — `OnFailure=`/journald unit
shipping, per-document delete audit logging (`_delete_by_query` only logs
aggregate counts), and the `checkpoints-compact.service` vs `slo-metrics.service`
dash-prefix `docker cp` inconsistency. None are the credential-detection gap
this issue's title/summary names.

## Verification
- `tests/ai_agent/test_slo_metrics.py`: new tests mirroring
  `metric_orphaned_claims`'s existing test shape (mock `es`, assert
  MetricUnavailable on failure, assert first-run/no-baseline is 0-not-error,
  assert a genuinely-vanished doc counts, assert a resolved-in-place doc does
  NOT count).
- security-auditor + code-reviewer in parallel (project standard).
- tester-debugger: live-verify against a real stack — write a real CLAIMED
  doc, resolve one normally (must NOT count), delete another directly via ES
  (must count), confirm `claimed_snapshot` round-trips through a real
  `soc-slo-metrics` doc.

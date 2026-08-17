# #358 — threat-intel detection gaps + delete_by_query timeout-doesn't-cancel

## Root-cause finding (changes the shape of part 1)

`rules/elastic_watcher/intel_feed_stale.json` — the existing stale-feed
alert, and the mechanism the issue's own "Suggested fix" assumes is live —
has never actually fired on this deployment. Live-confirmed against the
running cluster: `xpack.license.self_generated.type=basic` (`.env`), and
EVERY Watcher API call, including a brand-new trivial watch, is rejected
with `"current license is non-compliant for [watcher]"` (HTTP 403).
`deploy_dashboards.sh`'s watcher-install step has silently absorbed this
failure since WS1.3 via its own best-effort `WARN` logging. Confirmed with
the repo owner: migrate both detections into `slo_metrics.py`'s SLO-metric
framework (real, proven ntfy alerting + indexed history — used minutes ago
for #361) instead of adding a second Watcher that would be equally dead.

## Part 1 — no detection if threat-intel-indicators empties unexpectedly

Two new SLO metrics in `scripts/setup/ai_agent/slo_metrics.py`:

1. `intel_feed_stale_heartbeats` — replaces `intel_feed_stale.json`'s exact
   condition (count of `status:ok` docs in `threat-intel-meta` within
   `now-8h`; target `>= 1`). Same window/logic, now actually live.
2. `intel_indicator_count_drop_pct` — the NEW check #358 asks for: latest
   `threat-intel-meta` heartbeat's `indicator_count` vs `threat-intel-
   indicators`' real `_count`. `indicator_count` reflects one run's merged
   feed total, not the cumulative historical set the index actually holds
   (old indicators age out over `compact_threat_intel.py`'s 30-day
   retention, not per-run) — so under healthy operation actual >= reported
   most of the time; a MEANINGFUL shortfall is the anomaly. Target: reuse
   `compact_threat_intel.py`'s own `BLAST_RADIUS_FRACTION=0.5` precedent —
   breach if actual < 50% of latest reported `indicator_count`. No prior
   heartbeat at all → None/not-applicable (metric 1 already flags that
   condition on its own terms).

Retire `intel_feed_stale.json` the way #267 retired
`soar_quarantine_alert.json`: move to `rules/elastic_watcher/retired/`,
add an idempotent DELETE step to `deploy_dashboards.sh` (defensive — this
one was likely never actually installed anywhere, unlike its precedent,
but cheap to include), update the handful of comments elsewhere
(`configs/systemd/intel-refresh.service`, `configs/intel/refresh_intel.sh`,
`configs/systemd/zeek-host-capture.service`) that reference "the
intel_feed_stale Watcher" as the live alerting mechanism.

## Part 2 — compact_threat_intel.py's client timeout doesn't cancel the
## server-side delete

`compact_index()`'s `_delete_by_query` call (`timeout=60`) — a client-side
give-up does not cancel the ES-side task, which keeps running regardless;
a re-run then doubles the work with no record of what the first attempt
removed.

Fix: `wait_for_completion=false` on the kickoff POST (returns immediately
with a task ID), then a new `_wait_for_task()` helper polls `GET
_tasks/<id>` until `completed:true`, returning the same response shape a
synchronous call would have. If polling's OWN bounded budget
(`TASK_POLL_TIMEOUT_SECONDS`, default 300s) elapses, raise with the real
task ID and explicit "do not re-run, reconcile via `_tasks/<id>`"
guidance — folds the issue's "at minimum" fallback into the primary fix
rather than leaving it as a separate weaker option.

`configs/systemd/threat-intel-compact.service`'s `TimeoutStartSec=120` is
tight for two sequential indices' worst-case poll budgets (300s x 2) —
bump to give real headroom for the "legitimate long accumulation gap"
scenario the issue describes, rather than trading one silent-orphan bug
for a systemd-kills-mid-poll one.

## Test impact

`tests/ai_agent/test_compact_threat_intel.py`'s `_counts_then_delete`
helper currently has `requests.post`'s `_delete_by_query` branch return the
final body directly — needs to return `{"task": "..."}` instead, with
`_wait_for_task()` mocked separately per test to return the same
`delete_body` fixtures already in use (minimal test-assertion changes,
mechanical mocking-seam change). New `WaitForTaskTests` class for
`_wait_for_task()` itself (poll-until-complete, poll-interval sleep,
budget-exceeded raise with task ID).

## Verification

- Full test suite + ruff.
- `systemd-analyze verify` on the touched unit.
- security-auditor + code-reviewer in parallel.
- tester-debugger live-verification against the real stack: confirm the
  new SLO metrics compute correctly against real `threat-intel-*` data,
  confirm `_wait_for_task()` against a REAL `_delete_by_query?wait_for_
  completion=false` + `_tasks/<id>` round trip (not just mocked shape
  assumptions — the exact task-ID format and `_tasks` response shape need
  real-cluster confirmation), confirm `deploy_dashboards.sh`'s retirement
  DELETE step is idempotent.

# #555 — stack_health.sh on a timer + staleness checks

Plan written 2026-09-06, before implementation. Milestone M26.

## The issue asks for three things

1. `stack_health.sh` runs on a schedule on the capture host, with install docs.
2. A staleness check on `soc-slo-metrics`.
3. The same for `soc-health`.

## The design decision the issue does not make

Putting both staleness checks in one place is circular. A check on
`soc-slo-metrics` that lives inside `slo_metrics.py` cannot fire when
`slo_metrics.py` is the thing that stopped running — which is precisely the
condition it exists to detect, and precisely what happened here (the index has
been frozen at `2026-08-17T01:31:42Z` while the unit failed every 15 minutes).

So: **mutual cross-monitoring**, one check in each lane.

| Lane | Runs as | Watches | Detects |
|---|---|---|---|
| `stack_health.sh` | its own timer, every 5 min | `soc-slo-metrics` freshness | the SLO lane stopped producing |
| `slo_metrics.py` | `slo-metrics.timer`, every 15 min | `soc-health` freshness | the health lane stopped producing |

Neither lane can be silently dead without the other reporting it. That is the
M26 objective stated as a property rather than a wish, and it is strictly
stronger than what the issue text asks for at the same implementation cost.

It is not a closed loop on its own — both still depend on #554 for a delivery
path, and a simultaneous outage of both lanes is still silent. Recorded as a
known limit, not papered over.

## Work items

### 1. `configs/systemd/stack-health.service` + `.timer`

`configs/monitoring/reliability.cron` schedules `stack_health.sh` every 5
minutes, but is not installed on this host and the repo has already moved this
class of job to systemd (`configs/slo/slo-metrics.cron` is explicitly marked
non-preferred in favour of `slo-metrics.timer`). New unit follows
`slo-metrics.service`, with #550's conclusions built in from the start rather
than retrofitted:

- `ExecStartPre=-/usr/bin/timeout 15 /usr/bin/docker cp …` — best-effort AND
  time-bounded. `stack_health.sh` sources `lib/es_common.sh`, which hard-errors
  when `ES_CA` is unreadable unless `ES_INSECURE=true`, so this unit needs the
  same CA plumbing.
- `es_ca_cache.sh restore` -> `verify_ca_fingerprint.sh` (wrapped `|| exit 1`)
  -> `es_ca_cache.sh save`, against its own `RuntimeDirectory=`/`StateDirectory=`
  at mode 0700.
- `SuccessExitStatus=0 2` — `stack_health.sh` exits 2 when a component is DOWN,
  which is a successful run reporting degradation, same shape as `slo_metrics.py`.
- `TimeoutStartSec=`, no `RemoveIPC=`, and the sandbox directive set ported from
  `intel-refresh.service` (this also means the new unit does not start out with
  #558's parity gap).
- `stack_health.sh` also calls `docker ps` for container checks. Those are
  already `2>/dev/null`-guarded and fall through to DOWN, so a stopped engine
  degrades the report rather than breaking the run — but the report will read
  "containers DOWN" when the truth is "no Docker CLI". Worth one line in the
  script to say which.

### 2. `soc-slo-metrics` staleness in `stack_health.sh`

New check alongside the existing five, using the same `check`/`report`/`DOWN`
machinery so it participates in the existing ntfy path with no new delivery
code. Threshold from env (`SOC_SLO_METRICS_STALE_MAX_S`, default 3 x the
15-minute timer interval = 2700s).

### 3. `soc_health_stale_seconds` in `slo_metrics.py`

New metric on the established pattern (`metric_zeek_ingest_lag_seconds()` is the
closest template: newest `@timestamp`, `MetricUnavailable` on a failed query,
never a silent `n/a`). Target `SLO_SOC_HEALTH_STALE_MAX_S`, default 1200s
(4 x the 5-minute cadence). Registered in `TARGETS` and `metric_fns`.

Whether it belongs in `BREACH_IF_NA` needs deciding during implementation: an
empty `soc-health` index on a fresh deployment is legitimately "no data yet",
but on this host it would mean the health lane never ran. `metric_zeek_ingest_
lag_seconds` chose `BREACH_IF_NA` and documented why; follow that reasoning or
document a departure from it.

### 4. Tests

`tests/pipeline/` for the unit wiring (reusing the assertions written for #550 —
`-`-prefix, timeout, cache ordering, `StateDirectoryMode`), `tests/ai_agent/`
for the new metric against the existing fake-ES harness in
`tests/ai_agent/test_slo_metrics.py`.

### 5. Docs

Install steps in the operator docs; `reliability.cron` marked as the
non-preferred fallback the way `slo-metrics.cron` already is.

## Expected result on this host

Both new checks will report a breach immediately, because both indices really
are stale (`soc-slo-metrics` 20 days, `soc-health` ~56 days). That is the
checks working. They will stay breaching until the `slo_metrics` credential is
resynced and the health lane is installed — the two items sitting under
Outstanding owner action in `planned_execution.md`.

## Out of scope

- Installing the timer on the host (`sudo`; deferred at the operator's request).
- The delivery path itself — #554.
- Shipping the journal — #556.

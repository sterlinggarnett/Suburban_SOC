# Security audit — #555 stack-health liveness (`555-stack-health-liveness`)

Date: 2026-09-06. Red + blue lens. Read-only analysis; no code executed by the
auditor. Transcribed into this file by the main session (the auditor had
Read/Grep/Glob only), with a **Disposition** line added to each finding
recording what was actually done.

Auditor's stated assumptions: could not run `git diff` (no Bash), so audited the
working-tree state against `plans/20260906-555-stack-health-liveness.md`; did not
read secret *values* out of `scripts/setup/.env`, only key names.

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 6 |

---

## HIGH 1 — the new 5-minute timer authenticates to Elasticsearch as `elastic`

**T1078 (Valid Accounts).** `configs/systemd/stack-health.service` sets no
`Environment=ES_USER=`, so `scripts/setup/lib/es_common.sh:53` defaults it to
`elastic` and `:54` picks up `ELASTIC_PASSWORD` from `.env`. That reverses the
audit #167/#222 posture `slo-metrics.service:73` (`ES_USER=slo_metrics`) and
`intel-refresh.service` (`ES_USER=intel_writer`) already implement, and #555
turns occasional manual superuser use into **288 authentications a day**.

Red: any compromise of `tjlam`, the working tree, or `.env` yields the ES
superuser — evidence destruction across `.alerts-security.alerts-*`,
`soc-audit-*`, `logstash-security-*`. Blue: indistinguishable from legitimate
admin use in the ES audit log; no detection exists. The test at
`tests/pipeline/test_stack_health_unit.py:232-245` *codified* the gap by
asserting `ES_USER` is absent from `.env.example`.

No writer identity for `soc-health` existed anywhere: `logstash_writer` covers
`logstash-*`/`soar-actions-*`/`asset-inventory-*`/`soc-agent-health-*` only
(`docker-compose.yml:326`).

**Disposition: FIXED.** New least-privilege `soc_health` ES user + role
(`configs/elasticsearch/roles/soc_health.json`), provisioned in the
`docker-compose.yml` bootstrap block behind `SOC_HEALTH_PASSWORD`, extracted
into the unit via the `RuntimeDirectory` scratch-file `ExecStartPre` pattern
proven at `slo-metrics.service:58` (including the `grep -Eq "^ES_PASS=.{8,}"`
guard). The `.env.example` assertion test was replaced with one asserting the
unit pins a non-`elastic` `ES_USER`.

## HIGH 2 — `soc_admin` can forge or delete `soc-health`

**T1562.001 / T1070.** #555 promotes `soc-health` from dashboard data to a
monitoring-integrity signal, but its ACL was not promoted with it.
`configs/elasticsearch/roles/soc_admin.json:4-5` grants `all` on `soc-*` while
excluding `-soc-slo-metrics`, `-soc-agent-health-*`, `-soc-audit-*` — `soc-health`
matches `soc-*` and was not excluded.

Deletion *is* caught (missing index -> `None` -> `BREACH_IF_NA`). **Forgery is
not:** one document with a current `@timestamp`, then stop the timer, and the SLO
lane reports the health lane alive indefinitely.

**Disposition: FIXED.** `-soc-health` added to the `soc_admin` exclusion list
alongside the `-soc-slo-metrics` precedent, with a test covering both
self-monitoring output indices.

## MEDIUM 1 — a future-dated `@timestamp` reads as "fresh" in BOTH lanes

**T1562.001.** `scripts/setup/stack_health.sh` computed `slo_age` as a signed
difference and compared `slo_age > threshold`; a negative age trivially passes,
printing `UP (fresh -1728000s)`. `slo_metrics.py`'s
`metric_soc_health_stale_seconds()` had the same defect via
`LOWER_BETTER=True`. Reachable from a compromised `slo_metrics` credential
(`create` on `soc-slo-metrics`), from HIGH 2, or from plain host clock skew — so
the headline property "neither lane can go silently dead without the other
reporting it" did not hold. No test used a future timestamp on either side.

**Disposition: FIXED** in both lanes, with regression tests on each.

## MEDIUM 2 — an empty `ca.crt` silently bypasses the `ES_REQUIRE_CA=0` diagnostic

`scripts/setup/lib/es_common.sh:77` tested `[[ -f ]]` — existence of a regular
file, not readability and not non-emptiness — contradicting its own header
(":23, *if readable*") and `configs/intel/refresh_intel.sh:204`'s `[[ -r ]]`. A
0-byte `ca.crt` therefore took the first branch, so the `ES_REQUIRE_CA=0` branch
that *explains* a missing CA never ran. Realistic under this unit: `timeout 15
docker cp` killed mid-write leaves a truncated destination, and
`es_ca_cache.sh`/`verify_ca_fingerprint.sh` all gate on `-s` and no-op on it.
Still fail-closed (curl 77) — the cost is a misdiagnosed outage, not exposure.

**Disposition: FIXED** — `[[ -s && -r ]]`, with 0-byte and mode-000 cases added
to the functional tests.

## MEDIUM 3 — the ES password is passed in `curl` argv, now 288x/day

**T1552 + T1057.** `es_common.sh:75` `ES_AUTH=(-u "${ES_USER}:${ES_PASS}")`
expands into argv at `:109`/`:114`; any same-UID process can read it from
`/proc/<pid>/cmdline`. `ProtectProc=invisible`/`ProcSubset=pid` restrict what
this unit sees of others, not what others see of it.

**Disposition: PARTIALLY MITIGATED, remainder deferred.** HIGH 1's fix drops the
exposed credential from ES superuser to a narrow monitoring account. Moving auth
off argv entirely (`curl -K -` or a 0600 `--netrc-file`) is a change to a shared
library with 10+ consumers and cannot be verified without a live cluster — not
attempted blind inside #555. Recorded here rather than filed as a public issue.

## MEDIUM 4 — the new unit opens a second TOFU pin store and re-pins from scratch

**T1553 / T1557.** `stack-health.service` pins to
`/var/lib/suburban-soc-health/ca_fingerprint.sha256`, disjoint from
`slo-metrics.service`'s `/var/lib/suburban-soc-slo/...`. On a host where a
trusted anchor has existed for weeks, this creates a *new* first-use pin: an
attacker who swapped the container's CA is rejected by the old pin and
**accepted and permanently pinned** by the new one — on the lane carrying the
higher-privilege credential.

**Disposition: PARTIALLY FIXED.** A pin-seeding step was added to SOP-005's
install sequence, before the first `systemctl start`. Teaching
`verify_ca_fingerprint.sh` to cross-check sibling `/var/lib/suburban-soc-*` pins
and hard-fail on divergence is the stronger fix and is recorded as follow-up.

## MEDIUM 5 — `container_up()` ignored container state and health

**T1562.001.** `docker ps` lists containers in the `restarting` state and
`{{.Names}}` carries no state field, so a crash-looping `soc_ai_agent` or
`hive_mind_broker` read as UP and never reached the ntfy path. (`grep -qx` does
correctly require a full-line match, so name-prefix confusion was not possible.)

**Disposition: FIXED** — the single snapshot now carries `{{.State}}` and a
container only reads UP when its state is `running`; a decoy or crash-looping
container is reported with its actual state.

## LOW 1 — `.env` is sourced after systemd's `Environment=`, so `ES_INSECURE=true` there still wins

`stack_health.sh` runs `set -a; . .env; set +a` before sourcing `es_common.sh`,
so an `ES_INSECURE=true` line in `.env` yields `ES_TLS=(-k)`. The existing test
only asserted the *script* does not set it.

**Disposition: FIXED** — the script now refuses `ES_INSECURE=true` when running
under systemd (`INVOCATION_ID` set): a scheduled monitor is never the
"lab/first-run" case that opt-out exists for.

## LOW 2 — `SOC_SLO_METRICS_STALE_MAX_S` used unvalidated in `(( ))`

**T1059.004.** Bash recursively evaluates a variable's *contents* inside `(( ))`,
so `x[$(cmd)]` executes `cmd` and a value naming another variable makes the
comparison always false. Reachable from the process environment, not only `.env`.

**Disposition: FIXED** — validated against `^[1-9][0-9]*$`, falling back to the
default with a warning. `SLO_SOC_HEALTH_STALE_MAX_S` needs no equivalent:
`slo_metrics.py` wraps it in `float()`, which raises on garbage.

## LOW 3 — a timezone-less `@timestamp` is parsed as local time by `date -u -d`

`date -u` controls output formatting, not interpretation of a naive input.
`strict_date_optional_time` accepts a naive value, which would shift the age by
the UTC offset — enough to make a dead lane read fresh against a 2700s
threshold. Latent: no current writer emits one. The Python half fails *closed*
here (naive minus aware raises `TypeError` -> `MetricUnavailable`); the bash half
failed open.

**Disposition: FIXED** — `Environment=TZ=UTC` on the unit, and the script now
rejects a timestamp with no `Z`/offset.

## LOW 4 — every healthy `soc-health` document recorded `"down":[""]`

`printf '"%s",' "${DOWN[@]}"` on an empty array still applies the format once
with an empty argument. A panel or rule written as "alert when `down` is
non-empty" would match every healthy document — 288 false positives a day, the
practical route to the alert fatigue this lane exists to prevent. There is no
index template for `soc-health`, so the first document's dynamic mapping is
authoritative.

**Disposition: FIXED** — emits `[]` on a healthy run, with a test on the posted
body.

## LOW 5 — `Persistent=true` on a purely monotonic timer

Per `systemd.timer(5)`, `Persistent=` replays a missed run only for timers with
`OnCalendar=`. `stack-health.timer` used `OnBootSec=`/`OnUnitActiveSec=` only, so
the header comment and its test asserted a property the configuration could not
deliver. Auditor explicitly flagged this as asserted from documentation, not
executed on this host.

**Disposition: FIXED** — `OnCalendar=*:0/5` added, which makes `Persistent=`
meaningful and aligns the cadence to wall-clock. `slo-metrics.timer` has the same
shape and was deliberately left alone (outside #555's scope); the divergence is
noted in the timer's own comment.

## LOW 6 — `[[ -f ]]`-to-curl TOCTOU in a shared library

`ES_TLS` is fixed at source time; the file is re-read at each `curl`. **Not
exploitable in this unit**: the path lives in `RuntimeDirectory=` at mode 0700
owned by the service user, nothing writes it after `ExecStart`, and
`PrivateTmp=true` removes the shared-`/tmp` variant.

**Disposition: NO CHANGE**, per the auditor's own recommendation. Relevant only
if `es_common.sh` gains consumers pointing `ES_CA` at a group/world-writable
directory.

---

## Checked and clear (negative results, recorded rather than left as silence)

1. **No command injection in the `date -d` path.** `"$slo_newest"` is a single
   quoted argv element, never re-evaluated by a shell, never in `eval` or `$( )`.
   A leading `-` cannot be read as an option because it is the operand of `-d`.
2. **No arithmetic injection from the ES-supplied value.** `slo_epoch` is
   `date +%s` output (`[-]?[0-9]+` or empty); empty is caught by the explicit
   guard. (The *threshold* variable was a different story — LOW 2.)
3. **No unbounded or hung run.** `es()` sets `--max-time` unconditionally and the
   call passes `-m 6`; `docker ps` is `timeout 10`-wrapped; the start job is
   bounded by `TimeoutStartSec=120`.
4. **No log-injection via the error string.** JSON forbids unescaped control
   characters, so the `grep -o` capture can only contain a literal six-character
   `` escape sequence, never a raw terminal escape byte; `report()` passes
   the value as an argument, never as a format string.
5. **`ES_REQUIRE_CA=0` does not leak to children or siblings.** `set +a` closes
   before the assignment, so it is not exported, and `.env.example` correctly does
   not offer it as an operator knob.
6. **The `soc-health` read grant is least-privilege and both copies are in sync.**
   `read` on a concrete index name is the minimum privilege permitting `_search`;
   `view_index_metadata` would not suffice. The index holds no secrets.
7. **The CA trust chain is correctly ordered and correctly un-forgiving.**
   `restore` -> `verify` -> `save`; `verify` deliberately un-prefixed and wrapped
   in `|| exit 1`; `docker cp` both `-`-prefixed and `timeout`-wrapped; both
   directories 0700; `RemoveIPC` correctly absent. Every #550 conclusion is
   present and correctly reproduced.

## Deployment gate (not a code defect)

The cross-monitoring pair is **one-sided until an owner acts**:
`SLO_METRICS_PASSWORD` is blank in `scripts/setup/.env`, so
`docker-compose.yml:336`'s `if [ x$${SLO_METRICS_PASSWORD} != x ]` guard never
fires and `slo-metrics.service:58`'s credential check fails the unit outright.
The half of the pair that watches `soc-health` therefore cannot run at all.
`SOC_HEALTH_PASSWORD` (HIGH 1's fix) adds a second provisioning step of the same
class. Both are recorded under "Outstanding owner action" in
`planned_execution.md`; the milestone must not be closed on the assumption that
either half is live.

## Follow-up recommended by the auditor

Hand HIGH 2, MEDIUM 1 and MEDIUM 5 to the **purple-team** agent — all three are
"the watchdog reads healthy while the thing it watches is dead," which is the
coverage question that agent exists to answer.

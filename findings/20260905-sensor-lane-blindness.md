# Both sensor lanes blind — stale interface pins + a correlated monitoring failure

Date: 2026-09-05
Host: `Dragon-Zord` (local WSL2 capture host — the real one, per CLAUDE.md)
Scope: `zeek-host-capture.service`, distro `suricata.service`, `slo-metrics.service`
Trigger: session opened with "docker is up, continue the backlog" — the backlog's
premise (Docker was the blocker) turned out to be wrong.

## Summary

Docker Desktop being down was **not** why the Zeek lane stopped. Three independent
failures were in play, two of them silent, and the monitoring that should have
caught the first was itself dead from the third.

Net effect: **the SOC had no network sensor coverage at all** — neither Zeek nor
Suricata was seeing a single packet — while every `systemctl is-active` check
reported `active`.

## Finding 1 — Zeek lane dead 5 days, then wedged (root cause: stale `CAPTURE_IFACE`)

`/etc/default/zeek-host-capture` pinned `CAPTURE_IFACE=eth6`. WSL2 renumbered the
host NICs across a reboot; `eth6` came back `DOWN` with no address. The live LAN
interface is `eth4` — `192.168.1.103/24`, holding the default route
(`default via 192.168.1.1 dev eth4 proto kernel metric 30`).

Verbatim, every restart:

```
Sep 05 16:48:15 Dragon-Zord bash[6762]: tcpdump: eth6: That device is not up
Sep 05 16:48:15 Dragon-Zord bash[6763]: fatal error in <params>, line 1: problem with
  trace file - (truncated dump file; tried to read 4 file header bytes, only got 0)
Sep 05 16:48:15 Dragon-Zord systemd[1]: zeek-host-capture.service: Failed with result 'exit-code'.
```

Last Zeek log write: `conn.log` at `2026-08-31 20:56`. Five days of nothing.

**Why it stayed invisible — two compounding effects:**

1. `Restart=always` + `StartLimitIntervalSec=0` (both deliberate; the unit header
   explains the limiter must never give up while waiting for the Docker Desktop
   engine after boot) turned a *permanent config error* into an unbounded crash
   loop. `systemctl is-active` reports `active` throughout, because systemd
   re-enters the active state between failures.
2. **Then it wedged.** At restart #123 (`16:49:16`) the dead tcpdump leg left
   `docker run` attached to container `ba3b492f9bfb`, whose Zeek had already
   exited (`docker logs` shows the same `fatal error ... truncated dump file`).
   That client process never returns, so systemd saw `ExecStart` still running
   and parked the unit at `ActiveState=active / SubState=running` **indefinitely**,
   capturing nothing. The restart counter froze at 123.

   `set -o pipefail` — added specifically to stop a dead tcpdump leg from looking
   healthy — cannot catch this. It only decides an exit status once the pipeline
   *exits*, and this one hangs forever.

This is the unit's own documented nightmare scenario, which its header already
names for the image-pull case ("silently retrying forever inside
`Restart=always`/`StartLimitIntervalSec=0` while systemd reports 'activating' the
whole time") and mitigates only with a docs note. Nothing mitigated it for the
interface pin.

## Finding 2 — Suricata active, capturing zero packets (wrong unit, wrong interface)

The installed unit is the **distro** `suricata.service`, not the repo's
`configs/systemd/suricata-host-capture.service` (which is not installed at all —
`ls /etc/systemd/system/` shows no suricata unit). It runs:

```
ExecStart=/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid
```

against `/etc/suricata/suricata.yaml`:

```
af-packet:
  - interface: eth0
```

`eth0` is `DOWN`. Verbatim from the newest `eve.json` stats event:

```json
"capture":{"kernel_packets":0,"kernel_drops":0,"errors":0,...},
"decoder":{"pkts":0,"bytes":0,"invalid":0,"ipv4":0,"ipv6":0,"ethernet":0,...}
```

263 MB of `eve.json` that is almost entirely `event_type:"stats"` records — which
is exactly why the lane *looks* alive: the file keeps growing and its mtime stays
fresh while `decoder.pkts` never leaves 0.

It also loads distro rules, not `rules/suricata/`. So **M23 #443 ("Deploy Suricata
on the boundary capture path in IDS/EVE mode") is genuinely not deployed** — the
running Suricata is unrelated to this repo's signature lane. #443 remaining open
is correct; what is *not* correct is any assumption that a Suricata lane exists.

CLAUDE.md's note that during a Docker outage "Suricata and Filebeat stay active"
is true and misleading: active, and blind.

## Finding 3 — the monitoring died of the same cause (why nobody was told)

```
slo-metrics.service: Control process exited, code=exited, status=203/EXEC
```

on every run for as long as the journal covers. Cause:

```
ExecStartPre=/usr/bin/docker cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt /run/suburban-soc-slo/ca.crt
```

`/usr/bin/docker` is a symlink into the Docker Desktop WSL distro
(`-> /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker`), **re-created at
`Sep 5 16:46`** when Docker Desktop started. While Docker Desktop was stopped that
symlink dangled, so `ExecStartPre` failed `203/EXEC` (exec target not found) and
the whole unit never ran.

`203/EXEC` is a systemd-level exec failure, so the Python never starts and no
metric — including `metric_zeek_ingest_lag_seconds`, the per-source liveness
metric M21 shipped precisely for this — is ever computed or alerted on.

**This is the important part: coverage was not independent.** The Docker Desktop
outage took down the capture lane *and* the monitoring that watches the capture
lane, so a five-day sensor blackout produced zero signal. Any future reasoning
about "the SLO lane will catch it" has to account for the fact that both share a
single point of failure.

## Blue-team read

Detection-wise this is an availability failure, not an intrusion, but the
consequence is the same as a successful defense-evasion campaign: for five days
there is **no network telemetry to hunt in**. Anything that happened on
192.168.1.0/24 in that window is unreconstructable from Zeek or Suricata — there
is no data to go back to, only the gap itself.

Relevant framing: an adversary who could induce this state deliberately would be
performing **T1562.001 (Impair Defenses: Disable or Modify Tools)** —
and the telling detail is that the *observable* for this outage and for a
deliberate sensor-disable are identical: unit reports `active`, log files stop
advancing. The detection opportunity is therefore the same for both, which makes
it worth building regardless of cause:

- **Alert on sensor output staleness, never on unit state.** `systemctl is-active`
  was wrong in all three findings here. `conn.log` mtime and Suricata's
  `decoder.pkts` delta are ground truth; unit state is not.
- **Alert on `decoder.pkts == 0` over a window** — a Suricata that is running and
  decoding nothing is the single clearest signal of finding 2, and it was sitting
  in `eve.json` the whole time.
- **The monitoring lane needs its own liveness signal** that does not depend on
  Docker, or finding 3 recurs and silences everything downstream.

## Fix status

| # | Fix | Status |
|---|---|---|
| 1 | Interface preflight (`scripts/setup/capture_iface_preflight.sh`, exit 78 = `EX_CONFIG`) + `RestartPreventExitStatus=78` on the unit, so a bad pin parks the unit in `failed` instead of crash-looping behind `active`. Narrow by design: only 78 is terminal, so the Docker-Desktop boot race keeps its unbounded retry. Regression test: `tests/pipeline/test_zeek_capture_iface_validation.py` (20 cases) | Implemented and reviewed this session |
| 1a | Correcting the live pin (`CAPTURE_IFACE=eth4`) and restarting the unit | **Done 2026-09-05 by the owner** — `tcpdump: listening on eth4`, `conn.log` writing again after five days |
| 1b | Installing the updated unit (`sudo cp` + `systemctl daemon-reload`) — the repo copy is inert until then | **Done 2026-09-05 by the owner** — `RestartPreventExitStatus=78` verified present in `/etc/systemd/system/zeek-host-capture.service` |
| 2 | Suricata lane genuinely not deployed | Pre-existing open issue **#443**; this finding is evidence for it, not a new gap |
| 3 | `slo-metrics.service` `ExecStartPre` hard-depends on the Docker CLI | **Not yet fixed** — tracked as **#550** (M26), next candidate |
| 4 | Zeek wedge (`active (running)`, zero packets) — fix 1 closes the trigger, not this | **Not yet fixed** — tracked as **#549** (M26) |

> **Scope correction (security-auditor review).** Fix 1 closes the *trigger*
> observed on 2026-09-05 — an unusable interface pin — but **not the wedge
> itself**. The preflight runs once, before the pipeline; every other route to
> `active (running)` while capturing nothing is untouched, notably tcpdump dying
> mid-run (device removed, `ENOBUFS`, or the `CAP_SETUID` EPERM the unit
> documents at `zeek-host-capture.service:168-190`) and leaving `docker run`
> attached to a container whose Zeek has already exited. An earlier draft of
> this table claimed fix 1 stopped the unit "crash-looping/wedging"; that claim
> holds only for this one trigger and has been narrowed accordingly.
>
> Closing the wedge properly needs an **independent liveness supervisor** —
> `WatchdogSec=` cannot be used, because the bash `ExecStart` cannot
> `sd_notify()`. The shape that works: a timer comparing
> `/storage/PCAP/zeek_logs/conn.log` mtime against now, restarting the unit and
> alerting **only when it is `active` and the logs are stale** — never when it
> is `failed`, which must stay parked. Tracked as **#549** (M26).

## Verification performed

- Preflight run against the real stale pin: `SOC_IFACE_WAIT_SECS=0 bash
  scripts/setup/host_capture.sh eth6` → exit `78`, message correctly enumerates
  `lo`, `loopback0`, `eth4` as up and names `eth4` as the default route. This
  single run exercises both directions of the flag check (eth0–eth3, eth5, eth6
  correctly excluded).
- Positive path on the real NIC: `capture_iface_preflight.sh eth4` → exit `0`.
  Empty pin → `78`. Injection probe `'eth4; touch /tmp/pwned'` → `78`, no file
  created (#320's invariant holds).
- `pytest tests/pipeline/ tests/setup/` → 473 passed, 34 subtests passed.
- `shellcheck scripts/setup/host_capture.sh scripts/setup/capture_iface_preflight.sh` → clean.
- Full suite → 1148 passed, 2 failed, both confirmed **not** caused by this change
  via `git stash`: `test_slo_metrics.py::...::test_precheck_success_does_not_affect_a_healthy_run`
  fails identically on a clean tree (known local `SLO_COVERAGE_MIN` drift), and
  `test_weekly_ciso_report.py::...::test_each_run_gets_a_distinct_filename`
  *passed* on the clean tree — a same-second timestamp collision flake.
- `tests/detections/test_zeek_mime_detection.py` fails to import (`smtpd`, removed
  in Python 3.12) — pre-existing local toolchain drift, unrelated.


## Review outcomes (2026-09-05)

`security-auditor` and `code-reviewer` ran in parallel on the changeset. Both
cleared the #320 shell-injection invariant explicitly — quoting, `case`'s
literal-word semantics, and `ip`'s `dev` keyword close every candidate vector,
and `[ ... -ge ... ]` uses `legal_number()` rather than arithmetic evaluation.
Findings accepted and fixed before commit:

| Source | Finding | Resolution |
|---|---|---|
| code-reviewer | Greedy `.*<` in the flag extraction binds to the **last** `<...>` on the line, so an interface ALIAS containing `<...,UP>` makes a DOWN interface parse as up — reproduced live with `unshare -rn` + a crafted alias | Anchored to the first group (`s/^[^<]*<\([^>]*\)>.*/\1/p`); regression test `test_an_interface_alias_containing_angle_brackets_cannot_fake_the_up_flag` |
| both | `SOC_IFACE_WAIT_SECS` unvalidated → non-numeric spins forever; huge value sleeps ~31 years behind `active (running)` | Non-numeric → warn + zero grace period; values above 300s clamped with a warning |
| security-auditor | `docker run` passes the **container's** exit code through verbatim, so a Zeek-side 78 would permanently park the sensor (T1562.001) | Pipeline status captured and any downstream 78 remapped to 1; 78 reserved to the preflight |
| security-auditor | A bare `var="$(...)"` in the diagnostic takes the substitution's status; under `set -euo pipefail` a failing `ip` exits **before** `exit 78`, making `RestartPreventExitStatus` inert | Diagnostic moved into `emit_diagnosis`, called `|| true`; regression test with a deliberately failing fake `ip` |
| security-auditor | Empty `CAPTURE_IFACE` hit `${1:?}` → exit 1, not 78 → crash-loops forever | Explicit guard emitting the same diagnostic and exiting 78 |
| security-auditor | Five new root-executed, `$PATH`-resolved binaries in a unit whose `EnvironmentFile` can set `PATH` (T1574.007) | `PATH` pinned in `host_capture.sh` before anything runs |
| code-reviewer | No positive-path test — an `iface_is_up` that always returned false would pass the whole suite while permanently parking a **healthy** unit | Preflight extracted to its own script so the positive path is testable without firing `docker run`; `lo` and a synthetic up-interface both asserted to pass |

One recommendation was **declined**: code-reviewer proposed exiting 78 on a
malformed `SOC_IFACE_WAIT_SECS`. The auditor's finding shows why that is wrong —
`EnvironmentFile=-/etc/default/zeek-host-capture` injects arbitrary variables, so
"garbage → terminal" hands anyone with write access to that file a one-character
permanent sensor kill, strictly worse than the bug being fixed. A malformed value
instead loses its grace period (fail fast) and warns, so it can never buy silence
and never parks a healthy sensor. Covered by
`test_a_non_numeric_wait_value_does_not_park_an_otherwise_healthy_sensor`.

Carrier (`NO-CARRIER`) is deliberately **not** terminal: it can drop at any time
after the preflight passes, so no start-time check can own it, and making it
terminal risks permanently parking device types that never report carrier. The
preflight warns; sustained zero-traffic remains the capture-loss monitor's job.

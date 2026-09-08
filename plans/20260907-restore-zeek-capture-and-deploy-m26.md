# Complete path — restore Zeek capture, then deploy M26

**Date:** 2026-09-07 · **Host:** `Dragon-Zord` (local WSL capture host)
**Diagnosis:** `findings/20260907-zeek-host-capture-restart-loop.md`

## Current state

Zeek has produced nothing since **2026-09-06 15:38**. `zeek-host-capture.service`
is in `activating (auto-restart)`, restart counter **1181+**, looping every 5s
with `StartLimitIntervalSec=0` (nothing rate-limits it). `filebeat`, `suricata`
and `intel-refresh` stay `active`, so unit state alone looks healthy.

## Three problems, stacked

**A. The unit cannot read `$SOC_REPO`.** It runs as root but with
`CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_CHOWN CAP_SETUID CAP_SETGID`
— no `CAP_DAC_OVERRIDE`, so normal permission checks apply. `$SOC_REPO` is under
`/home/tjlam`, mode **750** `tjlam:tjlam`. The process is neither owner nor in
that group, so it cannot traverse in. Both refresh `cp`s in `ExecStartPre` fail
with EACCES; both are `2>/dev/null || true`, so nothing is logged. The guard then
trips on the stale file and reports the wrong cause.

*Why this is the source side, not the destination:* `/storage/PCAP/intel/intel.dat`
was rewritten today at 16:23 by `intel-refresh.timer`, so the directory is
writable. And if the `cp` were succeeding, `intel.dat` would carry a mtime of
seconds ago (1181 restarts), not 16:23.

**B. `CAPTURE_IFACE=eth4` does not exist.** `/etc/default/zeek-host-capture`
(written 2026-09-05 18:26) pins `eth4`; this host has only `lo` and `eth0`. This
is #551's failure mode recurring — WSL2 renumbered the NICs again.

**C. Structural: the park mechanism is unreachable.** #551's preflight — the one
that exits 78 so `RestartPreventExitStatus=78` parks the unit in `failed` instead
of looping — runs at `scripts/setup/host_capture.sh:50`, i.e. inside **ExecStart**.
Problem A fails in `ExecStartPre`, so ExecStart never runs, exit 78 never happens,
and `Restart=always` loops forever. **A fail-closed guard placed ahead of the
park guard converts a parked misconfiguration into an infinite loop.**

Fixing only A leaves B, and the unit will then correctly park in `failed`.
Fixing only B leaves A, and it keeps looping. Both are required.

---

## Phase 0 — prove A before acting on it (non-destructive)

The `CAP_DAC_OVERRIDE` mechanism explains every observation but has not been
directly proven; confirming the errno needs root. One command:

```bash
sudo systemd-run --uid=0 \
  --property=CapabilityBoundingSet="CAP_NET_RAW CAP_NET_ADMIN CAP_CHOWN CAP_SETUID CAP_SETGID" \
  --wait --pipe /bin/bash -c \
  'cat /home/tjlam/projects/Suburban-SOC/configs/intel/config.zeek >/dev/null 2>&1 && echo READABLE || echo BLOCKED'
```

**Expect `BLOCKED`.** If it prints `READABLE`, problem A is misdiagnosed — stop
and re-open the diagnosis rather than proceeding.

## Phase 1 — restore capture (needs sudo)

```bash
# B: point at the interface that actually exists
sudo sed -i 's/^CAPTURE_IFACE=.*/CAPTURE_IFACE=eth0/' /etc/default/zeek-host-capture

# A: grant traversal via group membership, NOT by widening capabilities
sudo systemctl edit zeek-host-capture.service --full   # add: SupplementaryGroups=tjlam
# (or, non-interactively, drop a one-line override:)
sudo mkdir -p /etc/systemd/system/zeek-host-capture.service.d
printf '[Service]\nSupplementaryGroups=tjlam\n' | sudo tee /etc/systemd/system/zeek-host-capture.service.d/10-repo-access.conf

sudo systemctl daemon-reload
sudo systemctl reset-failed zeek-host-capture.service
sudo systemctl restart zeek-host-capture.service
```

`SupplementaryGroups=tjlam` is the least-privilege option: group `tjlam` already
holds `r-x` on `/home/tjlam`, and `config.zeek` / `host_capture.sh` are both mode
644, so this grants exactly the traversal needed and nothing more. Adding
`CAP_DAC_OVERRIDE` would restore blanket root file access to a unit that runs
`tcpdump`; that defeats the point of the bounding set.

**Note:** `configs/intel/data/intel.dat` is mode **600** `tjlam:tjlam`, so its
`cp` will still fail even after this. That is harmless and arguably correct — the
deployed `intel.dat` (52 KB, refreshed 16:23 today) is maintained by
`intel-refresh.timer`, which is the live feed rather than the repo placeholder.

**Verify:**
```bash
systemctl is-active zeek-host-capture.service          # expect: active
stat -c '%y %s' /storage/PCAP/intel/config.zeek        # expect: today, 5837 bytes
sleep 60; ls -l --time-style=long-iso /storage/PCAP/zeek_logs/conn.log   # mtime must advance
docker ps --filter name=zeek-host-capture              # expect a running container
```
Pinned image `zeek/zeek:8.2.1@sha256:eca2b39…c87c7` is already present locally —
no pull needed.

## Phase 2 — fix the class in the repo, so it cannot recur (PR)

1. `configs/systemd/zeek-host-capture.service` — add `SupplementaryGroups=${SOC_USER}`.
2. `configs/systemd/suricata-host-capture.service` — **same latent trap**: it is
   the only other unit with a `CapabilityBoundingSet` (`CAP_NET_RAW CAP_NET_ADMIN`)
   and the only other unit referencing `SOC_REPO`. It is not installed on this
   host, so it has never been hit — fix it before it is.
3. **Stop silencing the refresh.** Replace `cp … 2>/dev/null || true` with a form
   that captures stderr and names it in the FATAL text. A one-line EACCES became
   a 1181-restart mystery purely because it was discarded.
4. **Fix the ordering (problem C).** Move the capture-iface preflight into an
   `ExecStartPre=` ahead of the config guard, or make the config guard exit 78 as
   well, so an unusable configuration parks rather than loops. Add a regression
   test asserting the preflight is reachable when an earlier guard fails.
5. Consider `StartLimitIntervalSec=`/`StartLimitBurst=` so nothing in this unit
   can ever loop unbounded again.

Land as one PR against `main`. Standard gates apply (14 checks).

## Phase 3 — deploy M26 (the original goal)

Only after Phase 1 verifies green.

```bash
git pull
sudo bash scripts/setup/redeploy_systemd_units.sh
sudo systemctl restart filebeat.service        # #556's new /var/log/syslog input
# restart Logstash for the event.dataset:syslog branch
bash scripts/setup/deploy_detections.sh        # #556's 2 new Sigma rules
sudo systemctl enable --now stack-health.timer zeek-capture-liveness.timer
```

**Verify:** all three of `zeek-capture-liveness.timer`, `stack-health.timer`,
`soc-alert-on-failure@.service` stop reporting `not-found`.

**Caveat worth resolving first:** #549's supervisor acts only when the unit is
`active` **and** `conn.log` is stale — never when `failed`. Today's outage sat in
`activating (auto-restart)`. Confirm that state is covered, or #549 will not
catch a repeat of exactly the event that motivated it.

## Phase 4 — the credential gate, then delivery

1. Resync the `slo_metrics` Elasticsearch credential. `slo-metrics.service` is
   `failed` with `ExecMainStatus=3`; every ES-backed metric reads
   `ERROR(unmeasurable)` and `soc-slo-metrics` has been frozen since
   `2026-08-17T01:31:42Z`.
2. Only then provision `NTFY_TOPIC` (#554). Enabling delivery while ~15 metrics
   report unmeasurable every 15 minutes produces ~96 high-priority pushes a day,
   the topic gets muted, and the silence returns behind a belief that alerting
   works.

## Blocked on you

- **PR #565** (docs close-out, 14/14 green, `MERGEABLE CLEAN`) — `gh pr merge` is
  denied by the auto-mode classifier. Needs your merge button or a
  `Bash(gh pr merge:*)` permission rule.
- **All of Phases 0, 1, 3, 4** — `sudo` requires a password here.

Phase 2 is the only part I can do unattended.

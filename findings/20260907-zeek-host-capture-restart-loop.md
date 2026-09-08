# Finding — zeek-host-capture.service permanent restart loop

**Date:** 2026-09-07 (local WSL capture host, `Dragon-Zord`)
**Scope:** read-only diagnosis. No unit was started, stopped, enabled, or modified.
**Status:** root cause identified; fix requires sudo and is NOT applied.

## Impact

The Zeek capture lane has produced **no output since 2026-09-06 15:38** (newest
write anywhere in `/storage/PCAP/zeek_logs/` is `conn.log`). `filebeat.service`,
`suricata.service` and `intel-refresh.timer` all remain `active`, so the outage
is invisible from unit state alone. `slo-metrics.service` — which holds the
`zeek_ingest_lag` metric that would have flagged it — is itself `failed`
(`ExecMainStatus=3`, the known credential-resync gap). M26's three
liveness/alerting units are merged but report `not-found` on this host.

## Evidence

1. **The failure, verbatim and repeating every 5s** (`journalctl -u
   zeek-host-capture.service`; restart counter was at **1181** at 17:59):

   ```
   FATAL: deployed config.zeek is missing an expected at-load line or the #389 Log redef - stale copy
   zeek-host-capture.service: Control process exited, code=exited, status=1/FAILURE
   ```

2. **The guard that emits it** — `/etc/systemd/system/zeek-host-capture.service`
   line 304 (`configs/systemd/zeek-host-capture.service:312` in the repo). It
   refreshes the deployed config from the repo, then verifies it:

   ```
   cp --remove-destination ${SOC_REPO}/configs/intel/config.zeek /storage/PCAP/intel/config.zeek 2>/dev/null || true
   ...
   { grep -q "policy/misc/capture-loss" /storage/PCAP/intel/config.zeek && \
     grep -q "^redef Log::default_max_field_string_bytes = 8191;" /storage/PCAP/intel/config.zeek; } \
     || { echo "FATAL: ..." >&2; exit 1; }
   ```

3. **The deployed file is stale and fails both greps:**
   `/storage/PCAP/intel/config.zeek` — `mode=755 root:root`, 2179 bytes,
   **mtime 2026-08-09 10:13**. `policy/misc/capture-loss` occurrences: 0.
   No `redef Log::default_max_field_string_bytes` line.

4. **The repo source is correct and reachable by path:**
   `configs/intel/config.zeek` — 5837 bytes, 2026-09-04 20:22, contains
   `policy/misc/capture-loss` and `redef Log::default_max_field_string_bytes = 8191;`
   at line 96. `systemctl show -p Environment` resolves
   `SOC_REPO=/home/tjlam/projects/Suburban-SOC` cleanly (checked with `cat -A`;
   no stray `^M` despite the deployed unit having CRLF terminators — systemd
   strips it, consistent with PR #561's measured finding).

5. **Ruled out:** filesystem is `rw` with 864G free; `/storage/PCAP/intel` is not
   a mountpoint; no immutable attributes (`lsattr` clean on both dir and file);
   the deployed unit is content-equivalent to the repo's (the 889-line `diff` is
   the CRLF/LF renormalisation from PR #561, not drift).

## Root cause

The unit runs as **root** (no `User=`) but with:

```
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_CHOWN CAP_SETUID CAP_SETGID
```

**`CAP_DAC_OVERRIDE` is not in that set**, so this root process does not bypass
ordinary permission checks. `$SOC_REPO` lives under `/home/tjlam`, which is
`drwxr-x---` (mode **750**, `tjlam:tjlam`) — no world execute bit, and the
process is neither the owner nor in the group. It therefore **cannot traverse
into `$SOC_REPO` at all**, so the refresh `cp` fails with EACCES.

Because that `cp` is best-effort (`2>/dev/null || true`), the failure produces
no journal line. The guard then correctly reports the *symptom* — a stale
config — while the actual cause (the refresh could not read its source) is
silenced. **The unit can never self-heal, and emits a message that points at
the wrong thing.**

## Timeline (consistent with all evidence)

- `2026-09-05 18:29:39` — the current unit file is installed at
  `/etc/systemd/system/` (matches PR #546 / #551 landing; `/etc/default/zeek-host-capture`
  was written 18:26 the same evening). The **already-running** container is
  unaffected and keeps capturing.
- `2026-09-06 15:38` — last Zeek write. The unit restarts for the first time
  since the new file was installed, runs the new `ExecStartPre` guard, and fails.
- `2026-09-06 15:38 -> now` — `Restart=always` / `RestartSec=5` with
  `StartLimitIntervalSec=0` (no rate limiting), so it has looped continuously.

## Caveat on certainty

Items 1-5 are directly observed. The `CAP_DAC_OVERRIDE` mechanism is strongly
supported by all of it but is **not** directly proven: confirming the `cp`'s
errno requires running it as root, and `sudo` needs a password here. Do not
record it as confirmed until that check is run.

## Suggested fix (NOT applied — needs sudo)

Sequenced, smallest first:

1. Confirm the mechanism: `sudo -u root ...` reproduce the `cp` and capture
   stderr, or `systemd-run` the ExecStartPre with the same
   `CapabilityBoundingSet=` and read the error.
2. Unblock capture now: `sudo install -m 755 -o root -g root
   configs/intel/config.zeek /storage/PCAP/intel/config.zeek`.
3. Fix the class, not the instance — pick one and land it in
   `configs/systemd/zeek-host-capture.service`:
   - add `CAP_DAC_OVERRIDE` to `CapabilityBoundingSet=` (widest, simplest), or
   - add `ReadOnlyPaths=`/`BindReadOnlyPaths=` exposing `$SOC_REPO` explicitly, or
   - stage the config outside `/home` (e.g. a root-owned `/opt/suburban-soc/`
     deploy path) so the unit never reads through a 750 home directory.
4. **Stop silencing the refresh.** `2>/dev/null || true` on the `cp` is what
   turned a one-line permission error into a 1181-restart mystery. It should log
   the failure and say so in the FATAL text.

## Related

- The three M26 units that would have caught and reported this
  (`zeek-capture-liveness.timer`, `stack-health.timer`,
  `soc-alert-on-failure@.service`) are merged as of PR #564 but **not installed**
  on this host.
- #549's supervisor acts only when the unit is `active` AND `conn.log` is stale,
  never when `failed` — by design. This unit sits in
  `activating (auto-restart)`, so **#549 would not have alerted on this either.**
  Worth checking whether that state is covered before treating #549 as closing
  this gap.

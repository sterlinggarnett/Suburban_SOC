# Executive Summary
This Standard Operating Procedure (SOP) covers the three reliability pillars for Suburban-SOC: High Availability (HA), restore-tested backups, and self-monitoring. It ensures uptime and recoverable evidence for the SOC stack.

## Name
SOP-005 — Reliability of the SOC Stack

## Problem Statement
A production SOC requires guaranteed uptime and data recoverability. The default development stack is single-node, lacks tested backup procedures, and fails silently when components crash.

## Objectives
- Deploy and validate a 3-node HA Elasticsearch cluster.
- Prove automated snapshots work via restore testing.
- Enable self-monitoring and alerting for pipeline outages.

## Compliance
- **NIST CSF**: ID.BE-5 (Resilience requirements), PR.IP-4 (Backups), DE.AE-2 (Event detection/monitoring).
- **CIS Controls**: Control 11 (Data Recovery).

## MITRE ATT&CK Framework
- mitigates Impact (TA0040) like Data Destruction (T1485) and Endpoint Denial of Service (T1499).

## Assumptions and Limitations
- The production deployment uses `docker-compose.ha.yml`.
- Snapshots are configured to use a filesystem repo (`fs`) or S3-compatible object storage.

# Analysis
The reliability pillars are validated through regular drills, including node-kill exercises, automated canary restore tests, and continuous health checks.

## Monitoring and Notifications
The `stack_health.sh` script runs every 5 minutes via `stack-health.timer` and pushes alerts to `ntfy` if any core component (Elasticsearch, Kibana, Logstash, broker, or agent) is down.

### Installing the self-health lane (#555)

The order below matters — steps 1 and 2 must both happen **before** the first
`systemctl start`, or the unit fails on a missing credential and re-pins its trust
anchor from whatever the container is serving at that moment.

**1. Provision the least-privilege credential.** The lane runs as a dedicated
`soc_health` ES user (cluster `monitor`, append-only `create` on `soc-health`,
read-only on `soc-slo-metrics`) rather than the `elastic` superuser — a 5-minute
timer authenticating as superuser is 288 superuser logins a day, and there is no
reason for a health probe to hold more than this.

```bash
# 1a. Set a real password (openssl rand -base64 24) in scripts/setup/.env:
#     SOC_HEALTH_PASSWORD=...
# 1b. Create the role + user:
docker compose -f scripts/setup/docker-compose.yml up setup      # bootstrap path
# or, on a running cluster:
./scripts/setup/apply_roles.sh                                   # applies soc_health.json
```

If `SOC_HEALTH_PASSWORD` is blank the user is never created and the unit fails its
own credential check loudly. That is deliberate: the alternative is a silent
fallback to `elastic`.

**2. Seed the CA fingerprint pin from the lane that already has one.** This unit
keeps its own TOFU pin under `/var/lib/suburban-soc-health/`, separate from
`slo-metrics.service`'s. On a host where a trusted anchor has existed for weeks,
starting the unit cold creates a *new* first-use pin — so a CA that the existing
pin would reject gets accepted and permanently pinned here instead. Copy the
established pin across first:

```bash
sudo install -m 0600 -D \
  /var/lib/suburban-soc-slo/ca_fingerprint.sha256 \
  /var/lib/suburban-soc-health/ca_fingerprint.sha256
```

Skip this only on a host that has never run `slo-metrics.service`.

**3. Install and enable.**

```bash
sudo cp configs/systemd/stack-health.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now stack-health.timer
# Verify:
systemctl list-timers stack-health.timer
sudo systemctl start stack-health.service && journalctl -u stack-health -n 40
sudo systemd-analyze security stack-health.service   # expect ~1.6 OK
```

Expect `journalctl` to show `soc_health` (not `elastic`) authenticating. A
`kibana ... HTTP 401/403` line means this credential lacks Kibana access — a
permissions problem, not an outage; the report says so rather than paging you for
a downed Kibana.

`configs/monitoring/reliability.cron` remains the fallback for hosts without systemd; the
timer is preferred because it survives reboot, extracts and pin-verifies the ES CA itself,
and treats `exit 2` (a component DOWN) as a successful run reporting degradation.

**Why this matters:** the cron file was never actually installed on the capture host, so
`soc-health` stopped being written on 2026-07-12 and nothing detected it for ~56 days. After
installing either path, confirm the index is moving:

```bash
curl -s --cacert "$ES_CA" -u "$ES_USER:$ES_PASS" \
  "$ES_URL/soc-health/_search?size=1&sort=@timestamp:desc&_source=@timestamp"
```

### Zeek capture liveness: output-derived, not unit-state (#549)

`systemctl is-active` on `zeek-host-capture.service` is not sufficient evidence
the sensor is actually capturing. On 2026-09-05 a dead `tcpdump` leg left
`docker run` attached to a container whose Zeek had already exited; the hung
`docker run` client never returns, so systemd reported
`ActiveState=active`/`SubState=running` for **five days** with zero packets
captured. `Restart=always` and the pipeline's own `set -o pipefail` cannot
catch this — both only act once a process actually *exits*, and this one
hangs.

`zeek-capture-liveness.timer` runs `scripts/setup/zeek_capture_liveness.sh`
every 5 minutes: it compares `/storage/PCAP/zeek_logs/conn.log`'s mtime
against now, and restarts `zeek-host-capture.service` (plus an ntfy alert)
**only** when the unit is `active` *and* the log has gone stale for longer
than `ZEEK_CAPTURE_STALE_MAX_S` (default 1800s). It deliberately does nothing
when the unit is `failed` — a genuine config error (e.g. the CAPTURE_IFACE
preflight's exit 78, #551) must stay parked and visible, not be papered over
by an automatic restart.

```bash
sudo cp configs/systemd/zeek-capture-liveness.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zeek-capture-liveness.timer
# No credential/CA prerequisite, unlike stack-health.timer — this unit only
# calls systemctl and, optionally, ntfy.
sudo systemctl start zeek-capture-liveness.service
journalctl -u zeek-capture-liveness -n 20 --no-pager
```

**Known limits, not oversights:**
- No cooldown/backoff. If a restart doesn't fix the underlying cause, the
  *next* 5-minute run sees the same staleness and restarts + alerts again —
  repeated alerts for the same wedge is the deliberate trade-off over silence.
- The default 1800s threshold is a starting point ("above the quietest
  legitimate traffic gap"), not a measured value for every deployment — retune
  `ZEEK_CAPTURE_STALE_MAX_S` per link if a genuinely quiet overnight window on
  your network is longer than that.
- Same observable as a deliberate sensor-disable (T1562.001): unit reports
  `active`, the log stops advancing. `rules/sigma/system_lnx_self_health_unit_failed.yml`
  (#556) covers the *other* half — the unit actually reaching `failed`.

### Mutual cross-monitoring: who watches the watchers

The two self-monitoring lanes watch **each other's output index**, never their own:

| Lane | Schedule | Watches | Detects | Threshold |
|---|---|---|---|---|
| `stack_health.sh` | `stack-health.timer`, 5 min | `soc-slo-metrics` freshness | the SLO lane stopped producing | `SOC_SLO_METRICS_STALE_MAX_S`, default 2700s (3x the 15-min cadence) |
| `slo_metrics.py` | `slo-metrics.timer`, 15 min | `soc-health` freshness | the health lane stopped producing | `SLO_SOC_HEALTH_STALE_MAX_S`, default 1200s (4x the 5-min cadence) |

A staleness check on `soc-slo-metrics` placed *inside* `slo_metrics.py` could not fire when
`slo_metrics.py` is the thing that stopped — which is exactly the condition it exists to
detect, and exactly what happened (the index sat frozen at `2026-08-17T01:31:42Z` while the
unit failed every 15 minutes). Splitting the checks across the two lanes means neither can
go silently dead without the other reporting it.

### Failure-delivery path (#554)

Two independent gaps used to leave both halves above with nowhere to send an alert:
no unit set `OnFailure=`, so a unit that failed before its own body ever ran (an
`ExecStartPre` credential check or CA-pin mismatch) produced a journal line and
nothing else; and `NTFY_TOPIC` was unprovisioned on the capture host, so even a
metric-computed breach had no transport.

**1. Provision `NTFY_TOPIC`.** Pick a long, unguessable value (`.env.example` already
documents this) and set it in `scripts/setup/.env`:

```bash
# openssl rand -hex 16, or any other hard-to-guess string
NTFY_TOPIC=subsoc-alerts-<random suffix>
```

`slo_metrics.py` prints a startup warning to stderr on every run while this is unset,
so an unprovisioned sink is visible in `journalctl -u slo-metrics` rather than only
discoverable by reading this doc.

**2. Install the failure-alert dispatcher.** `configs/systemd/soc-alert-on-failure@.service`
is a template unit, instantiated automatically by systemd via `OnFailure=` on
`slo-metrics.service` and `zeek-host-capture.service` — nothing to enable or start by
hand. It depends on neither Docker nor Elasticsearch (those are exactly what the two
watched units themselves depend on), so it stays reachable in the outage it exists to
report.

```bash
sudo cp configs/systemd/soc-alert-on-failure@.service /etc/systemd/system/
sudo systemctl daemon-reload
# scripts/setup/redeploy_systemd_units.sh does this + the two OnFailure= updates above
# together.

# Test without waiting for a real failure:
sudo systemctl start soc-alert-on-failure@test.service
journalctl -u 'soc-alert-on-failure@*' -n 10 --no-pager
```

**Sequencing matters.** Do not provision `NTFY_TOPIC` before the `slo_metrics`/
`soc_health` credentials are healthy. While either credential is broken, every run
reports ~15 unmeasurable metrics; turning on delivery first produces dozens of
high-priority pushes a day, the topic gets muted, and the silence returns with a false
belief that alerting works.

**Known limits, not oversights:**
- `OnFailure=` is wired on `slo-metrics.service` and `zeek-host-capture.service` only —
  the two units #554 named as the minimum. A unit added later needs its own
  `OnFailure=soc-alert-on-failure@%n.service` line.
- `zeek-host-capture.service` has `Restart=always` with `StartLimitIntervalSec=0`: most
  crash loops never reach the `failed` state `OnFailure=` requires, by design (a flapping
  capture process should keep retrying). Only a *terminal* condition — currently just the
  `RestartPreventExitStatus=78` CAPTURE_IFACE preflight failure (#549/#551) — parks the
  unit in `failed` and fires the dispatcher.
- A **simultaneous** outage of both self-monitoring lanes is still silent. The shared
  dependency is Elasticsearch itself, which is what `stack_health.sh`'s own component
  checks cover.
- `metric_soc_health_stale_seconds()` is in `BREACH_IF_NA`, so an empty `soc-health` index
  breaches rather than reading as "no data yet". On a genuinely fresh deployment that
  breaches once and clears within 5 minutes of enabling the timer.
- A **future-dated** `@timestamp` is treated as an anomaly, not as freshness, in both
  lanes (tolerance 120s for benign clock skew). Without that, a single forged or
  clock-skewed document pins either check to "healthy" forever — the failure the whole
  pair exists to prevent. `soc-health` and `soc-slo-metrics` are both excluded from
  `soc_admin`'s `all` grant so an analyst-tier role cannot write that document.
- The remaining shared exposure is `curl` argv: `es_common.sh` passes credentials via
  `-u`, readable from `/proc/<pid>/cmdline` by any same-UID process. The least-privilege
  `soc_health` identity bounds the damage; moving auth off argv entirely is a change to a
  shared library with 10+ consumers and is tracked separately.

`slo_metrics_reader` needs `read` on `soc-health` for its half. The grant is in
`configs/elasticsearch/roles/slo_metrics_reader.json`; apply it with
`./scripts/setup/apply_roles.sh`. `slo_metrics.py` self-checks its own privileges against
that file on every run, so a grant present in the repo but never applied to the cluster
fails **every** metric, not just this one.

## Playbook Verification
To verify the stack's reliability:
1. Check HA status: `curl -sk -u elastic:$ELASTIC_PASSWORD https://localhost:9200/_cluster/health` (should be `green`, nodes: 3).
2. Ensure index replicas are ≥ 1.
3. Run `./scripts/setup/stack_health.sh` (should exit 0).

## Recommended Response Action(s)

### Identification
To detect an outage or data availability issue:
- Monitor ntfy for `DOWN` alerts.
- Check cluster health API for `yellow` or `red` status.

### Containment
If a node goes down:
- The cluster enters `yellow` status but remains serving (no data loss).
- Verify the remaining nodes have enough disk/memory to handle the load.

### Eradication & Recovery
**HA Recovery:**
Restart the downed node: `docker compose -f docker-compose.ha.yml start <node>`

**Backup Restore Drill:**
To verify backups or recover data from snapshots:
1. Canary test: `./scripts/setup/restore_test.sh`
2. Full index restore test: `./scripts/setup/restore_test.sh <index>`
For disaster recovery, restore into a scratch cluster and verify doc counts.

**Stuck Approval Claim Recovery (#276 / #278):**
An approval claim (`agent-checkpoints-<tenant>/{alert_id}.claim`) can be left
in `phase: CLAIMED` forever when an isolation dispatch's outcome can't be
confirmed either way (`IsolationOutcomeUnknown` — the broker connection
dropped after the block command may already have run). This is deliberate:
releasing an unconfirmed claim risks a real double-dispatch on retry. Since
#278, the broker itself makes one bounded, read-only follow-up SSH check
before giving up as "unknown," reconciling the common case (the router
recovers from a transient blip) automatically — but a genuinely unreachable
router still needs a human.

Note: #278's own reconciliation only ever auto-promotes an ambiguous outcome
to `"failed"` (safe — the retry it enables is idempotent), never to
`"success"` — `nft get element` proves set membership, not that the
referencing drop rule is still in place, so a false auto-"success" would
permanently close a case that was never actually contained. A follow-up
that finds the IP present is logged and still left `unknown` for the human
steps below.

1. Identify stuck claims: `python3 scripts/setup/ai_agent/manage_stuck_claims.py list`
   (or `slo_metrics.metric_stuck_approval_claims()` on the SLO dashboard).
2. Determine out-of-band whether the block actually landed — SSH to the
   router and check BOTH the set membership and the referencing rule (set
   membership alone is not proof of containment — see the note above):
   ```
   nft get element inet fw4 hivemind_blocklist '{ <attacker_ip> }'   # exits 0 if present
   nft -a list chain inet fw4 input | grep hivemind_blocklist        # the rule must still be there too
   ```
3. Resolve the claim accordingly (`--actor`/`--reason` are required —
   these transitions are recorded on the claim doc as `resolved_by`/
   `resolution_reason`, since a manual override of this pipeline's
   at-most-once guarantee must be attributable):
   - Block did **NOT** land — safe to retry:
     `python3 scripts/setup/ai_agent/manage_stuck_claims.py resolve <tenant> <alert_id> --outcome released --actor <you> --reason "<how you confirmed it>" --yes`
   - Block **DID** land — mark done, never retry:
     `python3 scripts/setup/ai_agent/manage_stuck_claims.py resolve <tenant> <alert_id> --outcome resolved --actor <you> --reason "<how you confirmed it>" --yes`

The tool never deletes a claim doc — `agent_checkpoints`'s ES role has no
delete privilege (#245), by design. It also refuses a claim younger than
`--max-age-min` (default 30, same as `list`) unless `--force` is given — it
may still be genuinely in flight. Omit `--yes` to preview the transition
without applying it.

**Known gap (security-auditor round-2 MEDIUM), not yet closed:** the
`resolved_by`/`resolution_reason`/etc. attribution above lives only on the
claim doc itself, writable by the same credential that wrote it — not a
tamper-evident record. A durable copy needs its own append-only-role
credential (same pattern as `hive_mind_broker`'s `BROKER_AUDIT_PASSWORD`),
plus an alert on `resolution_source: "manual"` appearing at all, since a
manual override of this pipeline's at-most-once guarantee should page, not
sit silently. Tracked as a follow-up.

**Router firewall prerequisite for #278's idempotent blocking (one-time,
per router):** the dispatcher now manages set MEMBERSHIP
(`nft add element inet fw4 hivemind_blocklist { <ip> }`), not standalone
drop rules — the set itself, and a rule referencing it, must already exist
in the router's base `fw4` config. **This must be persisted through fw4's
UCI include mechanism, not applied as a one-off runtime command** — bare
`nft add set`/`nft insert rule` are lost on the next `fw4 reload` (any UCI
firewall commit, an interface event, a service restart) or reboot, silently
disabling every future block with no error.

1. Write the set and rule to an include file, e.g.
   `/etc/nftables.d/10-hivemind-blocklist.nft`:
   ```
   add set inet fw4 hivemind_blocklist { type ipv4_addr }
   insert rule inet fw4 input ip saddr @hivemind_blocklist drop
   ```
   (No `flags interval` — the dispatcher only ever adds single addresses,
   never ranges, and dropping the flag sidesteps nftables' version-dependent
   handling of duplicate/overlapping elements on interval sets — see the
   idempotency verification step below.)
2. Reference it from `/etc/config/firewall` via a `config include` section
   (`option type nftables`, `option path
   '/etc/nftables.d/10-hivemind-blocklist.nft'`) so `fw4 reload` re-applies
   it every time. **Verify the exact UCI include stanza syntax against the
   fleet's actual OpenWrt/fw4 version before rolling this out** — it is
   version-sensitive and untested against the deployed fleet as of this
   writing (tracked as a tester-debugger follow-up, together with confirming
   `nft add element` idempotency and `nft get element` support on the
   deployed nft version — see Finding 5/10 in the #278 security review).
3. Confirm the set definition survives: `fw4 reload && nft list set inet
   fw4 hivemind_blocklist` should succeed (not error "no such set").

**Known limitation (security-auditor round-2 MEDIUM): the set DEFINITION
persists across `fw4 reload`, but its MEMBERSHIP does not.** Every reload
re-creates `hivemind_blocklist` empty — any currently-blocked IP the
dispatcher had added at runtime is silently un-blocked, with no error on
either side, since `nft add element` is idempotent and no one re-adds it.
An empty set is therefore simultaneously "correctly provisioned, nothing
blocked yet" and "was blocking N IPs before the last reload" — step 3 above
cannot distinguish the two, and neither can anything else in this pipeline
today. There is no periodic reconciliation between the SOC's belief about
who is blocked and what a router's ruleset actually contains. Until one
exists (persisting elements into the include file at add-time, or a
broker-side job that re-issues `add element` for every active block — safe
precisely because the operation is idempotent), treat any router that has
had a firewall config change or reboot since a block was applied as
UNVERIFIED, and re-check via `manage_stuck_claims.py` / the stuck-claim SLO
metric rather than trusting the case-closed state.

# References and Resources
- `scripts/setup/docker-compose.ha.yml`
- `scripts/setup/restore_test.sh`
- `scripts/setup/stack_health.sh`
- `configs/systemd/stack-health.service` / `configs/systemd/stack-health.timer` (#555)
- `configs/monitoring/reliability.cron` (fallback for hosts without systemd)
- `configs/elasticsearch/roles/slo_metrics_reader.json` (the `soc-health` read grant)
- `configs/elasticsearch/roles/soc_health.json` (the self-health lane's own identity, #555)
- `scripts/setup/ai_agent/manage_stuck_claims.py` (#276)
- `scripts/hive-mind-broker/dispatcher.py` (#278)

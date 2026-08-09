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
The `stack_health.sh` script runs via cron every 5 minutes and pushes alerts to `ntfy` if any core component (Elasticsearch, Kibana, Logstash, broker, or agent) is down.

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
- `configs/monitoring/reliability.cron`
- `scripts/setup/ai_agent/manage_stuck_claims.py` (#276)
- `scripts/hive-mind-broker/dispatcher.py` (#278)

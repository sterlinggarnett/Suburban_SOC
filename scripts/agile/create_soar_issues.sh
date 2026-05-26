#!/bin/bash
# create_soar_issues.sh — creates all GitHub issues for the SOAR Quarantine Epic
# Repo: sterlinggarnett/Suburban_SOC
# Run from repo root: bash scripts/agile/create_soar_issues.sh

set -euo pipefail

REPO="sterlinggarnett/Suburban_SOC"
M5="Milestone 5: Advanced Features/Automation"
M6="Milestone 5: Advanced Features/Automation"
ASSIGNEE="voltron-1"
TMP=$(mktemp -d)

echo "=== Creating SOAR Quarantine Epic Issues ==="

# ─── M5: Phase A — MAC Enrichment User Story ────────────────────────────────
cat > "$TMP/us_m5.md" << 'EOF'
**Epic:** Automated Quarantine — SOAR Integration
**Milestone:** M5 — Threat Intelligence Integration
**Owner:** @voltron-1
**Priority:** HIGH

## User Story
As a SOC Analyst, I want Zeek to log Layer 2 MAC addresses alongside IPs in conn logs, so that infected devices can be identified and quarantined by hardware address (which persists across DHCP/IP changes).

## Acceptance Criteria
- [ ] `@load policy/protocols/conn/mac-logging` added to `configs/zeek/local.zeek`
- [ ] `logstash.conf` maps `orig_l2_addr` → `source.mac` and `resp_l2_addr` → `destination.mac`
- [ ] `source.mac` field visible in Kibana `zeek.conn` index

## Files Changed
- `configs/zeek/local.zeek` [NEW]
- `configs/logstash.conf` [MODIFIED]
EOF
echo "[M5] Creating User Story: MAC Address Enrichment..."
US_M5=$(gh issue create --repo "$REPO" \
  --title "[User Story] Enable MAC address enrichment in Zeek + Logstash pipeline" \
  --body-file "$TMP/us_m5.md" \
  --milestone "$M5" \
  --assignee "$ASSIGNEE" \
  --label "enhancement,user-story")
echo "Created: $US_M5"

# ─── M5: Task A.1 ────────────────────────────────────────────────────────────
cat > "$TMP/t_a1.md" << 'EOF'
**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 30 min

## Description
Create `configs/zeek/local.zeek` and load the `policy/protocols/conn/mac-logging` policy to emit `orig_l2_addr` and `resp_l2_addr` fields in conn logs.

## Acceptance Criteria
- [ ] `configs/zeek/local.zeek` created with correct load directives
- [ ] Zeek conn logs contain `orig_l2_addr` field on test capture
EOF
echo "[M5] Creating Task A.1: Zeek MAC logging config..."
T_A1=$(gh issue create --repo "$REPO" \
  --title "[Task] Add mac-logging policy to Zeek local.zeek" \
  --body-file "$TMP/t_a1.md" \
  --milestone "$M5" \
  --assignee "$ASSIGNEE" \
  --label "user-story")
echo "Created: $T_A1"

# ─── M5: Task A.2 ────────────────────────────────────────────────────────────
cat > "$TMP/t_a2.md" << 'EOF'
**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 20 min

## Description
Update the mutate/rename block in `configs/logstash.conf` to map Zeek MAC fields to ECS `source.mac` and `destination.mac` fields for Elasticsearch indexing.

## Acceptance Criteria
- [ ] `source.mac` field present in logstash-security-* index
- [ ] Kibana can filter/visualize by `source.mac`
EOF
echo "[M5] Creating Task A.2: Logstash MAC field mapping..."
T_A2=$(gh issue create --repo "$REPO" \
  --title "[Task] Map orig_l2_addr/resp_l2_addr to source.mac in logstash.conf" \
  --body-file "$TMP/t_a2.md" \
  --milestone "$M5" \
  --assignee "$ASSIGNEE" \
  --label "user-story")
echo "Created: $T_A2"

# ─── M6: Phase B — Kibana Alert User Story ───────────────────────────────────
cat > "$TMP/t_b1.md" << 'EOF'
**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 30 min

## Description
Create/update the Kibana Watcher rule in `rules/elastic_watcher/soar_quarantine_alert.json` to monitor `zeek.conn` for high-confidence IOC hits and include `source.mac` in the webhook payload sent to the AI agent.

## Acceptance Criteria
- [ ] Watcher rule targets `logstash-security-*` index
- [ ] Webhook payload includes both `source_ip` and `source_mac`
- [ ] Alert fires within 1 minute of IOC match
EOF
echo "[M6] Creating Task B.1: Kibana MAC-aware alert rule..."
T_B1=$(gh issue create --repo "$REPO" \
  --title "[Task] Update Kibana Watcher rule to include source.mac in webhook payload" \
  --body-file "$TMP/t_b1.md" \
  --milestone "$M6" \
  --assignee "$ASSIGNEE" \
  --label "user-story")
echo "Created: $T_B1"

# ─── M6: Phase C — Quarantine User Story ─────────────────────────────────────
cat > "$TMP/us_m6a.md" << 'EOF'
**Epic:** Automated Quarantine — SOAR Integration
**Milestone:** M6 — Proactive Kibana Alerting
**Owner:** @voltron-1
**Priority:** CRITICAL

## User Story
As a SOC Analyst, I want the system to automatically quarantine infected devices by MAC address the moment a high-confidence IOC is detected, so that ransomware or C2-communicating devices are isolated at machine-speed without manual intervention.

## Acceptance Criteria
- [ ] `scripts/setup/isolate.sh` executes uci MAC DROP rules on OpenWrt via SSH
- [ ] `agent_app.py` extracts `source_mac` from Kibana payload and calls `isolate.sh` with MAC
- [ ] Fallback to IP quarantine when MAC is unavailable
- [ ] Quarantine rule persists across router reboots (uci commit)

## Files Changed
- `scripts/setup/isolate.sh` [NEW]
- `scripts/setup/ai_agent/agent_app.py` [MODIFIED]
EOF
echo "[M6] Creating User Story: Automated MAC Quarantine..."
US_M6A=$(gh issue create --repo "$REPO" \
  --title "[User Story] Automated MAC-based device quarantine via OpenWrt uci" \
  --body-file "$TMP/us_m6a.md" \
  --milestone "$M6" \
  --assignee "$ASSIGNEE" \
  --label "enhancement,user-story")
echo "Created: $US_M6A"

# ─── M6: Task C.1 ─────────────────────────────────────────────────────────────
cat > "$TMP/t_c1.md" << 'EOF'
**Owner:** @voltron-1 | **Priority:** CRITICAL | **Time:** 45 min

## Description
Write a bash script at `scripts/setup/isolate.sh` that accepts a MAC address argument, SSHes into the OpenWrt router using the `id_ed25519_hivemind` key, and injects a persistent DROP rule targeting that MAC via uci.

## Acceptance Criteria
- [ ] Script validates MAC address format before executing
- [ ] uci rule named `SOAR_QUARANTINE_<MAC>` for traceability
- [ ] uci commit + firewall restart applied
- [ ] Script exits non-zero on SSH failure
EOF
echo "[M6] Creating Task C.1: isolate.sh quarantine script..."
T_C1=$(gh issue create --repo "$REPO" \
  --title "[Task] Write isolate.sh — OpenWrt uci MAC firewall rule injection" \
  --body-file "$TMP/t_c1.md" \
  --milestone "$M6" \
  --assignee "$ASSIGNEE" \
  --label "user-story")
echo "Created: $T_C1"

# ─── M6: Task C.2 + D combined ────────────────────────────────────────────────
cat > "$TMP/t_cd.md" << 'EOF'
**Owner:** @voltron-1 | **Priority:** CRITICAL | **Time:** 60 min

## Description
Update `scripts/setup/ai_agent/agent_app.py` to:
1. Extract `source_mac` from Kibana webhook payload
2. Pass MAC to `isolate.sh` instead of IP (with IP fallback)
3. Add `send_discord_alert()` function for rich SOC embed notifications
4. Fire Discord embed on critical quarantine events

## Acceptance Criteria
- [ ] `source_mac` extracted from payload with graceful IP fallback
- [ ] `isolate.sh` called with MAC as primary argument
- [ ] `send_discord_alert()` posts rich embed to SOC Discord channel
- [ ] `DISCORD_WEBHOOK_URL` env var controls destination (no-op if unset)
EOF
echo "[M6] Creating Task C.2+D: Update agent_app.py..."
T_CD=$(gh issue create --repo "$REPO" \
  --title "[Task] Update agent_app.py — MAC quarantine + Discord SOC notification" \
  --body-file "$TMP/t_cd.md" \
  --milestone "$M6" \
  --assignee "$ASSIGNEE" \
  --label "user-story")
echo "Created: $T_CD"

# ─── M6: Phase D — Discord User Story ────────────────────────────────────────
cat > "$TMP/us_m6b.md" << 'EOF'
**Epic:** Automated Quarantine — SOAR Integration
**Milestone:** M6 — Proactive Kibana Alerting
**Owner:** @voltron-1
**Priority:** MEDIUM

## User Story
As a SOC Analyst, I want to receive a Discord embed notification when a device is automatically quarantined, including device IP, MAC, threat reason, and AI analysis, so I have immediate situational awareness without checking the dashboard.

## Acceptance Criteria
- [ ] `send_discord_alert()` function added to `agent_app.py`
- [ ] Discord embed fires on critical quarantine events
- [ ] `DISCORD_WEBHOOK_URL` env var controls the destination
- [ ] Graceful no-op if env var is not set

## Files Changed
- `scripts/setup/ai_agent/agent_app.py` [MODIFIED]
EOF
echo "[M6] Creating User Story: Discord SOC notification..."
US_M6B=$(gh issue create --repo "$REPO" \
  --title "[User Story] Discord SOC channel notification on device quarantine" \
  --body-file "$TMP/us_m6b.md" \
  --milestone "$M6" \
  --assignee "$ASSIGNEE" \
  --label "enhancement,user-story")
echo "Created: $US_M6B"

rm -rf "$TMP"
echo ""
echo "=== All SOAR Quarantine issues created successfully! ==="

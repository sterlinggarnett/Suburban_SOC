## GitHub Issues Script — SOAR Quarantine Epic
## Milestone 5: Advanced Features/Automation (#9)
## Milestone 6: Presentation (#10)
## Repo: voltron-1/Suburban-SOC

$repo = "voltron-1/Suburban-SOC"
$m5   = "Milestone 5: Advanced Features/Automation"
$m6   = "Milestone 6: Presentation"

Write-Host "=== Creating SOAR Quarantine Epic Issues ==="

# ─── MILESTONE 5 ────────────────────────────────────────────────────────────
Write-Host "`n[M5] Creating User Story: MAC Address Enrichment..."
$us_m5 = gh issue create --repo $repo `
  --title "[User Story] Enable MAC address enrichment in Zeek + Logstash pipeline" `
  --body "**Epic:** Automated Quarantine — SOAR Integration`n**Milestone:** M5 — Threat Intelligence Integration`n**Owner:** @voltron-1`n**Priority:** HIGH`n`n## User Story`nAs a SOC Analyst, I want Zeek to log Layer 2 MAC addresses alongside IPs in conn logs, so that infected devices can be identified and quarantined by hardware address (which persists across DHCP/IP changes).`n`n## Acceptance Criteria`n- [ ] ``@load policy/protocols/conn/mac-logging`` added to ``configs/zeek/local.zeek```n- [ ] ``logstash.conf`` maps ``orig_l2_addr`` → ``source.mac`` and ``resp_l2_addr`` → ``destination.mac```n- [ ] ``source.mac`` field visible in Kibana ``zeek.conn`` index`n`n## Files Changed`n- ``configs/zeek/local.zeek`` [NEW]`n- ``configs/logstash.conf`` [MODIFIED]" `
  --milestone $m5 `
  --assignee "voltron-1" `
  --label "enhancement,user-story"
Write-Host "Created: $us_m5"

Write-Host "`n[M5] Creating Task: Zeek MAC logging config..."
$t_a1 = gh issue create --repo $repo `
  --title "[Task] Add mac-logging policy to Zeek local.zeek" `
  --body "**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 30 min`n`n## Description`nCreate ``configs/zeek/local.zeek`` and load the ``policy/protocols/conn/mac-logging`` policy to emit ``orig_l2_addr`` and ``resp_l2_addr`` fields in conn logs.`n`n## Acceptance Criteria`n- [ ] ``configs/zeek/local.zeek`` created with correct load directives`n- [ ] Zeek conn logs contain ``orig_l2_addr`` field on test capture" `
  --milestone $m5 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host "Created: $t_a1"

Write-Host "`n[M5] Creating Task: Logstash MAC field mapping..."
$t_a2 = gh issue create --repo $repo `
  --title "[Task] Map orig_l2_addr/resp_l2_addr to source.mac in logstash.conf" `
  --body "**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 20 min`n`n## Description`nUpdate the mutate/rename block in ``configs/logstash.conf`` to map Zeek MAC fields to ECS ``source.mac`` and ``destination.mac`` fields for Elasticsearch indexing.`n`n## Acceptance Criteria`n- [ ] ``source.mac`` field present in logstash-security-* index`n- [ ] Kibana can filter/visualize by ``source.mac``" `
  --milestone $m5 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host "Created: $t_a2"

# ─── MILESTONE 6 ────────────────────────────────────────────────────────────
Write-Host "`n[M6] Creating User Story: Automated MAC Quarantine via OpenWrt..."
$us_m6a = gh issue create --repo $repo `
  --title "[User Story] Automated MAC-based device quarantine via OpenWrt uci" `
  --body "**Epic:** Automated Quarantine — SOAR Integration`n**Milestone:** M6 — Proactive Kibana Alerting`n**Owner:** @voltron-1`n**Priority:** CRITICAL`n`n## User Story`nAs a SOC Analyst, I want the system to automatically quarantine infected devices by MAC address the moment a high-confidence IOC is detected, so that ransomware or C2-communicating devices are isolated at machine-speed without manual intervention.`n`n## Acceptance Criteria`n- [ ] ``scripts/setup/isolate.sh`` executes uci MAC DROP rules on OpenWrt via SSH`n- [ ] ``agent_app.py`` extracts ``source_mac`` from Kibana payload and calls ``isolate.sh`` with MAC`n- [ ] Fallback to IP quarantine when MAC is unavailable`n- [ ] Quarantine rule persists across router reboots (uci commit)`n`n## Files Changed`n- ``scripts/setup/isolate.sh`` [NEW]`n- ``scripts/setup/ai_agent/agent_app.py`` [MODIFIED]" `
  --milestone $m6 `
  --assignee "voltron-1" `
  --label "enhancement,user-story"
Write-Host "Created: $us_m6a"

Write-Host "`n[M6] Creating User Story: Discord SOC quarantine notification..."
$us_m6b = gh issue create --repo $repo `
  --title "[User Story] Discord SOC channel notification on device quarantine" `
  --body "**Epic:** Automated Quarantine — SOAR Integration`n**Milestone:** M6 — Proactive Kibana Alerting`n**Owner:** @voltron-1`n**Priority:** MEDIUM`n`n## User Story`nAs a SOC Analyst, I want to receive a Discord embed notification when a device is automatically quarantined, including device IP, MAC, threat reason, and AI analysis, so I have immediate situational awareness without checking the dashboard.`n`n## Acceptance Criteria`n- [ ] ``send_discord_alert()`` function added to ``agent_app.py```n- [ ] Discord embed fires on critical quarantine events`n- [ ] ``DISCORD_WEBHOOK_URL`` env var controls the destination`n- [ ] Graceful no-op if env var is not set`n`n## Files Changed`n- ``scripts/setup/ai_agent/agent_app.py`` [MODIFIED]" `
  --milestone $m6 `
  --assignee "voltron-1" `
  --label "enhancement,user-story"
Write-Host "Created: $us_m6b"

Write-Host "`n[M6] Creating Task: Write isolate.sh quarantine script..."
$t_c1 = gh issue create --repo $repo `
  --title "[Task] Write isolate.sh — OpenWrt uci MAC firewall rule injection" `
  --body "**Owner:** @voltron-1 | **Priority:** CRITICAL | **Time:** 45 min`n`n## Description`nWrite a bash script at ``scripts/setup/isolate.sh`` that accepts a MAC address argument, SSHes into the OpenWrt router using the ``id_ed25519_hivemind`` key, and injects a persistent DROP rule targeting that MAC via uci.`n`n## Acceptance Criteria`n- [ ] Script validates MAC address format before executing`n- [ ] uci rule named ``SOAR_QUARANTINE_<MAC>`` for traceability`n- [ ] uci commit + firewall restart applied`n- [ ] Script exits non-zero on SSH failure" `
  --milestone $m6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host "Created: $t_c1"

Write-Host "`n[M6] Creating Task: Update agent_app.py for MAC quarantine + Discord..."
$t_cd = gh issue create --repo $repo `
  --title "[Task] Update agent_app.py — MAC quarantine + Discord notification" `
  --body "**Owner:** @voltron-1 | **Priority:** CRITICAL | **Time:** 60 min`n`n## Description`nUpdate ``scripts/setup/ai_agent/agent_app.py`` to: (1) extract ``source_mac`` from Kibana webhook payload, (2) pass MAC to isolate.sh instead of IP, (3) add ``send_discord_alert()`` function, (4) fire Discord embed on critical quarantine events.`n`n## Acceptance Criteria`n- [ ] ``source_mac`` extracted from payload with graceful fallback`n- [ ] ``isolate.sh`` called with MAC as primary argument`n- [ ] ``send_discord_alert()`` posts rich embed to SOC Discord channel`n- [ ] ``DISCORD_WEBHOOK_URL`` env var controls destination (no-op if unset)" `
  --milestone $m6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host "Created: $t_cd"

Write-Host "`n[M6] Creating Task: Kibana MAC-aware alert rule..."
$t_b1 = gh issue create --repo $repo `
  --title "[Task] Update Kibana Watcher rule to include source.mac in webhook payload" `
  --body "**Owner:** @voltron-1 | **Priority:** HIGH | **Time:** 30 min`n`n## Description`nCreate/update the Kibana Watcher rule in ``rules/elastic_watcher/soar_quarantine_alert.json`` to monitor ``zeek.conn`` for high-confidence IOC hits and include ``source.mac`` in the webhook payload sent to the AI agent.`n`n## Acceptance Criteria`n- [ ] Watcher rule targets ``logstash-security-*`` index`n- [ ] Webhook payload includes both ``source_ip`` and ``source_mac```n- [ ] Alert fires within 1 minute of IOC match" `
  --milestone $m6 `
  --assignee "voltron-1" `
  --label "user-story"
Write-Host "Created: $t_b1"

Write-Host "`n=== All SOAR Quarantine issues created! ==="

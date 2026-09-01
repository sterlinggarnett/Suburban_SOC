# Suburban-SOC :: Emulation -> Detection Coverage Checklist

Three lanes, 33 emulation->detection pairs. `[x]` = wiring validated by `validate_emulation_map.py`; operational/live-fire steps are unchecked.

## Network / Linux lane (Zeek)

- [x] **RECONNAISSANCE** (T1046) — `sim_portscan.sh` -> `net_zeek_port_scan.yml`
- [x] ⚠️ **EXPLOITATION_UNVERIFIED** (T1105) — `sim_malware_download.sh` -> `net_zeek_executable_download.yml`
      ⚠️ **#383: structurally wired, confirmed NOT to produce matching telemetry.**
      `[x]` above means `validate_emulation_map.py`'s file-existence/tag-match
      check passes — it does not mean this loop live-fires. The default sample
      (EICAR over HTTPS) never reaches Zeek's file-analysis framework at all,
      and its documented plaintext-HTTP fallback types as `application/zip`,
      which this rule's `mime_type` list has never included. The RULE itself
      is verified (tests/detections/test_live_fire.py fires it against a real
      ES; #365 live-verified every mime_type against the pinned Zeek image) —
      only the emulation payload is wrong. See
      `net_zeek_executable_download.yml`'s own description and
      `configs/detections/emulation_telemetry.map`'s EXPLOITATION_UNVERIFIED
      section.
- [x] **CREDENTIAL_ACCESS_SSH** (T1110) — `sim_brute_ssh.sh` -> `net_zeek_ssh_bruteforce.yml`
- [x] **CREDENTIAL_ACCESS_SSH_CADENCE** (T1110) — `sim_brute_ssh.sh` -> `net_zeek_ssh_session_cadence.yml`
- [x] ⚠️ **CREDENTIAL_ACCESS_SSH_CADENCE_SUSTAINED** (T1110) — `sim_brute_ssh.sh` -> `net_zeek_ssh_session_cadence_sustained.yml`
      ⚠️ **#392: `sim_brute_ssh.sh`'s default (5 attempts) does NOT exercise
      this rule** (threshold.value:15) — needs an explicit
      `BRUTE_PASSWORDS` override (20+ words, not just 15 — a bare 15
      reintroduces the zero-margin defect this same caveat warns about
      elsewhere) AND `TARGET_HOST` pointed at a real capture-path host
      (the documented default, 127.0.0.1, is invisible to every real
      capture path in this repo). See
      `configs/detections/emulation_telemetry.map`'s
      CREDENTIAL_ACCESS_SSH_CADENCE_SUSTAINED section for the exact
      command.
- [x] ⚠️ **EXFILTRATION_OUTBOUND_VOLUME_ASYMMETRY** (T1048) — `sim_outbound_volume_asymmetry.sh` -> `net_zeek_conn_outbound_volume_asymmetry.yml`
      ⚠️ Requires a listener already running on `TARGET_HOST` (the sim does
      not stand one up itself — same convention as `sim_brute_ssh.sh`
      needing real SSH on the target) and a real capture-path host (not
      loopback). A single run produces one asymmetric flow, which is
      expected and not itself alerted on — the paired threshold rule
      (`rules/elastic/threshold/net-zeek-conn-outbound-volume-asymmetry.ndjson`)
      is the deployed enforcement and needs 3+ runs within a 30-minute
      window from the same source. See
      `configs/detections/emulation_telemetry.map`'s
      EXFILTRATION_OUTBOUND_VOLUME_ASYMMETRY section for the exact command.

Operational to-dos (Linux lane):
- [ ] `chmod +x tests/anomaly_simulation/sim_portscan.sh`
- [x] Load Zeek scan-detection policy alongside `config.zeek` — not via
      `local.zeek` (dead config, unused by any real capture path since #286);
      wired as `scan-detection.zeek` (a custom reimplementation; modern Zeek
      dropped `policy/misc/scan`) in `scripts/setup/stream_capture.sh` and
      `configs/systemd/zeek-host-capture.service`
- [x] Load `policy/protocols/ssh/detect-bruteforcing` alongside `config.zeek`
      in the same two real capture entry points (#261)
- [ ] Confirm Filebeat ships Zeek `files.log`
- [ ] Live-fire: run each sim, confirm the Zeek notice fires and the rule matches

## Linux endpoint lane (auditd execve, #442)

⚠️ None of these 5 have been live-verified against a real auditd stream in
the environment they were written in — see #442's own disclosed caveats
(not exercised against live auditd; the Logstash `aggregate` filter's
pipeline-worker-affinity requirement). `[x]` below means
`validate_emulation_map.py`'s wiring check passes, same as every other lane
— it does not mean this has live-fired.

- [x] **EXECUTION_LNX_REVERSE_SHELL** (T1059.004) — `sim_lnx_reverse_shell.sh` -> `proc_creation_lnx_reverse_shell_interpreter.yml`
- [x] **COMMAND_AND_CONTROL_LNX_INGRESS_TRANSFER** (T1105) — `sim_lnx_ingress_tool_transfer.sh` -> `proc_creation_lnx_ingress_tool_transfer.yml`
- [x] ⚠️ **PERSISTENCE_LNX_CRON_AT** (T1053.003) — `sim_lnx_cron_at_persistence.sh` -> `proc_creation_lnx_cron_at_persistence.yml`
      ⚠️ The cron.d-write branch needs passwordless sudo and the at branch
      needs `at` installed — both skipped (not failed) if unavailable; the
      crontab branch (no root needed) always runs regardless.
- [x] **DEFENSE_EVASION_LNX_HISTORY_TAMPER** (T1070.003) — `sim_lnx_shell_history_tamper.sh` -> `proc_creation_lnx_shell_history_tamper.yml`
- [x] ⚠️ **PERSISTENCE_LNX_SYSTEMD** (T1543.002) — `sim_lnx_systemd_service_persistence.sh` -> `proc_creation_lnx_systemd_service_persistence.yml`
      ⚠️ Needs passwordless sudo (systemd unit persistence requires root) —
      the whole sim is skipped, not failed, if unavailable.

Operational to-dos (Linux endpoint lane):
- [ ] Deploy `configs/endpoint/audit.rules` + `filebeat_endpoint.yml`'s
      `audit-logs` input to a real Linux test host (#442)
- [ ] Confirm `auditd.conf`'s `log_format = ENRICHED` is set (needed for
      `user.name` resolution — see `audit.rules`' own header)
- [ ] Live-fire: run each sim, confirm auditd + Filebeat + Logstash produce
      a correlated `event.dataset:auditd.execve` document and the rule matches

## Windows endpoint lane (Sysmon / 4688)

- [x] **DELIVERY_BITSADMIN** (T1105) — `sim_win_bitsadmin_download.ps1` -> `proc_creation_win_bitsadmin_download.yml`
- [x] **DEFENSE_EVASION_CERTUTIL** (T1140) — `sim_win_certutil_decode.ps1` -> `proc_creation_win_certutil_decode.yml`
- [x] **DEFENSE_EVASION_CLEAR_LOGS** (T1070.001) — `sim_win_clear_event_logs.ps1` -> `proc_creation_win_clear_event_logs.yml`  ⚠ destructive in armed mode
- [x] **DEFENSE_EVASION_DEFENDER_TAMPER** (T1562.001) — `sim_win_defender_tamper.ps1` -> `proc_creation_win_defender_tamper.yml`  ⚠ destructive in armed mode
- [x] **DISCOVERY_DOMAIN_GROUPS** (T1069.002) — `sim_win_domain_group_discovery.ps1` -> `proc_creation_win_domain_group_discovery.yml`
- [x] **PERSISTENCE_LOCAL_ACCOUNT** (T1136.001) — `sim_win_local_acct_create.ps1` -> `proc_creation_win_local_acct_create.yml`
- [x] **CREDENTIAL_ACCESS_LSASS** (T1003.001) — `sim_win_lsass_dump.ps1` -> `proc_creation_win_lsass_dump.yml`  ⚠ destructive in armed mode
- [x] **DEFENSE_EVASION_MSHTA** (T1218.005) — `sim_win_mshta_remote.ps1` -> `proc_creation_win_mshta_remote.yml`
- [x] **DISCOVERY_DOMAIN_TRUST** (T1018) — `sim_win_nltest_discovery.ps1` -> `proc_creation_win_nltest_discovery.yml`
- [x] **EXECUTION_POWERSHELL_ENCODED** (T1059.001) — `sim_win_powershell_encoded.ps1` -> `proc_creation_win_powershell_encoded.yml`
- [x] **LATERAL_MOVEMENT_RDP_HIJACK** (T1563.002) — `sim_win_rdp_hijack_tscon.ps1` -> `proc_creation_win_rdp_hijack_tscon.yml`  ⚠ destructive in armed mode
- [x] **CREDENTIAL_ACCESS_SAM** (T1003.002) — `sim_win_reg_save_sam.ps1` -> `proc_creation_win_reg_save_sam.yml`  ⚠ destructive in armed mode
- [x] **DEFENSE_EVASION_REGSVR32** (T1218.010) — `sim_win_regsvr32_remote_sct.ps1` -> `proc_creation_win_regsvr32_remote_sct.yml`
- [x] **PERSISTENCE_RUN_KEY** (T1547.001) — `sim_win_run_key_persistence.ps1` -> `proc_creation_win_run_key_persistence.yml`
- [x] **PERSISTENCE_SCHEDULED_TASK** (T1053.005) — `sim_win_scheduled_task.ps1` -> `proc_creation_win_scheduled_task.yml`
- [x] **PERSISTENCE_SERVICE_CREATION** (T1543.003) — `sim_win_service_creation_sc.ps1` -> `proc_creation_win_service_creation_sc.yml`
- [x] **DISCOVERY_USER** (T1033) — `sim_win_user_discovery.ps1` -> `proc_creation_win_user_discovery.yml`
- [x] **IMPACT_DELETE_SHADOWS** (T1490) — `sim_win_vss_delete_shadows.ps1` -> `proc_creation_win_vss_delete_shadows.yml`  ⚠ destructive in armed mode
- [x] **EXECUTION_WMI** (T1047) — `sim_win_wmi_process_create.ps1` -> `proc_creation_win_wmi_process_create.yml`
- [x] **COLLECTION_CLIPBOARD** (T1115) — `sim_win_clipboard_capture.ps1` -> `posh_ps_clipboard_capture.yml`
- [x] **COLLECTION_LOCAL_DATA_STAGING** (T1074.001) — `sim_win_local_data_staging.ps1` -> `proc_creation_win_local_data_staging.yml`
- [x] ⚠️ **COLLECTION_ARCHIVE_STAGING_NON_RAR** (T1560.001) — `sim_win_archive_staging_non_rar.ps1` -> `proc_creation_win_archive_staging_non_rar.yml`
      ⚠️ The sim's 7z branch is skipped (not failed) when `7z.exe` isn't
      installed on the test host — the makecab branch (bundled on every
      Windows host) always runs regardless, so the sim still exercises the
      rule either way.

Operational to-dos (Windows lane):
- [ ] Deploy the `.ps1` sims to a Windows test host (`chmod +x` so the validator's exec-bit check passes on Linux)
- [ ] Confirm Sysmon + winlogbeat ship process-creation events (Sysmon EID 1 / Security 4688)
- [ ] Review the 6 ⚠ scripts before using `-Armed` (LSASS, SAM, shadow delete, Defender, clear logs, RDP hijack)
- [ ] Live-fire each sim on an isolated host; confirm the proc_creation rule matches

## Suricata signature lane (M23, #443-#446)

Not an emulation->detection lane like the three above — Suricata is
signature-based IDS, not process/auth telemetry — tracked here for the
same disclose-what's-real-vs-not reasons.

- [x] **#443/#444** — sensor deployment (host-package, IDS/EVE mode) +
      `eve.json` → ECS ingest. Real `suricata -T` verified locally against
      the exact production config; no live capture host, no live traffic,
      CPU headroom alongside Zeek unmeasured, reboot survival unconfirmed.
- [x] **#445** — CI lane: syntax gate (`lint.yml`), SID registry, pcap-
      replay promotion gate (`tests/detections/test_suricata_rules.py`).
      Real `suricata` binary + real `scapy`-built pcaps in CI, not mocked
      — see `docs/detections/suricata-ci-lane.md`. ATT&CK coverage
      accounting explicitly scoped out for now
      (`findings/20260830-445-suricata-attack-coverage-scope.md`).
- [x] **#446** — landed the 100-rule university starter set as
      `rules/suricata/` (10 category files), all disabled until tuned.
      Re-supplied by the repo owner after the first attempt's source file
      was lost to a prior session's ephemeral scratchpad. 8 rules needed
      a Suricata-7.0.3 syntax compatibility fix (verified by hand, see
      `docs/detections/suricata-starter-set.md`) before they'd even
      parse — caught by extending the CI lane's syntax gate to validate
      disabled rules too (Suricata's loader otherwise silently skips
      `#`-commented lines, so it would never have caught this). 3
      placeholders (9000013 look-alike domain, 9000065 student-ID format,
      9000099 C2 domain fragment) left exactly as supplied per this
      repo's own never-invent-an-IOC convention. Full reconciliation
      against existing Sigma coverage, genuine-gap inventory, and DLP
      sign-off flag in `docs/detections/suricata-starter-set.md`.
- [x] **#446 follow-up (2026-09-01)** — 31 of the 100 rules promoted to
      enabled: each got a real, verified pcap fixture (`suricata -r`
      replay against real Suricata 7.0.3 + real `scapy`-built packets,
      not a hand-authored pcap taken on faith) — 9000021-9000040
      (web_lms_attacks + web_shell_compromise, 20 rules), 9000049,
      9000051, 9000052, 9000091-9000098 (11 rules across
      iot_lab_research/residential_policy_violations/ransomware_c2). Full
      per-rule detail in `docs/detections/suricata-starter-set.md`'s
      "Rules promoted" section. These were the rules with no placeholder
      to resolve and no `detection_filter` to tune — the other 69 need
      the same one-at-a-time fixture work, not a different decision.

Operational to-dos (Suricata lane):
- [ ] Deploy `suricata-host-capture.service` to a real capture host
      alongside Zeek; measure CPU headroom
- [ ] Confirm Filebeat ships `eve.json` and Logstash's Category 0b branch
      populates `rule.*`/`threat.technique.id` as designed
- [ ] Per-rule pcap fixtures for the remaining 69 rules — nothing enters
      the enabled set without one (#445's promotion gate); 31/100 done
- [ ] Resolve the 3 remaining placeholders (9000013/9000065/9000099) with
      real institutional/threat-intel values before those specific rules
      are ever enabled
- [ ] Obtain explicit data-handling-policy owner sign-off before enabling
      the DLP rules (9000065/9000066)
- [ ] Tune every remaining `detection_filter` count/seconds value against
      measured traffic — the shipped values are the source's own
      illustrative defaults, not a baseline for this deployment

## Global
- [ ] `python3 tests/validate_emulation_map.py` returns 0 fail
- [x] Map emulation->detection pairs to [compliance_matrix.md](docs/compliance_matrix.md)
- [ ] Commit map + new rules + sims together

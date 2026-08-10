# Suburban-SOC :: Emulation -> Detection Coverage Checklist

Two lanes, 22 emulation->detection pairs. `[x]` = wiring validated by `validate_emulation_map.py`; operational/live-fire steps are unchecked.

## Network / Linux lane (Zeek)

- [x] **RECONNAISSANCE** (T1046) — `sim_portscan.sh` -> `net_zeek_port_scan.yml`
- [x] **EXPLOITATION** (T1105) — `sim_malware_download.sh` -> `net_zeek_executable_download.yml`
- [x] **CREDENTIAL_ACCESS_SSH** (T1110) — `sim_brute_ssh.sh` -> `net_zeek_ssh_bruteforce.yml`

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

## Windows endpoint lane (Sysmon / 4688)

- [x] **DELIVERY_BITSADMIN** (T1105) — `sim_win_bitsadmin_download.ps1` -> `proc_creation_win_bitsadmin_download.yml`
- [x] **DEFENSE_EVASION_CERTUTIL** (T1140) — `sim_win_certutil_decode.ps1` -> `proc_creation_win_certutil_decode.yml`
- [x] **DEFENSE_EVASION_CLEAR_LOGS** (T1070.001) — `sim_win_clear_event_logs.ps1` -> `proc_creation_win_clear_event_logs.yml`  ⚠ destructive in armed mode
- [x] **DEFENSE_EVASION_DEFENDER_TAMPER** (T1562.001) — `sim_win_defender_tamper.ps1` -> `proc_creation_win_defender_tamper.yml`  ⚠ destructive in armed mode
- [x] **DISCOVERY_DOMAIN_GROUPS** (T1069.002) — `sim_win_domain_group_discovery.ps1` -> `proc_creation_win_domain_group_discovery.yml`
- [x] **PERSISTENCE_LOCAL_ACCOUNT** (T1136.001) — `sim_win_local_acct_create.ps1` -> `proc_creation_win_local_acct_create.yml`
- [x] **CREDENTIAL_ACCESS_LSASS** (T1003.001) — `sim_win_lsass_dump.ps1` -> `proc_creation_win_lsass_dump.yml`  ⚠ destructive in armed mode
- [x] **DEFENSE_EVASION_MSHTA** (T1218.005) — `sim_win_mshta_remote.ps1` -> `proc_creation_win_mshta_remote.yml`
- [x] **DISCOVERY_DOMAIN_TRUST** (T1482) — `sim_win_nltest_discovery.ps1` -> `proc_creation_win_nltest_discovery.yml`
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

Operational to-dos (Windows lane):
- [ ] Deploy the `.ps1` sims to a Windows test host (`chmod +x` so the validator's exec-bit check passes on Linux)
- [ ] Confirm Sysmon + winlogbeat ship process-creation events (Sysmon EID 1 / Security 4688)
- [ ] Review the 6 ⚠ scripts before using `-Armed` (LSASS, SAM, shadow delete, Defender, clear logs, RDP hijack)
- [ ] Live-fire each sim on an isolated host; confirm the proc_creation rule matches

## Global
- [ ] `python3 tests/validate_emulation_map.py` returns 0 fail
- [x] Map emulation->detection pairs to [compliance_matrix.md](docs/compliance_matrix.md)
- [ ] Commit map + new rules + sims together

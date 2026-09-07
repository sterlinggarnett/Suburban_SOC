# Compliance Mapping Matrix

This matrix comprehensively maps Suburban-SOC's Sigma rules, Zeek/Filebeat telemetry, and existing SOPs against core compliance frameworks (NIST CSF 2.0, NIST 800-171 / 800-53 Rev.5, and CIS Controls v8).

## 1. Identity, Access, & Credential Protection

| Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|
| **NIST CSF PR.AC-1** | Access to systems and assets is controlled | `proc_creation_win_local_acct_create.yml` | SOP-009-rbac.md |
| **NIST CSF PR.AC-6** | Identities are proofed and bound | `auth_win_explicit_cred_account_sweep.yml` | SOP-009-rbac.md |
| **NIST 800-53 AC-2** | Account Management | `auth_win_priv_group_membership_change.yml` | SOP-009-rbac.md |
| **NIST 800-171 3.1.1** | Limit system access | `net_zeek_ssh_bruteforce.yml`, `auth_win_bruteforce_failed_logons.yml` | IR_Sigma_Playbook.md |
| **CIS Control 5** | Account Management | `auth_win_bruteforce_source_spray.yml` | SOP-009-rbac.md |
| **CIS Control 6** | Access Control Management | `auth_win_sedebug_special_logon.yml` | SOP-009-rbac.md |
| **NIST 800-53 SC-8** | Transmission Confidentiality | `proc_creation_win_lsass_dump.yml`, `proc_creation_win_reg_save_sam.yml` | SOP-012-privacy-data-handling.md |

## 2. Audit, Accountability, & Logging

| Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|
| **NIST CSF PR.PT-1** | Audit/log records are determined and implemented | Zeek logs, Sysmon EID 1, Filebeat pipeline | SOP-010-audit-trail.md |
| **NIST 800-53 AU-2** | Event Logging | `auth_win_security_log_cleared.yml` | SOP-010-audit-trail.md |
| **NIST 800-53 AU-3** | Content of Audit Records | `system_win_eventlog_cleared.yml` | SOP-010-audit-trail.md |
| **NIST 800-171 3.3.1** | Create and retain system audit logs | `proc_creation_win_clear_event_logs.yml` | SOP-010-audit-trail.md |
| **CIS Control 8** | Audit Log Management | `system_win_eventlog_service_tamper.yml` | SOP-010-audit-trail.md |

## 3. Configuration & Asset Management

| Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|
| **NIST CSF ID.AM-1** | Hardware/Software inventories are maintained | `proc_creation_win_domain_group_discovery.yml` | SOP-007-change-management.md |
| **NIST 800-53 CM-2** | Baseline Configuration | `proc_creation_win_nltest_discovery.yml` | SOP-007-change-management.md |
| **NIST 800-171 3.4.1** | Establish and maintain baselines | `proc_creation_win_user_discovery.yml` | SOP-007-change-management.md |
| **CIS Control 4** | Secure Configuration of Enterprise Assets | `system_win_service_installed.yml`, `proc_creation_win_service_creation_sc.yml` | SOP-007-change-management.md |
| **CIS Control 1** | Inventory and Control of Enterprise Assets | `net_zeek_port_scan.yml` | SOP-007-change-management.md |

## 4. Incident Response & Threat Detection

| Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|
| **NIST CSF RS.MI-1** | Incidents are contained and mitigated | `proc_creation_win_defender_tamper.yml` | IR_Sigma_Playbook.md |
| **NIST CSF DE.CM-1** | Networks and environments are monitored | `proc_creation_win_bitsadmin_download.yml` | IR_Sigma_Playbook.md |
| **NIST CSF DE.CM-4** | Malicious code is detected | `net_zeek_executable_download.yml`, `proc_creation_win_powershell_encoded.yml` | IR_Sigma_Playbook.md |
| **NIST 800-53 IR-4** | Incident Handling | `proc_creation_win_mshta_remote.yml`, `proc_creation_win_regsvr32_remote_sct.yml` | IR_Sigma_Playbook.md |
| **NIST 800-53 SI-4** | Information System Monitoring | `posh_ps_obfuscated_scriptblock.yml`, `wmi_win_event_subscription_binding.yml`, `system_lnx_self_health_unit_failed.yml`, `system_lnx_ca_fingerprint_mismatch.yml` | IR_Sigma_Playbook.md, SOP-005-reliability.md |
| **NIST 800-171 3.14.2**| Provide protection from malicious code | `proc_creation_win_certutil_decode.yml` | IR_Sigma_Playbook.md |
| **CIS Control 17** | Incident Response Management | `proc_creation_win_lateral_tool_parent.yml`, `proc_creation_win_rdp_hijack_tscon.yml` | IR_Sigma_Playbook.md |
| **CIS Control 13** | Network Monitoring and Defense | `proc_creation_win_run_key_persistence.yml`, `proc_creation_win_scheduled_task.yml` | IR_Sigma_Playbook.md |

## 5. Data Recovery & Resilience

| Framework ID | Description | Telemetry / Sigma Rules | Related SOP / Playbook |
|---|---|---|---|
| **NIST CSF RC.RP-1** | Recovery plan is executed | `proc_creation_win_vss_delete_shadows.yml` | SOP-008-dr-plan.md |
| **NIST 800-53 CP-9** | Information System Backup | Volume Shadow Copy deletion tracking | SOP-008-dr-plan.md |
| **CIS Control 11** | Data Recovery | `proc_creation_win_vss_delete_shadows.yml` | SOP-008-dr-plan.md |

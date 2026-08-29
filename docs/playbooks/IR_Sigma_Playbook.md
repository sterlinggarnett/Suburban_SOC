# Executive Summary
This playbook provides a structured, per-rule methodology to respond to alerts triggered by the Sigma rules deployed in Suburban-SOC.

<a id="how-to-use-this-playbook"></a>
**How to use this playbook:**

1. **An alert fires** in the Elastic Detection Engine for a managed Sigma rule.
2. **Find the rule's row** in the [Master Detection & Response Matrix](#master-detection--response-matrix) below — it names the technique, the fields to extract, the threat-intel target, and the maximum automated containment action.
3. **Open the rule's linked section** under Rule Response Procedures for the full workflow: summary and MITRE mapping → automated extraction fields → enrichment criteria → containment decision flow → remediation and evidence preservation.
4. **Every section follows the same 4-phase workflow** defined once in [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow): Trigger & Ingestion → Artifact Extraction → Threat Intelligence Enrichment → Containment & Response.

## Name
IR Sigma Playbook (Endpoint & Network Alerts)

## Problem Statement
Suburban-SOC deploys 108 Sigma detection rules across endpoint (Sysmon, Windows event channels, Linux auth) and network (Zeek) telemetry, spanning 75 MITRE ATT&CK techniques across 12 tactics (see [`docs/detections/attack-coverage.md`](../detections/attack-coverage.md)). Every one of those alerts requires a standardized triage and containment response; a generic playbook cannot tell an analyst which fields to extract, which threat-intelligence lookups apply, or when containment may be automated. This playbook gives each deployed rule its own response procedure.

## Objectives
- Rapidly identify and validate suspicious activities flagged by Sigma rules.
- Contain affected endpoints and accounts, and neutralize threats, with automation where severity and threat-intelligence confirmation justify it.
- Eradicate artifacts, preserve evidence, recover systems, and tune rules to reduce false positives.

## Compliance
- NIST CSF: DE.AE (Detection Processes), RS.AN (Analysis)
- CIS Controls: 17 (Incident Response Management)

## MITRE ATT&CK Framework
The deployed corpus covers **78 techniques across 12 tactics**. Per-rule technique IDs are in the Master Detection & Response Matrix below and in each rule's section; the authoritative coverage matrix (auto-generated from `rules/sigma/`) is [`docs/detections/attack-coverage.md`](../detections/attack-coverage.md).

## Assumptions and Limitations
- Assumes EDR and Logstash pipelines are fully operational.
- Requires Tier 2 Analyst or higher for Endpoint Isolation actions.
- Severities quoted in each rule section are verbatim from the rule's `level:` field.
- Threat-intelligence thresholds (VirusTotal, AbuseIPDB, OTX) are policy defaults set in this playbook, not properties of the rules; changing them is a policy decision.
- Detection thresholds (counts over time) live in the Elastic threshold companion rules (`rules/elastic/threshold/`), not in the Sigma logic; sections for paired rules cite their companion.

# Analysis
Analysts must evaluate process lineage, account context, and network context to distinguish known administrative behavior from adversarial action. The per-rule sections below make that evaluation concrete for each detection.

## Monitoring and Notifications
Alerts are generated natively in the Elastic Detection Engine and forwarded to the SOAR webhook or ntfy topics.

## Playbook Verification
- An alert corresponding to a managed Sigma rule fires (e.g. `proc_creation_win_lsass_dump.yml`).
- Endpoint telemetry indicating suspicious child processes is visible in Kibana.
- The alert's rule maps to exactly one section in this playbook (verified mechanically: 108 rules, 108 sections).

## Recommended Response Action(s)
The generic actions below are superseded by the per-rule sections in Rule Response Procedures at the end of this section; they remain as the workflow-phase summary.

### Identification
Phases 1–3 of the [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow): validate the alert against the rule's section, extract the listed fields, enrich per the section's criteria.

### Containment
Phase 4 of the [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow): apply the section's containment decision flow — automated tier action on confirmation, analyst triage path otherwise.

### Eradication & Recovery
Each section's *Remediation & Evidence Preservation* subsection: acquire evidence first (per SOP-147), remove the technique-specific artifacts, reset exposed credentials, verify clean, then restore. Tune the rule (falsepositives/exclusions) when the alert was benign.

<a id="standard-4-phase-ir-workflow"></a>
### Standard 4-Phase IR Workflow
Every rule section implements these four phases. Definitions live here once; sections state only what is specific to their rule.

1. **Trigger & Ingestion** — the SIEM alert fires when log events match the rule's detection logic. The section's *Rule Summary* restates that logic in plain language.
2. **Artifact Extraction** — indicators are parsed from the matched event's fields: network (source/destination IPs, ports, domains, URLs), file/process (paths, hashes, command lines, parent command lines), identity/host (user names, host names). The section's *Automated Extraction Fields* table names the exact fields, separating the rule's own detection-block fields from standard fields the event source carries.
3. **Threat Intelligence Enrichment** — extracted indicators are looked up automatically. **Escalation thresholds (policy defaults):**
   - File hash → VirusTotal: confirmed-malicious at **≥ 5 malicious verdicts**.
   - IP address → AbuseIPDB: confirmed-malicious at **≥ 50% confidence score**.
   - Domain / URL → AlienVault OTX: confirmed-malicious on **any pulse match**.
   - *Internal-only* — some events (pure identity or configuration changes) carry no external-TI artifact; enrichment is internal context: AD group diffs, change calendar, asset owner, prior case history.
   - An indicator is never labeled malicious without the citing TI verdict or an internal case ID.
4. **Containment & Response** — the containment tier is decided by rule severity × TI confirmation (table below). Confirmed-malicious triggers automated containment; ambiguous results route to analyst triage with verification queries and process-tree or identity analysis.

**Containment tiers:**

- **Tier A — auto-isolate + identity kill:** EDR network isolation + AD/IdP account disable + token/session/Kerberos-ticket revocation, executed automatically; page the IR lead.
- **Tier B — auto-isolate:** EDR isolation automatic on the stated condition; account actions on analyst confirm.
- **Tier C — auto-block indicator:** perimeter/DNS/EDR blocklist entry for the TI-confirmed indicator only; no host action without an analyst.
- **Tier D — triage-only:** enrich, queue for analyst review, no automation.

**Severity × TI auto-containment policy:**

| Rule `level` | TI-confirmed artifact (VT ≥5 / AbuseIPDB ≥50% / OTX pulse) | Automated action |
|---|---|---|
| critical | any — the 8 critical rules are behaviorally conclusive; the rule match plus the verbatim event is the cited evidence | Tier A |
| high | yes | Tier B (+ auto account-disable when the confirmed artifact is identity-bearing) |
| high | no / not applicable | Tier D with 15-minute analyst SLA; Tier B on analyst confirm |
| medium | yes | Tier C |
| medium / low | no | Tier D |

Identity-centric events with no host artifact (most Windows Security and Linux auth detections) substitute account-centric actions — disable, session/ticket revocation, forced reset — for EDR isolation at every tier; their sections mark this as *Tier B (identity)*.

### Per-Family Response Baselines
Rule sections inherit their family's baseline and state only deviations.

| Family (rules) | Event source | Artifact classes yielded | TI enrichment | Default tier |
|---|---|---|---|---|
| Windows Process Creation (51) | Sysmon EID 1 | binary paths, command lines, parent lineage, SHA-256, URLs/IPs/domains embedded in `CommandLine` | Hash → VT ≥5; embedded URL/domain → OTX; embedded IP → AbuseIPDB ≥50% | B (A for its critical rules) |
| Windows Security Log (15) | Security channel | account names/SIDs, source IPs, logon types, SPNs, group/policy objects | external IP → AbuseIPDB ≥50%; pure identity events → Internal-only | B (identity) / D; A for DCSync |
| PowerShell Script Block (7) | PowerShell/Operational 4104 | script content → decoded URLs, domains, IPs; dropped-payload hashes | OTX for URLs/domains, AbuseIPDB for IPs, VT for decoded payload hashes | B |
| Windows System Log (6) | System channel (SCM / event log service) | service names, service binary paths, driver paths | VT for the service binary hash via the correlated Sysmon EID 1 event | B |
| Zeek Network (21) | Zeek conn/dns/files/http/notice/smtp/ssh/ssl | external IPs/ports, domains, URIs, certificate attributes, MIME types, byte volumes | destination IP → AbuseIPDB ≥50%; domain/URI → OTX; downloaded-file hash → VT ≥5 | C, promote to B on confirmed internal-host involvement |
| Linux Authentication (5) | auth.log | usernames, SSH source IPs, sudo/su context | SSH source IP → AbuseIPDB ≥50%; local-context events → Internal-only | B (identity) / D |
| Sysmon Specialized (2) | Sysmon EID 8 / EID 11 | source/target process images, dropped-file path and hash | Hash → VT ≥5 | B |
| WMI Activity (1) | WMI-Activity 5861 | filter/consumer names, consumer command line | Internal-first; VT for any extracted payload hash | B |

<a id="master-detection--response-matrix"></a>
### Master Detection & Response Matrix

One row per deployed Sigma rule (108 rows), grouped by log-source family in the same
order as the Rule Response Procedures sections below, alphabetical by rule file within
each family. **Extracted Fields** lists the rule's own detection-block field names
verbatim; the fuller extraction set (standard event-source fields) is in each rule's
section. **Threat Intel Target** and **Automated Containment Action** use the controlled
vocabularies defined in [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow).

| Rule Name | MITRE ATT&CK ID | Extracted Fields | Threat Intel Target | Automated Containment Action |
|---|---|---|---|---|
| [Accessibility Feature Backdoor via Image/OriginalFileName Mismatch](#proc_creation_win_accessibility_binary_debugger_swap) | T1546.008 | `Image`, `OriginalFileName`, `ParentImage`, `CommandLine` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [ARP Cache Enumeration via arp.exe](#proc_creation_win_arp_cache_discovery) | T1016 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Windows Recovery Options Disabled via bcdedit](#proc_creation_win_bcdedit_recovery_disabled) | T1490 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [Malicious File Download via Bitsadmin](#proc_creation_win_bitsadmin_download) | T1105 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier C — indicator block on TI-confirm |
| [Payload Decoding via Certutil](#proc_creation_win_certutil_decode) | T1140 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Data Encoded for Exfiltration via Certutil](#proc_creation_win_certutil_encode_exfil_prep) | T1132.001 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Ingress Tool Transfer via Certutil URL Cache](#proc_creation_win_certutil_urlcache_download) | T1105 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier C — indicator block on TI-confirm |
| [Free Disk Space Wiped via cipher.exe](#proc_creation_win_cipher_free_space_wipe) | T1485 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Clearing Windows Event Logs via Wevtutil](#proc_creation_win_clear_event_logs) | T1070.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Saved Credential Enumeration via cmdkey or vaultcmd](#proc_creation_win_cmdkey_saved_creds_enum) | T1555.004 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [CMSTP Execution via Malicious INF or Silent-Install Flags](#proc_creation_win_cmstp_execution) | T1218.003 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Cscript/Wscript Executing from a Non-Standard Location](#proc_creation_win_cscript_wscript_remote) | T1059.005, T1059.007 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier C — indicator block on TI-confirm |
| [Windows Defender Real-Time Protection Disabled](#proc_creation_win_defender_tamper) | T1562.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [DNS Server Plugin DLL Side-Loading via dnscmd](#proc_creation_win_dnscmd_serverlevelplugindll) | T1574.002 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [Domain Group Discovery via Net.exe](#proc_creation_win_domain_group_discovery) | T1087.002 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier D — triage-only |
| [Locked File Copied via esentutl VSS Trick (Browser Credential Access)](#proc_creation_win_esentutl_locked_file_copy) | T1005 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Indirect Command Execution via Forfiles](#proc_creation_win_forfiles_execution) | T1202 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [InstallUtil Execution Bypassing Uninstall Logging](#proc_creation_win_installutil_bypass) | T1218.004 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Shell Spawned by PsExec Service or WMI Provider Host](#proc_creation_win_lateral_tool_parent) | T1021, T1569.002 | `Image`, `ParentImage` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [LaZagne Credential Harvester Execution](#proc_creation_win_lazagne_credential_harvest) | T1555 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Local User Account Creation via Net.exe](#proc_creation_win_local_acct_create) | T1136.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [LSASS Memory Dump via Comsvcs.dll](#proc_creation_win_lsass_dump) | T1003.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Mimikatz Module Syntax on the Command Line](#proc_creation_win_mimikatz_module_syntax) | T1003.001 | `CommandLine` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [Mshta Remote or Script Payload Execution](#proc_creation_win_mshta_remote) | T1218.005 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier B — auto-isolate on TI-confirm |
| [MSI Package Installed from a Remote URL](#proc_creation_win_msiexec_remote) | T1218.007 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier C — indicator block on TI-confirm |
| [Network Share Enumeration via net.exe](#proc_creation_win_net_share_recon) | T1135 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Firewall Rule Added via netsh](#proc_creation_win_netsh_firewall_rule_added) | T1562.004 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Port-Proxy Relay Configured via netsh](#proc_creation_win_netsh_portproxy_relay) | T1090.001 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5; IP → AbuseIPDB ≥50% | Tier B — auto-isolate on TI-confirm |
| [Domain Controller Discovery via Nltest](#proc_creation_win_nltest_discovery) | T1018 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier D — triage-only |
| [NTDS.dit Extraction via ntdsutil IFM Media Creation](#proc_creation_win_ntdsutil_ifm_dump) | T1003.003 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Indirect Command Execution via Pcalua](#proc_creation_win_pcalua_execution) | T1202 | `Image`, `CommandLine`, `ParentImage` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [PowerShell Remote Download Cradle](#proc_creation_win_powershell_downloadstring) | T1059.001, T1105 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier B — auto-isolate on TI-confirm |
| [Suspicious PowerShell Encoded Command Execution](#proc_creation_win_powershell_encoded) | T1059.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [PsExec Client-Side Remote Execution Launch](#proc_creation_win_psexec_client_side_launch) | T1569.002 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Password-Protected Archive Staging via RAR/WinRAR](#proc_creation_win_rar_archive_staging) | T1560.001 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [RDP Session Hijacking via Tscon](#proc_creation_win_rdp_hijack_tscon) | T1574 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [SAM Hive Dump via Reg.exe](#proc_creation_win_reg_save_sam) | T1003.002 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Regasm/Regsvcs Proxy Execution](#proc_creation_win_regasm_regsvcs_bypass) | T1218.009 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Regsvr32 Execution from Remote Server](#proc_creation_win_regsvr32_remote_sct) | T1218.010 | `Image`, `CommandLine` | Hash → VT ≥5; Domain/URL → OTX | Tier A — auto-isolate + identity kill |
| [Registry Run Key Persistence via Reg.exe](#proc_creation_win_run_key_persistence) | T1547.001 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Rundll32 Executing Inline Script via mshtml](#proc_creation_win_rundll32_inline_script) | T1218.011 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Existing Service Reconfigured to a New Binary Path](#proc_creation_win_sc_config_binpath_change) | T1543.003 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Scheduled Task Creation via Schtasks](#proc_creation_win_scheduled_task) | T1053.005 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier D — triage-only |
| [Windows Service Creation via Sc.exe](#proc_creation_win_service_creation_sc) | T1543.003 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [SharpHound / BloodHound AD Collection Execution](#proc_creation_win_sharphound_bloodhound_collection) | T1087.002 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Print Spooler Service Spawning a Suspicious Child Process](#proc_creation_win_spooler_child_process_printnightmare) | T1068 | `ParentImage`, `Image` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [Suspicious System Owner/User Discovery](#proc_creation_win_user_discovery) | T1033 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier D — triage-only |
| [Shadow Copy Deletion via Vssadmin](#proc_creation_win_vss_delete_shadows) | T1490 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Windows Backup Catalog or System State Backup Deleted via wbadmin](#proc_creation_win_wbadmin_delete_catalog) | T1490 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier A — auto-isolate + identity kill |
| [WMI Process Call Create](#proc_creation_win_wmi_process_create) | T1047 | `Image`, `CommandLine` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Shadow Copy Deletion via WMIC](#proc_creation_win_wmic_shadowcopy_delete) | T1490 | `Image`, `OriginalFileName`, `CommandLine` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [AS-REP Roasting — TGT Requested for an Account Without Pre-Authentication](#auth_win_asreproast_no_preauth_tgt) | T1558.004 | `EventID`, `PreAuthType`, `TargetUserName` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [Audit Policy Changed](#auth_win_audit_policy_changed) | T1562.002 | `EventID` | Internal-only | Tier B (identity) — account disable on TI-confirm |
| [Repeated Failed Sign-Ins (Windows Security 4625)](#auth_win_bruteforce_failed_logons) | T1110 | `EventID` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [Password Spray Indicator via Failed Logons From a Single Source (Windows Security 4625)](#auth_win_bruteforce_source_spray) | T1110.003 | `EventID`, `IpAddress` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [DCSync — Directory Replication Rights Exercised by a Non-DC Account](#auth_win_dcsync_replication_rights_used) | T1003.006 | `EventID`, `AccessMask`, `Properties`, `SubjectUserName` | Internal-only | Tier A — auto-isolate + identity kill |
| [Logon Attempt Against a Disabled Account](#auth_win_disabled_account_logon_attempt) | T1078.002 | `EventID`, `SubStatus`, `Status` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Explicit-Credential Sign-In Recorded (Windows Security 4648)](#auth_win_explicit_cred_account_sweep) | T1110.003 | `EventID` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [Kerberoasting — RC4 Service Ticket Requested for a User SPN](#auth_win_kerberoasting_rc4_spn_request) | T1558.003 | `EventID`, `TicketEncryptionType`, `Status`, `ServiceName` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [Pass-the-Hash Logon Pattern (LogonType 9, Negotiate)](#auth_win_pass_the_hash_logon) | T1550.002 | `EventID`, `LogonType`, `AuthenticationPackageName` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [Privileged Group Membership Change (Windows Security 4732/4728/4756)](#auth_win_priv_group_membership_change) | T1098, T1078 | `EventID`, `TargetUserName`, `TargetSid` | Internal-only | Tier B (identity) — account disable on TI-confirm |
| [Interactive Logon via RDP (LogonType 10)](#auth_win_rdp_logon_type10) | T1021.001 | `EventID`, `LogonType` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Security Audit Log Cleared (Windows Security 1102)](#auth_win_security_log_cleared) | T1070.001 | `EventID` | Internal-only | Tier B (identity) — account disable on TI-confirm |
| [Special-Privilege Logon Assigning SeDebugPrivilege (Windows Security 4672)](#auth_win_sedebug_special_logon) | T1078, T1134 | `EventID`, `PrivilegeList`, `SubjectUserSid` | Internal-only | Tier D — triage-only |
| [Object Access Against a Privileged AD Group](#auth_win_sensitive_group_recon) | T1069.002 | `EventID`, `ObjectName` | Internal-only | Tier D — triage-only |
| [User Account Created (Windows Security 4720)](#auth_win_user_account_created) | T1136.001 | `EventID` | Internal-only | Tier D — triage-only |
| [PowerShell Credential-Harvesting Cmdlet Pattern](#posh_credential_harvesting_scriptblock) | T1056.002 | `EventID`, `ScriptBlockText` | Decoded Domain/URL → OTX; Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [PowerShell-Native Data Compression Staging](#posh_data_compression_staging) | T1560 | `EventID`, `ScriptBlockText` | Decoded Domain/URL → OTX; Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Active Directory Query via Official ActiveDirectory Module](#posh_ps_ad_recon_admodule) | T1087.002 | `EventID`, `ScriptBlockText` | Internal-only | Tier D — triage-only |
| [Active Directory Reconnaissance via PowerView](#posh_ps_ad_recon_powerview) | T1087.002 | `EventID`, `ScriptBlockText` | Internal-only | Tier B — auto-isolate on TI-confirm |
| [PowerShell AMSI Bypass Attempt](#posh_ps_amsi_bypass_attempt) | T1562.001 | `EventID`, `ScriptBlockText` | Decoded Domain/URL → OTX; Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Obfuscated or Encoded PowerShell Script Block](#posh_ps_obfuscated_scriptblock) | T1059.001, T1027 | `EventID`, `ScriptBlockText` | Decoded Domain/URL → OTX; Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [PowerShell Reverse Shell via TCPClient](#posh_ps_reverse_shell) | T1059.001 | `EventID`, `ScriptBlockText` | Decoded Domain/URL → OTX; Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Kernel or File-System Driver Service Installed](#system_win_driver_service_installed) | T1068 | `EventID`, `ServiceType` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [Event Log Cleared (Windows System 104)](#system_win_eventlog_cleared) | T1070.001 | `EventID` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Windows Event Log Service Reconfigured or Disabled (Windows System 7040)](#system_win_eventlog_service_tamper) | T1562.002 | `EventID`, `param1` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Remote-Style Service Creation (PsExec Pattern)](#system_win_remote_service_creation_psexec_style) | T1543.003 | `EventID`, `ServiceName` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [New Service Installed (Windows System 7045)](#system_win_service_installed) | T1543.003 | `EventID`, `ImagePath` | Hash → VT ≥5 | Tier C — indicator block on TI-confirm |
| [New Service Installed With a LOLBin as its Binary](#system_win_suspicious_service_binpath_lolbin) | T1543.003 | `EventID`, `ImagePath` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [RDP Connection Originating From Outside Private Address Space](#net_zeek_conn_external_rdp_inbound) | T1021.001 | `id.resp_p`, `proto`, `id.orig_h` | IP → AbuseIPDB ≥50% | Tier B — auto-isolate on TI-confirm |
| [Unusually Large ICMP Flow (Possible ICMP Tunnel)](#net_zeek_conn_icmp_tunnel_large) | T1095 | `proto`, `orig_bytes` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [SMB Connection Crossing Private/Public Address Boundary](#net_zeek_conn_smb_lateral_admin) | T1021.002 | `id.resp_p`, `proto`, `id.orig_h`, `id.resp_h` | IP → AbuseIPDB ≥50% | Tier B — auto-isolate on TI-confirm |
| [Connection to Tor's Default OR or Directory Port](#net_zeek_conn_tor_exit_node) | T1090.003 | `id.resp_p`, `proto` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [DNS Query for a Known Cryptocurrency Mining Pool](#net_zeek_dns_crypto_mining_pool) | T1496 | `query` | Domain → OTX | Tier C — indicator block on TI-confirm |
| [NXDOMAIN Response for a DGA-Characteristic Domain Name](#net_zeek_dns_dga_nxdomain_burst) | T1568.002 | `rcode_name`, `query` | Domain → OTX | Tier C — indicator block on TI-confirm |
| [DNS Lookup for a Known Public DNS-over-HTTPS Provider — Blind to Hardcoded-IP DoH Clients](#net_zeek_dns_doh_non_standard) | T1572 | `query` | Domain → OTX | Tier D — triage-only |
| [DNS Query with High-Entropy Long Subdomain Label (Possible Tunneling)](#net_zeek_dns_tunneling_high_entropy) | T1071.004 | `query` | Domain → OTX | Tier C — indicator block on TI-confirm |
| [TXT Record Answer with Encoded-Looking Payload (Possible C2 Download Direction)](#net_zeek_dns_txt_answer_abuse) | T1071.004 | `qtype_name`, `answers` | Domain → OTX | Tier C — indicator block on TI-confirm |
| [TXT Record Query with Encoded-Looking Payload (Possible C2/Exfil Channel)](#net_zeek_dns_txt_record_abuse) | T1071.004 | `qtype_name`, `query` | Domain → OTX | Tier C — indicator block on TI-confirm |
| [Executable or Script Payload Downloaded Over HTTP (Zeek Files)](#net_zeek_executable_download) | T1105 | `source`, `mime_type` | Hash → VT ≥5; IP → AbuseIPDB ≥50% | Tier D — triage-only |
| [HTTP Request to a Known Default C2 Beacon URI](#net_zeek_http_cobalt_strike_beacon) | T1071.001 | `method`, `uri` | Domain/URL → OTX; IP → AbuseIPDB ≥50% | Tier D — triage-only |
| [Large HTTP POST Request Body](#net_zeek_http_exfil_large_post) | T1048.003 | `method`, `request_body_len` | Domain/URL → OTX; IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Network Port or Address Scan Detected (Zeek Notice)](#net_zeek_port_scan) | T1046 | `note` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Executable Payload Sent as an Email Attachment (Zeek Files) — Plaintext SMTP Only](#net_zeek_smtp_attachment_executable) | T1566.001 | `source`, `mime_type` | Hash → VT ≥5; IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [SMTP Session with an Anomalously Deep Transaction Count — Plaintext SMTP Only](#net_zeek_smtp_mass_outbound) | T1071.003 | `trans_depth` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [SSH Password Guessing / Brute Force (Zeek Notice)](#net_zeek_ssh_bruteforce) | T1110 | `note` | IP → AbuseIPDB ≥50% | Tier B — auto-isolate on TI-confirm |
| [SSH Session Cadence — Complementary Brute-Force Coverage Below detect-bruteforcing's Threshold](#net_zeek_ssh_session_cadence) | T1110 | `client` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Sustained Low-and-Slow SSH Session Cadence — Below detect-bruteforcing AND net_zeek_ssh_session_cadence's Own Rate Floor](#net_zeek_ssh_session_cadence_sustained) | T1110 | `client` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [TLS Connection with Expired Certificate](#net_zeek_ssl_expired_cert_connection) | T1071.001 | `validation_status` | IP → AbuseIPDB ≥50% | Tier D — triage-only |
| [TLS Connection with Self-Signed Certificate (Possible C2)](#net_zeek_ssl_self_signed_c2) | T1573.002 | `validation_status` | IP → AbuseIPDB ≥50% | Tier D — triage-only |
| [SSH Login Attempt for a Nonexistent User](#auth_linux_invalid_user_ssh_attempt) | T1110.001 | `event.module`, `message` | IP → AbuseIPDB ≥50% | Tier C — indicator block on TI-confirm |
| [Reference to authorized_keys in Linux Auth Log](#auth_linux_ssh_authorized_keys_change) | T1098.004 | `event.module`, `message` | Internal-only | Tier D — triage-only |
| [Direct Root Login via SSH](#auth_linux_ssh_root_login) | T1078.003 | `event.module`, `user.name`, `event.outcome` | IP → AbuseIPDB ≥50% | Tier B (identity) — account disable on TI-confirm |
| [su Session Opened](#auth_linux_su_session_opened) | T1078.003 | `event.module`, `message` | Internal-only | Tier D — triage-only |
| [Sudo Command Execution Logged](#auth_linux_sudo_privilege_escalation) | T1548.003 | `event.module`, `message` | Internal-only | Tier D — triage-only |
| [Suspicious CreateRemoteThread Target or Source (Sysmon EventID 8)](#create_remote_thread_win_susp_target) | T1055 | `EventID`, `TargetImage`, `SourceUser` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [File Dropped into the Startup Folder](#proc_creation_win_startup_folder_file_drop) | T1547.001 | `TargetFilename` | Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |
| [Suspicious WMI Event Filter-to-Consumer Binding (WMI-Activity 5861)](#wmi_win_event_subscription_binding) | T1546.003 | `EventID`, `Operation` | Internal-only; Hash → VT ≥5 | Tier B — auto-isolate on TI-confirm |

### Rule Response Procedures
One section per deployed Sigma rule, grouped by log-source family (matching the Master Matrix order), alphabetical by rule file within each family. Each section carries the five subsections of the [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow): Rule Summary & MITRE Mapping, Automated Extraction Fields, Enrichment Criteria, Containment Decision Flow, and Remediation & Evidence Preservation. Field names in extraction tables are quoted verbatim from the rule's detection block or named as the event source records them.

#### Windows Process Creation (Sysmon EID 1) — 51 rules

<a id="proc_creation_win_accessibility_binary_debugger_swap"></a>
##### Accessibility Feature Backdoor via Image/OriginalFileName Mismatch

**Rule file:** `rules/sigma/proc_creation_win_accessibility_binary_debugger_swap.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1546.008 — Event Triggered Execution: Accessibility Features |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | Either (a) one of the six accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`, `narrator.exe`, `displayswitch.exe`) launches with a PE `OriginalFileName` that does not match its own expected value — six independent `Image`-endswith / `OriginalFileName`-mismatch pairs, each pair evaluated as *selection and not its own filter* — or (b) the IFEO branch: `winlogon.exe` parents `cmd.exe` or `powershell.exe` whose `CommandLine` contains any of the six accessibility binary names |

Detects two forms of the "sticky keys" class of pre-logon backdoor, both launchable from the Winlogon screen before any credential is entered. Form 1 is binary replacement: the accessibility executable is overwritten with cmd.exe, so `Image` still ends in e.g. `\sethc.exe` while the PE metadata (`OriginalFileName`) still says `Cmd.Exe` — a mismatch a legitimate accessibility-tool launch never produces (matching is case-insensitive, so casing in the real string does not evade it). Form 2 is the IFEO `Debugger` redirect, which form 1's selectors structurally CANNOT see (security review #233): the launched process is a genuine `cmd.exe` with a genuine `OriginalFileName`, and the original target name appears only as an argument (`cmd.exe "sethc.exe"`) under a `winlogon.exe` parent — hence the separate detection branch. Rule falsepositives: an OriginalFileName-stripping packer or an unusual accessibility-tool build without standard PE metadata (treat missing/empty `OriginalFileName` the same as a mismatch); a legitimate pre-logon debugging/accessibility-testing tool launching cmd/powershell from winlogon with one of these names incidentally on its command line — uncommon in practice.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which of the six accessibility binaries launched (form 1), or `cmd.exe`/`powershell.exe` (IFEO branch) |
| `OriginalFileName` | rule detection block | The mismatch evidence — a value other than the binary's own name (e.g. `Cmd.Exe` under `\sethc.exe`) is the finding |
| `ParentImage` | rule detection block | `winlogon.exe` parent is the IFEO-branch trigger and confirms pre-logon launch context |
| `CommandLine` | rule detection block | IFEO branch: carries the redirected target's name as an argument |
| `ParentCommandLine` | event source (Sysmon EID 1) | Corroborates the launch context behind the parent |
| `User` | event source (Sysmon EID 1) | Pre-logon launches run as SYSTEM — a SYSTEM shell with no logged-on user is the backdoor firing |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the launched binary for TI lookup and known-good comparison |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**. Also compare against the known-good hash of the named binary from a reference host — a mismatch there is internal evidence even at VT 0.
- Internal-only: IFEO registry check on the host — `Debugger` values under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>` for each of the six names; file-system check of the six binaries in `System32` (hash, signature, timestamp); change-calendar and case-history lookup for the host.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- The mismatch itself is behavioral evidence; still record the rule ID, the verbatim event, and the registry/file findings as the citation — do not assert who planted it.

###### 4. Containment Decision Flow

**Auto-containment:** severity critical → **Tier A — auto-isolate + identity kill**, executed automatically on rule match (no TI gate; the match plus the verbatim event is the cited evidence): EDR network isolation + AD/IdP account disable + token/session/Kerberos-ticket revocation; page the IR lead.
**Analyst triage path** (post-containment validation):
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\sethc.exe and not process.pe.original_file_name : sethc.exe)
   or (process.executable : *\\utilman.exe and not process.pe.original_file_name : utilman.exe)
   or (process.executable : *\\osk.exe and not process.pe.original_file_name : osk.exe)
   or (process.executable : *\\magnify.exe and not process.pe.original_file_name : Magnify.exe)
   or (process.executable : *\\narrator.exe and not process.pe.original_file_name : Narrator.exe)
   or (process.executable : *\\displayswitch.exe and not process.pe.original_file_name : DisplaySwitch.exe)
   or (process.parent.name : winlogon.exe
       and process.executable : (*\\cmd.exe or *\\powershell.exe)
       and process.args : (*sethc.exe* or *utilman.exe* or *osk.exe* or *magnify.exe* or *narrator.exe* or *displayswitch.exe*))
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; a `winlogon.exe` parent at logon-screen time is the backdoor in use. Sweep the host ±24 h for who wrote the swapped binary or the IFEO key, and sweep the fleet for the same mismatch or IFEO value.
3. False-positive checks: OriginalFileName-stripping packer or non-standard accessibility build (missing/empty `OriginalFileName` — triage as a mismatch, then verify the file hash against known-good); sanctioned pre-logon debugging/accessibility-testing tool — confirm against the change calendar.
**Escalation:** already paged at Tier A. Evidence the backdoor was *used* (SYSTEM shell at the logon screen, interactive children of the flagged process) → treat as full host compromise with pre-auth persistence; extend the credential-exposure scope to every account that has logged on since the swap/IFEO write.

###### 5. Remediation & Evidence Preservation

- Acquire host memory and disk-image the six accessibility binaries plus the IFEO registry hive **before** cleanup; collect and hash the swapped binary and export the IFEO key.
- Cleanup: delete the `Debugger` value(s) under the IFEO key(s); restore the replaced binary from a known-good source (component store / clean media) and verify its hash and signature; reset credentials for accounts with sessions on the host since the earliest planting evidence.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_arp_cache_discovery"></a>
##### ARP Cache Enumeration via arp.exe

**Rule file:** `rules/sigma/proc_creation_win_arp_cache_discovery.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1016 — System Network Configuration Discovery |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `arp.exe` (by `Image` path or `OriginalFileName`) with `-a` on the command line |

Detects `arp -a`, which dumps the local ARP cache — every IP/MAC pair the host has recently communicated with on its local segment. The rule documents its own limits: this is one of the most heavily used legitimate diagnostic commands on any Windows fleet, so it is intentionally low-confidence — on its own it is closer to noise than signal, and its value comes from correlation with the other discovery-stage rules (SharpHound, net view/share) or a subsequent lateral-movement/scan indicator, not from firing in isolation. Rule falsepositives: routine network troubleshooting by IT staff or an end user diagnosing a connectivity issue.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\arp.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of arp.exe (`arp.exe`) |
| `CommandLine` | rule detection block | Confirms the `-a` cache-dump flag |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive shell vs script vs unexpected parent — the main triage discriminator |
| `User` | event source (Sysmon EID 1) | IT/admin account vs standard user context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, correlation key for the discovery-chain sweep |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts** (a renamed non-Microsoft binary posing as arp.exe would surface here).
- Internal-only: case history for the host/user; asset-owner check (is this an IT workstation?); correlation sweep for sibling discovery-rule hits from the same host/user.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- A lone `arp -a` is not malicious; do not label it so without a correlated chain or a cited TI/internal-case verdict.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: if the binary hash returns VT ≥ 5 malicious, auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst. Without TI confirmation → Tier D triage queue.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\arp.exe or process.pe.original_file_name : arp.exe) and process.args : *-a*
   ```
2. Discovery-chain pivot: sweep the same host/user ±60 min for other discovery-rule hits (net group, nltest, SharpHound indicators) and for follow-on lateral-movement or scan alerts — the rule's stated value is correlation, not the isolated event.
3. False-positive checks: routine network troubleshooting by IT staff or an end user diagnosing a connectivity issue — an interactive shell parent under a known IT account with no sibling discovery hits supports benign closure.
**Escalation:** two or more distinct discovery-family rules from the same host/user inside the window, or any subsequent lateral-movement indicator → promote to a discovery-stage incident and assign an analyst-led investigation.

###### 5. Remediation & Evidence Preservation

- Export the host's process-creation slice for the correlation window — the discovery-chain sequence is the evidence product; no host artifact cleanup applies to a cache read.
- If the chain is confirmed, remediation follows the downstream technique's section (lateral movement / credential access); document the reconnaissance scope (which segment's IP/MAC pairs were exposed).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_bcdedit_recovery_disabled"></a>
##### Windows Recovery Options Disabled via bcdedit

**Rule file:** `rules/sigma/proc_creation_win_bcdedit_recovery_disabled.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1490 — Inhibit System Recovery |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `bcdedit.exe` (by `Image` path or `OriginalFileName`) with a command line containing `recoveryenabled no` (space- or tab-delimited) or `ignoreallfailures` |

Detects bcdedit.exe disabling Windows Recovery Environment auto-repair (`bootstatuspolicy ignoreallfailures`) or the Recovery Console itself (`recoveryenabled no`) — a pre-encryption ransomware step that removes the OS's automatic-repair fallback so a corrupted/encrypted boot volume cannot self-heal into a recovery prompt; CISA AA23-320A names this as a key pre-encryption TTP for education-sector-targeting ransomware. The rule anchors `recoveryenabled no` against a tab delimiter as well as a space (`CreateProcess` treats them as equivalent argument delimiters) — the delimiter-evasion class named by security review #235/#236, fixed explicitly here as the batch's one critical rule. Rule falsepositives: a deliberate, documented dual-boot or embedded-device configuration change by IT staff — rare; correlate against the change calendar.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\bcdedit.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of bcdedit.exe (`bcdedit.exe`) |
| `CommandLine` | rule detection block | Which recovery control was disabled (`recoveryenabled no` vs `ignoreallfailures`) and the target boot entry |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Ransomware droppers typically parent this from a script host or an unexpected binary |
| `User` | event source (Sysmon EID 1) | Requires elevation — identifies the compromised admin context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor for the pre-encryption window, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**. Enrich the **parent** binary's hash from its own Sysmon EID 1 event as well — bcdedit itself is Microsoft-signed; the parent is where a dropper surfaces.
- Internal-only: change calendar (documented dual-boot/embedded configuration work?), asset owner, prior case history for the host; check backup/snapshot posture for the host immediately.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- The command is behaviorally conclusive as recovery-inhibition; cite the rule ID and the verbatim event, and do not attribute it to a specific actor or family without TI.

###### 4. Containment Decision Flow

**Auto-containment:** severity critical → **Tier A — auto-isolate + identity kill**, executed automatically on rule match (no TI gate): EDR network isolation + AD/IdP account disable + token/session/Kerberos-ticket revocation; page the IR lead. Speed matters: this fires in the pre-encryption window.
**Analyst triage path** (post-containment validation):
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped — args are tokenized, so confirm the exact `recoveryenabled no` value pair on the raw `CommandLine` in the hit):
   ```
   (process.executable : *\\bcdedit.exe or process.pe.original_file_name : bcdedit.exe)
   and process.args : (*recoveryenabled* or *ignoreallfailures*)
   ```
2. Process-tree and impact-chain pivot: `process.parent.name` / `process.parent.args`, then sweep the host ±30 min for companion pre-encryption steps (shadow-copy deletion, service stops, mass file writes) and the fleet for the same command line on other hosts.
3. False-positive checks: deliberate, documented dual-boot or embedded-device configuration change by IT staff — confirm against the change calendar; absent a matching change record, treat as hostile.
**Escalation:** already paged at Tier A. Any companion pre-encryption indicator on this or another host → declare a ransomware incident, invoke the major-incident process, and verify backup integrity before any restore decisions.

###### 5. Remediation & Evidence Preservation

- Image or snapshot the host before changes; export the process-creation slice covering the parent chain and any companion impact commands.
- Cleanup: revert the boot configuration (`bcdedit /set {default} recoveryenabled yes`, `bcdedit /set {default} bootstatuspolicy displayallfailures`) only after evidence capture; eradicate the parent dropper per its own hash/TI findings; verify backups are intact and offline-protected before reconnecting the host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_bitsadmin_download"></a>
##### Malicious File Download via Bitsadmin

**Rule file:** `rules/sigma/proc_creation_win_bitsadmin_download.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1105 — Ingress Tool Transfer |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `bitsadmin.exe` with `/transfer` on the command line |

Detects the use of bitsadmin.exe to download files via the /transfer switch — a signed, built-in transfer client abused to pull payloads without a browser. Rule falsepositives: legitimate background update processes.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\bitsadmin.exe`) |
| `CommandLine` | rule detection block | Carries the job name, the source URL/domain, and the local destination path — the primary artifacts |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (shell, script host, Office child) |
| `User` | event source (Sysmon EID 1) | Account context for the download |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the downloaded file's hash comes from follow-up collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- Downloaded file (collected from the destination path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- URL/domain parsed from `CommandLine` → AlienVault OTX; escalate on **any pulse match**.
- Internal-only: is the URL a known software-update or internal endpoint? Check the software-deployment inventory and change calendar.
- Do not label the URL or file malicious without the citing OTX/VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on OTX pulse (URL/domain) or VT ≥ 5 (file hash), auto-add the confirmed indicator to the perimeter/DNS/EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : *\\bitsadmin.exe and process.args : */transfer*
   ```
2. Process-tree pivot on `process.parent.name` / `process.parent.args`; then check whether the destination file was subsequently executed (a later process-creation event whose `process.executable` is the destination path).
3. False-positive checks: legitimate background update processes — a known updater parent and a vendor URL support benign closure; an Office/script-host parent or a user-writable destination does not.
**Escalation:** downloaded file executed, or TI-confirmed URL/hash on a user endpoint → promote to Tier B host isolation on analyst confirm and treat as an active ingress-tool-transfer incident.

###### 5. Remediation & Evidence Preservation

- Collect and hash the downloaded file from the destination path before deletion; enumerate BITS jobs (`bitsadmin /list /allusers`) and export the job details — BITS jobs persist and can re-fetch.
- Cleanup: cancel the BITS job, remove the payload, block the confirmed URL/domain at the perimeter, and eradicate the parent delivery vector per its own findings.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_certutil_decode"></a>
##### Payload Decoding via Certutil

**Rule file:** `rules/sigma/proc_creation_win_certutil_decode.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1140 — Deobfuscate/Decode Files or Information |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `certutil.exe` (by `Image` path or `OriginalFileName` `CertUtil.exe`) with a space-anchored decode flag — ` -decode` or ` /decode` — on the command line (also matching `-decodehex`/`-decodeasn` as prefixes) |

Detects certutil.exe used to decode a base64/hex-encoded file, a common way to deobfuscate a dropped payload. The match is deliberately flag-form and space-anchored (#217, #235/#236): a bare-word `decode` match collided with unrelated filenames (`decode_report.txt`), and un-anchored flag matching still collided with hyphen-compound filenames like `base64-decoded-blob.bin`; real certutil syntax always has the leading space. The `OriginalFileName` fallback gives rename-resistance, matching the sibling -encode rule. Rule falsepositives: rare legitimate certificate encoding/decoding workflows.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\certutil.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of certutil (`CertUtil.exe`) |
| `CommandLine` | rule detection block | Which decode flag was used, plus the encoded input and decoded output file paths — the primary artifacts |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | What staged the encoded file and invoked the decode |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the decoded payload's hash comes from collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **decoded output file** (collected from the path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**. Hash the encoded input as well — the encoded form may itself be VT-known.
- Internal-only: where did the encoded input come from (download logs, email gateway, removable media)? Change calendar for certificate-management work.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Do not label the decoded file malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on VT ≥ 5 for the decoded payload (or the executing binary if renamed/tampered), auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped — the Sigma space anchor corresponds to flag-initial args):
   ```
   (process.executable : *\\certutil.exe or process.pe.original_file_name : CertUtil.exe)
   and process.args : (-decode* or /decode*)
   ```
2. Process-tree pivot on `process.parent.name` / `process.parent.args`; then check for execution of the decoded output (later process-creation whose `process.executable` is the output path) and for a sibling `-urlcache` download that staged the input.
3. False-positive checks: rare legitimate certificate encoding/decoding workflows — a PKI-admin context with certificate-typed input/output files supports benign closure; ambiguous file paths mean the verdict rests on collecting and hashing the output, not on the command line alone.
**Escalation:** decoded payload executed or VT-confirmed → promote to Tier B host isolation on analyst confirm and pivot to the payload's own technique chain.

###### 5. Remediation & Evidence Preservation

- Collect and hash both the encoded input and decoded output files before cleanup; capture the parent chain.
- Cleanup: remove both files, eradicate the staging vector (downloader, mail attachment), and hunt the fleet for the input/output hashes.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_certutil_encode_exfil_prep"></a>
##### Data Encoded for Exfiltration via Certutil

**Rule file:** `rules/sigma/proc_creation_win_certutil_encode_exfil_prep.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Exfiltration |
| Technique(s) | T1132.001 — Data Encoding: Standard Encoding |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `certutil.exe` (by `Image` path or `OriginalFileName` `CertUtil.exe`) with a space-anchored encode flag — ` -encode` or ` /encode` — on the command line |

Detects `certutil.exe -encode` (or `/encode`), which base64-encodes an arbitrary local file — a standard LOLBin step to defeat egress controls that inspect for binary/archive signatures but pass what looks like text; the exact inverse of the corpus's `-decode` rule. The match is space-anchored (security review #235/#236): flag-form-only matching still collided with hyphen-compound filenames like `base64-encoded-output.txt`, and real certutil syntax always has the leading space a compound filename does not. Rule falsepositives: rare legitimate certificate-encoding workflows (e.g. converting a binary cert to base64 PEM format for transfer) — correlate the input/output file paths against the change calendar.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\certutil.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of certutil (`CertUtil.exe`) |
| `CommandLine` | rule detection block | The input file (what data is being staged) and the encoded output path — the exfil-scope evidence |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | What orchestrated the staging (interactive shell vs script) |
| `User` | event source (Sysmon EID 1) | Whose data access rights were used |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` (and of the encoded output once collected) → VirusTotal; escalate at **≥ 5 malicious verdicts** — the executing binary's hash flags a renamed impostor; the output hash fingerprints the staged data for fleet hunting.
- Internal-only: classify the **input** file (what data was staged — sensitivity, owner); change calendar for certificate-management work; egress-log check for a transfer of the output file after this event.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Staging is not exfiltration; state what the encoded file contained and whether egress evidence exists rather than asserting data loss without it.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on VT ≥ 5, auto-add the confirmed hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\certutil.exe or process.pe.original_file_name : CertUtil.exe)
   and process.args : (-encode* or /encode*)
   ```
2. Exfil-chain pivot: process-tree via `process.parent.name` / `process.parent.args`, then sweep the host's subsequent events for transfer activity referencing the output path (bitsadmin, script hosts, network utilities) and check egress/proxy logs for the same window.
3. False-positive checks: rare legitimate certificate-encoding workflows (binary cert → base64 PEM for transfer) — correlate the input/output file paths against the change calendar; if the paths are ambiguous, say so and rest the verdict on the collected file contents.
**Escalation:** sensitive input file plus any egress evidence for the output → declare an exfiltration incident, page the IR lead, and promote to Tier B host isolation on analyst confirm.

###### 5. Remediation & Evidence Preservation

- Collect and hash the input and encoded output files; record the input file's data classification and owner before any cleanup.
- Cleanup: remove the staged output, eradicate the orchestrating parent, and if egress occurred, follow data-breach handling for the input file's contents (owner notification, credential/key rotation if credentials were inside).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_certutil_urlcache_download"></a>
##### Ingress Tool Transfer via Certutil URL Cache

**Rule file:** `rules/sigma/proc_creation_win_certutil_urlcache_download.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1105 — Ingress Tool Transfer |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `certutil.exe` with `urlcache` or `verifyctl` on the command line, combined with `split` (the flag that writes the fetched content to disk) |

Detects certutil.exe fetching a remote file into the local URL cache via either the `-urlcache` or the lesser-known `-verifyctl` verb, both combined with `-split` — a common LOLBin technique for downloading a second-stage payload without invoking a browser or scripting engine. Distinct from the `-decode` rule (T1140, payload deobfuscation). Rule falsepositives: legitimate certificate-chain retrieval against an internal PKI endpoint that happens to also pass -split (uncommon but possible).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\certutil.exe`) |
| `CommandLine` | rule detection block | Which verb (`urlcache`/`verifyctl`), the source URL/domain, and the dropped-file destination — the primary artifacts |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector for the download command |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the dropped payload's hash comes from collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- Dropped payload (collected from the destination path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- URL/domain parsed from `CommandLine` → AlienVault OTX; escalate on **any pulse match**.
- Internal-only: is the URL an internal PKI endpoint (the stated FP case)? Check the PKI inventory and change calendar.
- Do not label the URL or payload malicious without the citing OTX/VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on OTX pulse (URL/domain) or VT ≥ 5 (payload hash), auto-add the confirmed indicator to the perimeter/DNS/EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : *\\certutil.exe
   and process.args : (*urlcache* or *verifyctl*) and process.args : *split*
   ```
2. Process-tree pivot on `process.parent.name` / `process.parent.args`; then check for execution or decode of the dropped file (a follow-on process-creation using the destination path, or a sibling ` -decode` event).
3. False-positive checks: legitimate certificate-chain retrieval against an internal PKI endpoint that happens to also pass -split (uncommon but possible) — an internal PKI URL supports benign closure; an external or look-alike domain does not.
**Escalation:** dropped payload executed or TI-confirmed → promote to Tier B host isolation on analyst confirm and treat as active second-stage delivery.

###### 5. Remediation & Evidence Preservation

- Collect and hash the dropped file; export certutil's URL cache metadata (`certutil -urlcache` listing) to document what was fetched.
- Cleanup: delete the payload and the cache entry, block the confirmed URL/domain, eradicate the parent vector, and hunt the fleet for the same URL or payload hash.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_cipher_free_space_wipe"></a>
##### Free Disk Space Wiped via cipher.exe

**Rule file:** `rules/sigma/proc_creation_win_cipher_free_space_wipe.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1485 — Data Destruction |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `cipher.exe` (by `Image` path or `OriginalFileName`) with a space-anchored ` /w` flag on the command line (covers `/w` and `/w:<path>`) |

Detects `cipher.exe /w`, which overwrites the free (deallocated) space on a volume — a legitimate anti-forensics-capable tool built into Windows, repurposed by ransomware and data-destruction actors after deleting or exfiltrating files to prevent forensic recovery of the deleted originals. The rule notes `/w` is genuinely rare in normal operation (not part of cipher's everyday EFS workflow), which is what keeps a single flag usable as a signal; the flag match is space-anchored against URL-style `//w...` substring collisions. Rule falsepositives: IT staff deliberately sanitizing free space on a workstation being decommissioned or repurposed — correlate against the change calendar and asset-lifecycle records.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\cipher.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of cipher.exe (`cipher.exe`) |
| `CommandLine` | rule detection block | Confirms `/w` and the target volume/path being wiped |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive admin session vs automated/dropper parent |
| `User` | event source (Sysmon EID 1) | Account context; wipe requires write access to the volume |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor (evidence is being destroyed from this moment), pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**; enrich the parent binary's hash as well — cipher itself is Microsoft-signed.
- Internal-only: change calendar and asset-lifecycle records (decommission/repurpose job?); case history for the host; check what was deleted on the host shortly before the wipe (prior deletion or exfil alerts).
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Treat the event as time-critical anti-forensics; document what was verified even if the wipe proves sanctioned.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → **Tier B — auto-isolate on TI-confirm**: auto EDR-isolate the host when a related hash (executing or parent binary) returns VT ≥ 5; account actions on analyst confirm. Without a TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm — bias toward early isolation because a running wipe destroys evidence by the minute.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\cipher.exe or process.pe.original_file_name : cipher.exe)
   and process.args : /w*
   ```
2. Anti-forensics-chain pivot: process-tree via `process.parent.name` / `process.parent.args`; sweep the host's prior 24 h for mass deletions, exfil-staging alerts (e.g. certutil -encode), or ransomware-precursor indicators — `/w` after deletion is the destruction of the deleted originals.
3. False-positive checks: IT staff deliberately sanitizing free space on a workstation being decommissioned or repurposed — correlate against the change calendar and asset-lifecycle records; no matching record → treat as hostile.
**Escalation:** the wipe follows deletion/exfil indicators, or no sanctioned-sanitization record exists → page the IR lead, isolate immediately if not already done, and kill the cipher process to stop further overwrite.

###### 5. Remediation & Evidence Preservation

- Act fast: stop the cipher.exe process, then image the volume — every minute of `/w` reduces recoverable deleted data; prioritize NTFS metadata ($MFT, $UsnJrnl, $LogFile) to reconstruct what was deleted before the wipe.
- Cleanup: eradicate whatever orchestrated the wipe (parent chain); if paired with exfil evidence, follow the data-breach path for the affected files.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_clear_event_logs"></a>
##### Clearing Windows Event Logs via Wevtutil

**Rule file:** `rules/sigma/proc_creation_win_clear_event_logs.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `wevtutil.exe` with a space-delimited ` cl ` or ` clear-log ` verb on the command line |

Detects the use of wevtutil.exe to clear event logs — indicator removal to cover activity that preceded it. Rule falsepositives: IT admin cleanup scripts.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\wevtutil.exe`) |
| `CommandLine` | rule detection block | Which log channel was cleared (the argument after `cl`/`clear-log`) — scopes what the attacker wanted erased |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive admin vs script vs post-exploitation tooling |
| `User` | event source (Sysmon EID 1) | Requires elevation — the compromised admin context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, the "everything before this is suspect" timeline anchor, pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**; enrich the parent binary's hash as well — wevtutil itself is Microsoft-signed.
- Internal-only: change calendar (sanctioned log-maintenance script?), case history for the host, and a SIEM-side check of what the cleared channel contained in the hours before the clear (events already forwarded survive the local wipe).
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- The clear is evidence of concealment intent only in context; cite the surrounding activity, not the clear alone, before calling the host compromised.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → **Tier B — auto-isolate on TI-confirm**: auto EDR-isolate the host when a related hash returns VT ≥ 5; account actions on analyst confirm. Without a TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped — the Sigma space-delimited verbs correspond to exact args):
   ```
   process.executable : *\\wevtutil.exe and process.args : (cl or clear-log)
   ```
2. Pre-clear reconstruction: pivot on `Computer` and query the SIEM's forwarded copy of the cleared channel for the 24 h before `UtcTime` — what was worth erasing is the real finding; also process-tree the parent via `process.parent.name` / `process.parent.args` and sweep for other defense-evasion alerts on the host.
3. False-positive checks: IT admin cleanup scripts — a known maintenance script parent, a scheduled window, and a matching change record support benign closure.
**Escalation:** the Security channel was cleared, multiple channels were cleared, or the pre-clear window contains other alerts → page the IR lead and treat the host as compromised with active anti-forensics.

###### 5. Remediation & Evidence Preservation

- Export the SIEM-side (forwarded) copies of the cleared channel(s) immediately and preserve them as the surviving record; collect the local `.evtx` files that remain and the parent-chain telemetry.
- Cleanup: eradicate the parent tooling; review and re-tighten who holds log-clear-capable privileges on the host; verify forwarding remained healthy through the incident window.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_cmdkey_saved_creds_enum"></a>
##### Saved Credential Enumeration via cmdkey or vaultcmd

**Rule file:** `rules/sigma/proc_creation_win_cmdkey_saved_creds_enum.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1555.004 — Credentials from Password Stores: Windows Credential Manager |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `cmdkey.exe` or `vaultcmd.exe` (by `Image` path or `OriginalFileName`) with `/list` or `-list` on the command line (`/list` also matches vaultcmd's `/listcreds:` verb as a substring) |

Detects cmdkey.exe or vaultcmd.exe listing the stored credentials in Windows Credential Manager / Windows Vault — two separate signed built-ins reading the same store; a standard early-access discovery step revealing which remote hosts the user has cached credentials for, feeding lateral movement. vaultcmd was added after security review #232 flagged that a cmdkey-only rule is trivially evaded by tool substitution. Both are genuinely low-volume on a normal endpoint, which is what makes the plain list verb usable as a signal. Rule falsepositives: helpdesk or provisioning scripts auditing stored credentials on a managed workstation; an administrator manually checking which credentials are cached before troubleshooting a mapped-drive or RDP issue.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which tool ran (`\cmdkey.exe` or `\vaultcmd.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification (`cmdkey.exe` / `vaultcmd.exe`) |
| `CommandLine` | rule detection block | The list verb used (`/list`, `-list`, `/listcreds:`) and any targeted vault |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Helpdesk/provisioning script vs interactive attacker shell |
| `User` | event source (Sysmon EID 1) | Whose credential store was enumerated — defines the exposure scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, pivot key for the follow-on lateral-movement sweep |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: which stored targets exist in that user's Credential Manager (via the user/helpdesk, or host triage); case history; helpdesk-ticket check for the stated FP scenarios; then watch authentications from this host to the stored-credential targets after `UtcTime`.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Enumeration alone proves interest, not theft; do not report credentials as compromised without follow-on access evidence or a TI/internal-case citation.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on VT ≥ 5 for the executing binary's hash, auto-add it to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : (*\\cmdkey.exe or *\\vaultcmd.exe)
    or process.pe.original_file_name : (cmdkey.exe or vaultcmd.exe))
   and process.args : (/list* or -list*)
   ```
2. Lateral-movement pivot: process-tree via `process.parent.name` / `process.parent.args`, then sweep the same host/user ±60 min for both tools (tool-substitution doubles), other credential-access alerts, and new outbound RDP/SMB authentication to hosts the store would name.
3. False-positive checks: helpdesk or provisioning scripts auditing stored credentials on a managed workstation; an administrator manually checking cached credentials before troubleshooting a mapped-drive or RDP issue — a matching ticket or known script parent supports benign closure.
**Escalation:** enumeration followed by authentication to a stored-credential target, or paired with another credential-access alert → treat every credential in the user's store as exposed, page the IR lead, and promote to Tier B on analyst confirm.

###### 5. Remediation & Evidence Preservation

- Record (with the user or via host triage) which credential targets were in the store at enumeration time; export the host's process and authentication telemetry for the window.
- Cleanup: rotate the stored credentials, purge the affected Credential Manager entries, and hunt post-event authentications to the stored targets from any host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_cmstp_execution"></a>
##### CMSTP Execution via Malicious INF or Silent-Install Flags

**Rule file:** `rules/sigma/proc_creation_win_cmstp_execution.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.003 — System Binary Proxy Execution: CMSTP |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `cmstp.exe` with any of `/s`, `/ns`, `.inf`, `\appdata\`, `\temp\`, or `\users\public\` on the command line |

Detects cmstp.exe (Connection Manager Profile Installer) invoked with a silent-install flag or an .inf argument — a well-known UAC-bypass and AppLocker-bypass technique (Squiblydoo-style) where cmstp executes an arbitrary scriptlet or DLL referenced from the supplied profile. The rule states its own tuning rationale: cmstp.exe execution is already rare on modern endpoints, so the OR-based match is kept broad to catch the technique regardless of which specific invocation flag is used. Rule falsepositives: legitimate VPN/dial-up connection profile installation (rare on modern endpoints).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\cmstp.exe`) |
| `CommandLine` | rule detection block | The flags used and the INF file path — the payload pointer |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (Office child, script host, shell) |
| `User` | event source (Sysmon EID 1) | Account context; relevant to the UAC-bypass value of the technique |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the INF/scriptlet payload hashes come from collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the INF file and any scriptlet/DLL it references (collected from the path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: does the org actually deploy Connection Manager profiles (VPN/dial-up)? Check the software-deployment inventory and change calendar; a user-writable INF path (`\appdata\`, `\temp\`, `\users\public\`) has no legitimate deployment story.
- No external IP/domain artifact on this event itself; if the collected INF references a remote scriptlet URL, enrich that finding under its own citation.
- Do not label the INF malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → **Tier B — auto-isolate on TI-confirm**: auto EDR-isolate the host when the INF/payload hash returns VT ≥ 5; account actions on analyst confirm. Without a TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : *\\cmstp.exe
   and process.args : (/s or /ns or *.inf* or *\\appdata\\* or *\\temp\\* or *\\users\\public\\*)
   ```
2. Process-tree pivot: `process.parent.name` / `process.parent.args` for the delivery vector, and children of the cmstp process — the proxied payload (scriptlet host, DLL loader) appears as its child or a near-simultaneous sibling.
3. False-positive checks: legitimate VPN/dial-up connection profile installation (rare on modern endpoints) — a managed-deployment parent and a system-path INF support benign closure; a user-writable INF path does not.
**Escalation:** INF in a user-writable path, a spawned child process, or a VT-confirmed payload → page the IR lead and isolate; treat as an active defense-evasion execution chain.

###### 5. Remediation & Evidence Preservation

- Collect and hash the INF file and every scriptlet/DLL it references before deletion; capture the child-process chain.
- Cleanup: remove the INF and payload files, revert any connection-profile artifacts it installed, and eradicate the delivery vector; hunt the fleet for the same INF/payload hashes.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_cscript_wscript_remote"></a>
##### Cscript/Wscript Executing from a Non-Standard Location

**Rule file:** `rules/sigma/proc_creation_win_cscript_wscript_remote.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution |
| Technique(s) | T1059.005 — Command and Scripting Interpreter: Visual Basic; T1059.007 — Command and Scripting Interpreter: JavaScript |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `cscript.exe` or `wscript.exe` with any of `//e:` (engine override), a user-writable staging path (`\appdata\`, `\temp\`, `\users\public\`, `\downloads\`), or `http` on the command line |

Detects cscript/wscript invoked against a script staged in a user-writable location, with an explicit scripting-engine override, or with an http(s) reference on the command line. The rule carries its own honesty note: Windows Script Host has no HTTP handler of its own — a bare `wscript.exe http://...` argument does not execute anything — so `http` is only a secondary signal (e.g. a WebDAV/UNC path embedding a URL-like string), and the primary signal is where the script is staged. Rule falsepositives: legitimate business VBScript/JScript run from a user-writable path during a manual troubleshooting session.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which script host ran (`\cscript.exe` / `\wscript.exe`) |
| `CommandLine` | rule detection block | The script path (primary artifact), engine override, or embedded URL-like string |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector — Office child, explorer double-click, another script |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the script file's hash comes from collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the staged script file (collected from the path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- URL/domain, if a real one appears on the command line or inside the collected script → AlienVault OTX; escalate on **any pulse match** — remembering the rule's caveat that a bare URL argument executes nothing by itself.
- Internal-only: is the script a known business script (software inventory, prior cases)? How did it arrive in the staging path (browser/email telemetry)?
- Do not label the script or URL malicious without the citing VT/OTX verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on VT ≥ 5 (script hash) or OTX pulse (domain/URL), auto-add the confirmed indicator to the EDR/perimeter blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : (*\\cscript.exe or *\\wscript.exe)
   and process.args : (*//e\:* or *\\appdata\\* or *\\temp\\* or *\\users\\public\\* or *\\downloads\\* or *http*)
   ```
2. Process-tree pivot: `process.parent.name` / `process.parent.args` for delivery (Office/browser/archive extraction), and children of the script host — spawned shells, LOLBins, or network utilities are the payload behavior.
3. False-positive checks: legitimate business VBScript/JScript run from a user-writable path during a manual troubleshooting session — a known script, an IT-session parent, and no suspicious children support benign closure; an `http`-only match with no staging-path or engine-override signal is the rule's weakest form — weigh it accordingly.
**Escalation:** script hash or contacted domain TI-confirmed, or the script spawns follow-on execution → promote to Tier B host isolation on analyst confirm.

###### 5. Remediation & Evidence Preservation

- Collect and hash the script file before deletion; capture its delivery artifact (email attachment, download record) and the child-process chain.
- Cleanup: delete the script, remove any persistence pointing at it (Run keys, Startup folder, scheduled tasks), block confirmed domains, and hunt the fleet for the script hash.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_defender_tamper"></a>
##### Windows Defender Real-Time Protection Disabled

**Rule file:** `rules/sigma/proc_creation_win_defender_tamper.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1562.001 — Impair Defenses: Disable or Modify Tools |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `powershell.exe` or `pwsh.exe` whose command line contains both `Set-MpPreference` and `Disable` |

Detects use of Set-MpPreference to disable Defender protections (real-time monitoring), a common defense-evasion step. Rule falsepositives: administrators temporarily disabling protection for troubleshooting.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which PowerShell host ran (`\powershell.exe` / `\pwsh.exe`) |
| `CommandLine` | rule detection block | Exactly which `-Disable*` preference was set — scopes what protection was turned off |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Admin console vs dropper/script delivery vector |
| `User` | event source (Sysmon EID 1) | Requires elevation — the admin context that was used or abused |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, the start of the protection-off window, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts** — and enrich the parent binary and any binary executed on the host *after* the disable, since the protection-off window is where a payload lands.
- Internal-only: change calendar / helpdesk ticket for sanctioned troubleshooting; current `Get-MpComputerStatus` state of the host; EDR console operator log.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Do not label follow-on binaries malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → **Tier B — auto-isolate on TI-confirm**: auto EDR-isolate the host when a related hash (parent or post-disable binary) returns VT ≥ 5; account actions on analyst confirm. Without a TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : (*\\powershell.exe or *\\pwsh.exe)
   and process.args : *Set-MpPreference* and process.args : *Disable*
   ```
2. Protection-off-window sweep: process-tree the parent via `process.parent.name` / `process.parent.args`, then enumerate every new process and dropped binary on the host from `UtcTime` until protection is confirmed re-enabled — that window is the reason the tamper happened.
3. False-positive checks: administrators temporarily disabling protection for troubleshooting — a matching ticket/change record and a prompt re-enable support benign closure; a script-host or unexpected parent does not.
**Escalation:** new/unknown binary executed during the protection-off window, or no sanctioned-troubleshooting record → page the IR lead and isolate; assume a payload was intended to land while Defender was off.

###### 5. Remediation & Evidence Preservation

- Capture the current Defender configuration and the protection-off window's process/file telemetry before changing anything.
- Cleanup: re-enable protections (`Set-MpPreference -DisableRealtimeMonitoring $false`, revert other changed preferences), verify with `Get-MpComputerStatus`, run a full scan, and eradicate anything that landed during the window; review who holds local-admin on the host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_dnscmd_serverlevelplugindll"></a>
##### DNS Server Plugin DLL Side-Loading via dnscmd

**Rule file:** `rules/sigma/proc_creation_win_dnscmd_serverlevelplugindll.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1574.002 — Hijack Execution Flow: DLL Side-Loading |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `dnscmd.exe` (by `Image` path or `OriginalFileName`) with `serverlevelplugindll` on the command line |

Detects `dnscmd.exe /config /serverlevelplugindll <path>`, which sets a registry value the DNS Server service loads as an in-process plugin DLL on its next (or forced) restart. It requires admin rights on the DNS server, but the DNS Server service typically runs as SYSTEM — a privilege-escalation and persistence primitive specific to DNS servers, which very commonly co-host on domain controllers; the switch has essentially no legitimate use in normal DNS administration. Known blind spot carried from the rule (security review #233): the same registry value can be set via the `DnsServerPsProvider` PowerShell module (`Set-DnsServerSetting -ServerLevelPluginDll <path>`) or a direct registry write, neither of which invokes dnscmd.exe — this rule has no visibility into either path.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\dnscmd.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of dnscmd.exe (`dnscmd.exe`) |
| `CommandLine` | rule detection block | The plugin DLL path being registered — the payload pointer |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | How the admin session/tooling that set the value was reached |
| `User` | event source (Sysmon EID 1) | The (necessarily privileged) account used — identity-kill target |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the plugin DLL's hash comes from collection |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Which DNS server/DC, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the registered plugin DLL (collected from the path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**; a DLL absent from VT on a DC is itself a priority finding to document.
- Internal-only: read the `ServerLevelPluginDll` value under the DNS service's Parameters key on the server to confirm the current state; vendor-product inventory (the rule's only stated legitimate case is a deliberately deployed vendor DNS-plugin architecture, which should be a standing exclusion by exact DLL path); change calendar; DNS service restart events after `UtcTime` (the load trigger).
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Cite the registry value and DLL hash in the case record; do not attribute the intrusion without TI.

###### 4. Containment Decision Flow

**Auto-containment:** severity critical → **Tier A — auto-isolate + identity kill**, executed automatically on rule match (no TI gate): EDR network isolation of the DNS server + disable of the initiating account + token/session/Kerberos-ticket revocation; page the IR lead. Coordinate fast: this host is likely a domain controller, and isolation has service impact the IR lead must own.
**Analyst triage path** (post-containment validation):
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\dnscmd.exe or process.pe.original_file_name : dnscmd.exe)
   and process.args : *serverlevelplugindll*
   ```
2. DC-compromise pivot: process-tree the parent via `process.parent.name` / `process.parent.args`; establish how the privileged session was obtained (logon telemetry for `User` on the server); check whether the DNS service restarted after the write — if it did, the DLL has already executed as SYSTEM. Because of the rule's documented blind spot, also inspect the registry value directly for changes this rule could not see.
3. False-positive checks: none expected in normal DNS server operation — the only legitimate case is a vendor-deployed DNS-plugin architecture, which should be a standing exclusion by exact DLL path; anything else is treated as hostile.
**Escalation:** already paged at Tier A. Confirmed DLL load (service restart post-write) → treat as SYSTEM-level DC compromise: invoke the domain-compromise procedure, including KRBTGT and privileged-credential rotation planning.

###### 5. Remediation & Evidence Preservation

- Collect and hash the plugin DLL and export the DNS Parameters registry key before any change; acquire memory of the DNS server if the service restarted after the write.
- Cleanup: clear the `ServerLevelPluginDll` value, remove the DLL, restart the DNS Server service under change control, and verify the value stays clear; rotate the initiating account's credentials and audit all privileged access to the server; hunt other DNS servers for the same value set by any method (dnscmd, PowerShell, or direct registry write — the latter two are invisible to this rule).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_domain_group_discovery"></a>
##### Domain Group Discovery via Net.exe

**Rule file:** `rules/sigma/proc_creation_win_domain_group_discovery.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1087.002 — Account Discovery: Domain Account |
| Severity (`level`) | low |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `net.exe` or `net1.exe` whose command line contains both `group` and `/domain` |

Detects net.exe enumerating domain groups (e.g. Domain Admins) — account discovery during recon. This single-event definition is deliberately kept at level low as the logic-of-record for hunting and correlation (#217); the alerting signal is the Elastic threshold companion `rules/elastic/threshold/disc-win-domain-group-discovery-repeat.ndjson`, which fires at severity medium on **≥ 3** matching events counted per `host.name` within its 10-minute detection window (evaluated every 10 minutes over a 20-minute lookback that guarantees full window containment, per review #393) — repeated enumeration on the same host being what distinguishes automated recon tooling from routine account administration; a single deliberate attacker execution is still recorded in raw telemetry, just not alerted on alone. Rule falsepositives: help-desk and IAM administration.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which binary ran (`\net.exe` / `\net1.exe` — net.exe frequently proxies through net1.exe) |
| `CommandLine` | rule detection block | Which domain group was enumerated (e.g. `Domain Admins`) — the recon-interest evidence |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | IAM/helpdesk tooling vs attacker shell or script |
| `User` | event source (Sysmon EID 1) | Admin/helpdesk account vs standard user running domain recon |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host (the companion's counting key), timeline anchor, pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: help-desk/IAM ticket check for the user; case history for the host; count sibling `group /domain` executions on the same host (the companion's ≥ 3-in-10-minutes condition) and note which groups were queried — privileged groups first is a recon signature.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- A single enumeration by an admin account is routine; keep the verdict tied to repetition, group selection, and context, each cited from the telemetry.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → **Tier D — triage-only**: enrich and queue for analyst review; no automation. The threshold companion firing (≥ 3 on one host in 10 minutes, severity medium) is what elevates this into an active analyst investigation.
**Analyst triage path:**
1. Verify and burst-check with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   process.executable : (*\\net.exe or *\\net1.exe)
   and process.args : *group* and process.args : */domain*
   ```
   Bucket by `host.name` over 10-minute windows; ≥ 3 matches on one host reproduces the companion's alert condition.
2. Discovery-chain pivot: process-tree via `process.parent.name` / `process.parent.args`; sweep the host/user ±60 min for companion discovery alerts (arp cache, nltest, user discovery) and for the queried groups' membership being subsequently targeted (logons, credential-access alerts against those members).
3. False-positive checks: help-desk and IAM administration — a matching ticket, known IAM tooling parent, and non-privileged group queries support benign closure.
**Escalation:** the threshold companion fires, privileged groups (Domain Admins et al.) are queried from a non-IAM context, or a second discovery-family rule hits the same host/user → promote to an analyst-led discovery-stage investigation and watch the queried groups' members for follow-on targeting.

###### 5. Remediation & Evidence Preservation

- Export the host's process-creation slice for the burst window; record which groups were enumerated — that list predicts the attacker's next targets.
- No host artifact cleanup applies to enumeration; if the chain is confirmed, remediation follows the downstream technique and the queried privileged accounts get heightened monitoring.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_esentutl_locked_file_copy"></a>
##### Locked File Copied via esentutl VSS Trick (Browser Credential Access)

**Rule file:** `rules/sigma/proc_creation_win_esentutl_locked_file_copy.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Collection, Credential Access |
| Technique(s) | T1005 — Data from Local System |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `esentutl.exe` (by `Image` path or `OriginalFileName`) with a space-delimited ` /y ` copy flag **and** `/vss` both on the command line |

Detects esentutl.exe using `/y` (copy) together with `/vss` (Volume Shadow Copy) to copy a file that is normally locked while in use — most notably browser SQLite credential/cookie stores (Chrome/Edge `Login Data`, `Cookies`), which the browser holds open and a plain copy cannot read. The rule requires `/vss` specifically (security review #235/#236): a bare `/y ... /d` copy is esentutl's documented general-purpose copy syntax, cannot bypass a file lock, and deliberately does NOT match — `/vss` is genuinely rare in normal IT operation, which is what keeps this a real signal. Rule falsepositives: legitimate database-repair or forensic-imaging use of esentutl by IT/DBA staff — rare in practice; correlate the copied file path against the change calendar.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\esentutl.exe`) |
| `OriginalFileName` | rule detection block | Rename-resistant identification of esentutl (`esentutl.exe`) |
| `CommandLine` | rule detection block | The source (locked) file and destination copy paths — source path identifies *what* was taken (browser cred store vs database) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive attacker shell vs DBA/imaging tooling |
| `User` | event source (Sysmon EID 1) | Whose profile/browser store was targeted — defines credential-exposure scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**; enrich the parent binary's hash as well — esentutl itself is Microsoft-signed.
- Internal-only: classify the source path from `CommandLine` — a browser profile path (`Login Data`, `Cookies`) is credential access; a database path may be the DBA FP case (change-calendar check); locate the destination copy and any onward movement of it (exfil-staging or transfer alerts).
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- State what file was copied and to where, with paths quoted from the event; do not assert credential theft without the source path or collected copy substantiating it.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → **Tier B — auto-isolate on TI-confirm**: auto EDR-isolate the host when a related hash returns VT ≥ 5; account actions on analyst confirm. Without a TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm — a browser-cred-store source path is grounds for immediate analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped):
   ```
   (process.executable : *\\esentutl.exe or process.pe.original_file_name : esentutl.exe)
   and process.args : /y and process.args : */vss*
   ```
2. Credential-access pivot: process-tree via `process.parent.name` / `process.parent.args`; sweep the host ±60 min for DPAPI/decryption tooling activity (the copied store still needs decrypting), other credential-access alerts, and transfer of the destination file off-host.
3. False-positive checks: legitimate database-repair or forensic-imaging use by IT/DBA staff — rare in practice; correlate the copied file path against the change calendar. A bare `/y ... /d` copy without `/vss` does not match this rule and is not a bypass of its intent — do not chase those as misses.
**Escalation:** source path is a browser credential/cookie store, or the copy moves off-host → page the IR lead; treat the user's browser-saved credentials and session cookies as exposed.

###### 5. Remediation & Evidence Preservation

- Collect and hash the destination copy; record the source path verbatim; capture the parent chain and any decryption-tool artifacts.
- Cleanup: remove the copied store and tooling; have the affected user rotate passwords saved in the browser and invalidate active web sessions (stolen cookies bypass passwords and MFA); hunt for use of the exposed web credentials.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_forfiles_execution"></a>
##### Indirect Command Execution via Forfiles

**Rule file:** `rules/sigma/proc_creation_win_forfiles_execution.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1202 — Indirect Command Execution |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `forfiles.exe` with `/c` on the command line **and** a suspicious payload token (`cmd /c`, `powershell`, `pwsh`, `rundll32`, `regsvr32`, `mshta`, `wscript`, `cscript`, `certutil`) in the executed command |

Detects forfiles.exe invoked with the /c flag and a suspicious payload token — e.g. `forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c calc.exe"` — proxying execution through a signed utility. The rule documents its tuning: a prior draft matched bare `/c`, which appears in the single most common *legitimate* forfiles invocation (the log-rotation one-liner `forfiles /p C:\Logs /s /m *.log /d -30 /c "cmd /c del @path"`) and would have fired on every routine run; requiring a payload token keeps the log-rotation case negative while catching the indirect-execution abuse pattern. Rule falsepositives: a legitimate script that happens to invoke cmd.exe or powershell.exe as the per-file action (uncommon; most legitimate forfiles usage calls a single utility like del/copy/attrib directly).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\forfiles.exe`) |
| `CommandLine` | rule detection block | The `/c` payload command (which LOLBin/interpreter is being proxied) and the `/p`/`/m` file-match pretext |
| `OriginalFileName` | event source (Sysmon EID 1) | Rename-evasion check (the rule matches on `Image` only) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Scheduled task/script vs interactive attacker use |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary; the proxied payload's artifacts come from the child events |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, parent key for the spawned payload's own EID 1 event |

###### 3. Enrichment Criteria

- SHA-256 of the proxied payload's binary/script (from the child process-creation event or collected file) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: scheduled-task and script inventory for the host (is this a known maintenance job?); change calendar; case history.
- No external IP/domain artifact on this event itself; if the proxied child carries a URL (e.g. certutil download), enrich under that child's own finding.
- Do not label the payload malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → **Tier C — indicator block on TI-confirm**: on VT ≥ 5 for the payload hash, auto-add it to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped — the rule's `cmd /c` token spans a quoted argument, so confirm the full payload on the hit's raw command line):
   ```
   process.executable : *\\forfiles.exe and process.args : */c*
   and process.args : (*cmd* or *powershell* or *pwsh* or *rundll32* or *regsvr32* or *mshta* or *wscript* or *cscript* or *certutil*)
   ```
2. Child-process pivot: the real payload is the process forfiles spawns — pivot on the flagged event's process as parent (`process.parent.name : forfiles.exe`) and follow that child's own command line, hashes, and grandchildren.
3. False-positive checks: a legitimate script that happens to invoke cmd.exe or powershell.exe as the per-file action (uncommon; most legitimate forfiles usage calls a single utility like del/copy/attrib directly) — a known scheduled maintenance job with a benign per-file action supports closure.
**Escalation:** the spawned child is itself a flagged LOLBin chain (download, decode, script host from a staging path) or its payload is TI-confirmed → promote to Tier B host isolation on analyst confirm and follow the child technique's section.

###### 5. Remediation & Evidence Preservation

- Capture the full forfiles command line and the child-process chain; collect and hash any script/binary the `/c` payload referenced.
- Cleanup: remove the invoking artifact (scheduled task, script, or persistence entry that ran forfiles) and the payload files; hunt the fleet for the same command-line pattern.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_installutil_bypass"></a>
##### InstallUtil Execution Bypassing Uninstall Logging

**Rule file:** `rules/sigma/proc_creation_win_installutil_bypass.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.004 — System Binary Proxy Execution: InstallUtil |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `installutil.exe` launched with any one of the uninstall switch (`/u`/`-u`) or the log-suppression flags (`/logfile=`, `-logfile=`, `/logtoconsole=false`) |

Detects InstallUtil.exe — a signed Microsoft binary — proxy-executing an attacker-supplied .NET assembly's `[Uninstall]`-attributed method. The rule deliberately matches on any one of these flags rather than requiring them together: `/U` alone (with no log-suppression flags at all) is the canonical form of the technique and must not be missed just because logging wasn't also suppressed.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\installutil.exe`) |
| `CommandLine` | rule detection block | Carries the flag(s) and the path of the .NET assembly being executed — the primary artifact |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Separates deployment tooling (msiexec, CI agents) from shells and script hosts |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of installutil.exe itself (Microsoft-signed; low TI value on its own) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **assembly** named on `CommandLine` (collect from disk or the correlated Sysmon file events) → VirusTotal; escalate at **≥ 5 malicious verdicts**. InstallUtil itself is Microsoft-signed — the payload assembly is the TI artifact.
- SHA-256 of the parent process binary → VirusTotal at the same threshold when the parent is not recognized deployment tooling.
- Internal-only: change calendar / software-deployment records for a sanctioned uninstall or rollback at this time.
- Do not label the assembly malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the assembly (or parent-binary) VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel — `process.args`, not `process.command_line`):
   ```
   process.executable : *\\installutil.exe and process.args : ("/u" or "-u" or *logfile=* or *logtoconsole=false*)
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; inspect the assembly on disk — unsigned, user-writable staging path, or recently dropped reads as attacker-supplied.
3. False-positive check: legitimate .NET application uninstall/rollback during software deployment tooling (msiexec, CI agents).
**Escalation:** assembly confirms on VT, or the parent is a shell, script host, or Office process rather than deployment tooling → page the IR lead and isolate the host.

###### 5. Remediation & Evidence Preservation

- Collect and hash the assembly named on `CommandLine` before removal; capture the full process tree.
- Remove the assembly and whatever persistence launched it (scheduled task, service, Run key); hunt the assembly hash fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_lateral_tool_parent"></a>
##### Shell Spawned by PsExec Service or WMI Provider Host

**Rule file:** `rules/sigma/proc_creation_win_lateral_tool_parent.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Lateral Movement |
| Technique(s) | T1021 — Remote Services; T1569.002 — System Services: Service Execution |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `cmd.exe` or `powershell.exe` launched with `PSEXESVC.exe` or `WmiPrvSE.exe` as the parent process |

Detects a shell spawned by the PsExec service or the WMI Provider Host — a common indicator of lateral movement via PsExec or WMI-based remote command execution. This alert fires on the **target** host of the remote session; the launching side is covered separately by `proc_creation_win_psexec_client_side_launch.yml`.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which shell was spawned (`\cmd.exe` / `\powershell.exe`) |
| `ParentImage` | rule detection block | Remote-execution vector (`\PSEXESVC.exe` = PsExec, `\WmiPrvSE.exe` = WMI) |
| `CommandLine` | event source (Sysmon EID 1) | The actual command executed remotely — the substantive evidence |
| `ParentCommandLine` | event source (Sysmon EID 1) | Service/provider invocation context |
| `User` | event source (Sysmon EID 1) | Account the remote session runs as — drives credential-reset scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the shell binary (Microsoft-signed; TI applies to follow-on binaries) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Target host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of any binary the spawned shell subsequently executes or drops (from its child EID 1 events) → VirusTotal; escalate at **≥ 5 malicious verdicts**. The shell and parent themselves are signed system binaries.
- Internal-only: identify the source host via the correlated network logon for `User` (Security 4624, network/service logon) and, for PsExec, the paired service-install signal (`system_win_remote_service_creation_psexec_style.yml`); check whether source + account match a known admin workflow.
- The parent pairing proves remote execution, not intent — cite an admin-workflow miss plus a TI verdict or internal case ID before calling it malicious.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the target host when a follow-on binary's VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : (*\\cmd.exe or *\\powershell.exe) and process.parent.name : ("PSEXESVC.exe" or "WmiPrvSE.exe")
   ```
2. Process-tree analysis: enumerate every child of the spawned shell (`process.parent.name : ("cmd.exe" or "powershell.exe")` on the same host, ±30 min) — recon or credential-access commands change the verdict; sweep other hosts for the same parent pairing to size the movement.
3. False-positive check: authorized remote administration via PsExec or WMI by IT/helpdesk staff.
**Escalation:** the source host is not a known admin workstation, the account is non-IT, or the shell ran discovery/credential commands → page the IR lead; treat as active lateral movement and identify the source-side foothold.

###### 5. Remediation & Evidence Preservation

- Capture the full child-process tree of the shell and the correlated logon events before cleanup; for PsExec, remove PSEXESVC service remnants on the target.
- Reset the credentials used for the remote session; sweep the fleet for the same parent pairing and for the source host's other outbound sessions.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_lazagne_credential_harvest"></a>
##### LaZagne Credential Harvester Execution

**Rule file:** `rules/sigma/proc_creation_win_lazagne_credential_harvest.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1555 — Credentials from Password Stores |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | A `lazagne` token in the image path, `OriginalFileName`, or command line combined with a module-category or output-format argument — OR the module-category keyword (` all`, ` browsers`, ` windows`) paired with an output switch (` -oN`/` -oJ`) with no name match at all |

Detects the LaZagne credential harvester by its distinctive argument surface: no common Windows tool combines a module-category keyword with those output-format switches, so the pairing is a real signal even with no filename match. The second firing path exists because LaZagne's official builds are PyInstaller EXEs that often ship with no populated `OriginalFileName`, so a renamed binary defeats every name check — the category+output pairing survives that rename. Accepted limits stated by the rule: a renamed binary invoked with no arguments, or a category keyword with no output switch, still evades it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Binary path; a `lazagne` token here is near-conclusive |
| `OriginalFileName` | rule detection block | PE-header name; often empty on PyInstaller builds — absence is expected, not exonerating |
| `CommandLine` | rule detection block | Which firing path matched: `lazagne` token, category keyword, output switch — and the report output path |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (interactive shell vs. remote-execution service) |
| `User` | event source (Sysmon EID 1) | Whose credential stores were in reach |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary — primary TI artifact |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts**. Public LaZagne builds are widely detected — a clean verdict on a category+output hit supports the tool-collision explanation below.
- Internal-only: check prior case history for authorized credential-hygiene assessments; confirm with the security team before treating a self-test as an incident.
- A hit lacking a `lazagne` token anywhere and lacking a TI verdict stays "unconfirmed tool collision" until evidence says otherwise.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the binary's VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *lazagne* or process.pe.original_file_name : *lazagne* or process.args : *lazagne*
   ```
   For the rename-surviving path (no `lazagne` token anywhere), query `process.args : (*-oN* or *-oJ*)` and review hits for an adjacent module-category keyword (`all`, `browsers`, `windows`).
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; look for the report file written at the `-oN`/`-oJ` output path.
3. False-positive checks: a security team running LaZagne during an authorised credential-hygiene assessment; and the rule's own documented collision class — the category+output pairing has no name anchor, so an unrelated tool combining those tokens (e.g. nmap's `-p all -oN <file>`) also matches. Triage any hit that lacks `lazagne` anywhere on the command line as this collision class first, before escalating as credential harvesting.
**Escalation:** VT confirms the binary, a `lazagne` token is present, or a harvester report file is found on disk → page the IR lead; treat every credential store on the host as read.

###### 5. Remediation & Evidence Preservation

- Collect and hash the binary and any `-oN`/`-oJ` report files before deletion — the report enumerates exactly which credentials were exposed.
- Force resets for all credentials in the harvested stores (browser-saved, Windows vault, Wi-Fi, application creds for `User`); hunt post-event use of those credentials from other hosts.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_local_acct_create"></a>
##### Local User Account Creation via Net.exe

**Rule file:** `rules/sigma/proc_creation_win_local_acct_create.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1136.001 — Create Account: Local Account |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `net.exe` or `net1.exe` with a command line containing both `user` and `/add` |

Detects the creation of a local user account using the `net user` command — a persistence method that gives an attacker a foothold account independent of any compromised credential.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\net.exe` / `\net1.exe` |
| `CommandLine` | rule detection block | Carries the created account name (token after `user`) and any password set inline |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Provisioning script vs. interactive shell vs. remote-execution service |
| `User` | event source (Sysmon EID 1) | Who created the account — must already hold local admin |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of net.exe (Microsoft-signed; TI applies to the parent binary) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (net.exe itself is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: correlate with the matching Security 4720 event for ground truth on the created account; check provisioning/change records and asset ownership for a sanctioned setup at this time.
- An account creation is an event, not an incident — cite the provisioning-record miss plus corroborating evidence before escalating.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; when the parent-binary VT verdict is ≥ 5 malicious, auto-add that hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : (*\\net.exe or *\\net1.exe) and process.args : "user" and process.args : "/add"
   ```
2. Identity sweep: extract the account name from `process.args`; check for a follow-on `net localgroup administrators <name> /add` on the same host, and for logons by the new account (Security 4624) after creation.
3. False-positive check: initial workstation setup or provisioning scripts.
**Escalation:** the new account is added to a privileged local group, logs on interactively/remotely shortly after creation, or the creating parent is a shell spawned by a remote-execution service → disable the account, promote to the high-severity flow, and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the account's creation and logon events; screenshot/export its group memberships before removal.
- Disable then delete the unauthorized account; revert any group additions; reset the creating account's credentials if its own compromise is suspected.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_lsass_dump"></a>
##### LSASS Memory Dump via Comsvcs.dll

**Rule file:** `rules/sigma/proc_creation_win_lsass_dump.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1003.001 — OS Credential Dumping: LSASS Memory |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `rundll32.exe` launched with a command line containing both `comsvcs.dll` and `MiniDump` |

Detects `rundll32.exe` invoking the exported MiniDump function of `comsvcs.dll` to write LSASS process memory to disk — a living-off-the-land credential-dumping method that needs no attacker tooling. Rule falsepositives: rare legitimate debugging operations.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\rundll32.exe`) |
| `CommandLine` | rule detection block | Carries the target PID and the dump output file path |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (shell, script host, service) |
| `User` | event source (Sysmon EID 1) | Account context; drives credential-reset scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from the parent's own Sysmon EID 1 event — `rundll32.exe` itself is Microsoft-signed) → VirusTotal; treat as confirmed-malicious at **≥ 5 malicious verdicts**.
- Dump output path parsed from `CommandLine` → internal-only: confirm the file exists, quarantine it. The dump is evidence, not a TI artifact.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Comsvcs MiniDump has no routine administrative use; behavioral confidence is high even without a TI verdict, but record the rule ID and the verbatim event as the cited evidence — do not assert attribution.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; disable the initiating account on analyst confirm.
**Analyst triage path** (no TI-confirmable artifact) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; this channel is ECS-mapped — note `process.args`, not `process.command_line`):
   ```
   process.executable : *\\rundll32.exe and process.args : *comsvcs.dll* and process.args : *MiniDump*
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; sweep the host ±30 min for sibling children of the same parent.
3. False-positive check: sanctioned debugging session? Confirm against the change calendar and the EDR console operator log.
**Escalation:** dump file confirmed on disk, or a non-interactive parent (service host, WmiPrvSE, script engine) → page the IR lead; treat every credential with a session on the host as exposed.

###### 5. Remediation & Evidence Preservation

- Acquire full host memory **before** any cleanup or reboot; collect and hash the dump output file.
- Force password resets for every account with a session on the host; revoke Kerberos tickets and cached sessions for those accounts; hunt post-event authentications by those accounts from new source hosts.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_mimikatz_module_syntax"></a>
##### Mimikatz Module Syntax on the Command Line

**Rule file:** `rules/sigma/proc_creation_win_mimikatz_module_syntax.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1003.001 — OS Credential Dumping: LSASS Memory |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | Any process command line containing a Mimikatz `module::function` token: `sekurlsa::`, `lsadump::`, `privilege::debug`, `kerberos::golden`, `kerberos::ptt`, `crypto::capi`, or `misc::memssp` |

Detects Mimikatz driven by its distinctive module syntax. The rule deliberately does NOT match the filename `mimikatz.exe` — renaming the binary is the first thing any operator does — so it survives that specific evasion. Its stated blind spots: Mimikatz driven interactively at its own `mimikatz #` prompt puts none of these strings on the launching command line (no console-input telemetry exists in this environment to close that gap), and the reflective in-memory case (`Invoke-Mimikatz`) is not covered here either — pair with `posh_ps_obfuscated_scriptblock.yml` / script-block logging (4104) for that.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `CommandLine` | rule detection block | Which module::function tokens ran — determines the compromise scope (see Remediation) |
| `Image` | event source (Sysmon EID 1) | The actual binary path — the rule ignores the name, so this reveals what the tool was renamed to |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary — primary TI artifact |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector |
| `User` | event source (Sysmon EID 1) | Account context; must be privileged for most modules to succeed |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; **≥ 5 malicious verdicts** confirms the binary, but containment does not wait for it (critical policy row).
- Internal-only: check the red-team engagement calendar and detection-validation schedule — the documented false-positive population for this rule.
- Per policy, the 8 critical rules are behaviorally conclusive: the rule match plus the verbatim event is the cited evidence. Record both in the case; still never assert attribution.

###### 4. Containment Decision Flow

**Auto-containment:** severity critical → Tier A: EDR network isolation + AD/IdP account disable + Kerberos-ticket/session revocation execute automatically on the rule match itself; the IR lead is paged. Analyst steps below run post-containment.
**Analyst triage path** (verification after auto-containment):
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.args : (*sekurlsa\:\:* or *lsadump\:\:* or *privilege\:\:debug* or *kerberos\:\:golden* or *kerberos\:\:ptt* or *crypto\:\:capi* or *misc\:\:memssp*)
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; sweep the host ±60 min for the binary's arrival (download, copy, archive extraction) and for sibling executions.
3. False-positive checks: security staff running Mimikatz deliberately during an authorised red-team exercise or a detection-validation test; documentation, training material, or a detection rule file quoted verbatim on a command line. Confirm against the engagement calendar before releasing containment.
**Escalation:** already paged by Tier A. Additionally: `lsadump::` or `kerberos::golden` tokens present → declare a domain-level incident (see Remediation), not a single-host one.

###### 5. Remediation & Evidence Preservation

- Acquire full host memory before cleanup; collect and hash the executing binary (whatever its name) and any output files.
- Scope by module: `sekurlsa::` → reset every credential with a session on the host; `lsadump::` (incl. dcsync syntax) → treat domain credential material as exposed; `kerberos::golden` → treat the krbtgt key as compromised and perform the double krbtgt reset; `kerberos::ptt` → revoke and reissue tickets for the affected accounts; `misc::memssp` → remove the injected SSP and reset every credential entered on the host since infection.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_mshta_remote"></a>
##### Mshta Remote or Script Payload Execution

**Rule file:** `rules/sigma/proc_creation_win_mshta_remote.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.005 — System Binary Proxy Execution: Mshta |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `mshta.exe` with a command line containing `http`, `javascript`, or `vbscript` |

Detects mshta.exe proxy-executing a remote HTA or an inline javascript/vbscript payload (System Binary Proxy Execution). Promoted from threat hunt HUNT-001.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\mshta.exe` |
| `CommandLine` | rule detection block | Carries the remote URL or the inline `javascript:`/`vbscript:` payload — the primary artifact |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector — Office processes and mail-borne shortcuts are the classic launchers |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of mshta.exe (Microsoft-signed; TI applies to the URL and fetched payload) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- URL/domain parsed from `CommandLine` → AlienVault OTX; escalate on **any pulse match**.
- SHA-256 of the fetched HTA/payload (retrieve from disk, browser cache, or the correlated Sysmon file events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: is the domain an internal admin-tooling host? Rare legitimate HTA tooling exists — check asset records.
- Do not call the URL malicious without the OTX pulse, VT verdict, or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host on an OTX pulse for the URL/domain or a payload VT verdict ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *\\mshta.exe and process.args : (*http* or *javascript* or *vbscript*)
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args` for the delivery vector; enumerate mshta's children — a spawned shell or script host confirms payload execution.
3. False-positive check: rare legitimate HTA-based administrative tooling.
**Escalation:** mshta spawned children, the URL is external and newly registered, or the parent is an Office/mail process → page the IR lead and isolate the host; sweep the fleet for other requests to the same URL.

###### 5. Remediation & Evidence Preservation

- Retrieve and hash the HTA/payload; export mshta's child-process tree and any files it dropped.
- Block the URL/domain at perimeter and DNS once TI-confirmed; remove dropped payloads and any persistence they installed; hunt the payload hash fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_msiexec_remote"></a>
##### MSI Package Installed from a Remote URL

**Rule file:** `rules/sigma/proc_creation_win_msiexec_remote.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.007 — System Binary Proxy Execution: Msiexec |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `msiexec.exe` with an install verb immediately adjacent to an http URL on the command line (`/i http`, `/i"http`, `-i http`, `/package http`, `/a http`) |

Detects msiexec.exe installing a package directly from an http(s) URL rather than a local or UNC path — a common technique for delivering a signed-binary-proxied payload past naive allowlisting. The rule matches the install-verb-adjacent-to-URL phrase directly rather than the flag and `http` as independent floating tokens, since the latter also matches routine deployments that pass an unrelated URL-valued MSI property (e.g. `SERVERURL=https://...`) alongside a purely local package path.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\msiexec.exe` |
| `CommandLine` | rule detection block | Carries the install verb and the package URL — the primary artifact |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Deployment agent vs. shell/script host |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of msiexec.exe (Microsoft-signed; TI applies to the URL and the MSI) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- Package URL/domain from `CommandLine` → AlienVault OTX; escalate on **any pulse match**.
- SHA-256 of the fetched MSI (retrieve from the URL or the Windows Installer cache `C:\Windows\Installer`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: is the URL an internal software-repository host? Check deployment-tooling records and the change calendar.
- Do not label the package malicious without the citing OTX/VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on OTX pulse or MSI VT verdict ≥ 5 malicious, auto-add the domain/URL to the perimeter/DNS blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *\\msiexec.exe and process.args : ("/i" or "-i" or "/package" or "/a") and process.args : http*
   ```
   Confirm on the raw command line that the URL is the package argument directly adjacent to the install verb — an unrelated URL-valued property beside a local package path is not a match for this rule.
2. Process-tree analysis: pivot on `process.parent.name`; enumerate what the installed package wrote and executed (msiexec's children and correlated file events).
3. False-positive check: enterprise software deployment tools that legitimately push MSIs from an internal HTTP repository.
**Escalation:** external URL with an OTX pulse, an unsigned or VT-confirmed MSI, or a shell/Office parent → promote to the high-severity flow (Tier B host isolation) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Retrieve and hash the MSI (installer cache or re-fetch in a sandbox); export the package's file-write and child-process activity.
- Uninstall the package, remove files and persistence it installed, and block the source domain once TI-confirmed; hunt the MSI hash and URL fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_net_share_recon"></a>
##### Network Share Enumeration via net.exe

**Rule file:** `rules/sigma/proc_creation_win_net_share_recon.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1135 — Network Share Discovery |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `net.exe`/`net1.exe` (by path or `OriginalFileName`) with ` view` or ` share` on the command line |

Detects `net view` (list shares/computers reachable from this host) and bare `net share` (list this host's own shares) — standard early discovery steps that reveal lateral-movement targets. The rule states its own scope honestly: this activity is genuinely common in normal IT administration, so it is deliberately a lower-confidence signal whose real value is correlation with the other discovery-stage rules, not a standalone high-confidence detection.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\net.exe` / `\net1.exe` |
| `OriginalFileName` | rule detection block | Catches a renamed copy of net.exe by its PE-header name |
| `CommandLine` | rule detection block | `view` vs. `share`, and any target host argument |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive admin shell vs. script vs. remote-execution service |
| `User` | event source (Sysmon EID 1) | Account context — recon by a non-IT account is the interesting case |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary — TI check for a renamed/planted copy |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts** (only meaningful for a renamed or planted binary — the stock system copy is Microsoft-signed).
- Internal-only: asset owner and role of `User` and `Computer`; case history for an active investigation on this host; login/logon-script inventory for sanctioned share enumeration.
- Enumeration alone is never labeled malicious — it escalates only through correlation with other discovery-stage or lateral-movement signals, or a TI-confirmed follow-on artifact.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on a VT verdict ≥ 5 malicious for the executing binary, auto-add the hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   (process.executable : (*\\net.exe or *\\net1.exe) or process.pe.original_file_name : ("net.exe" or "net1.exe")) and process.args : ("view" or "share")
   ```
2. Correlation sweep: query the same host ±30 min for the other discovery-stage rules (`proc_creation_win_nltest_discovery`, `proc_creation_win_domain_group_discovery`, `proc_creation_win_user_discovery`) and for subsequent SMB/logon activity toward hosts the enumeration would have revealed.
3. False-positive checks: routine IT/helpdesk troubleshooting of a mapped-drive or file-share access issue; login/logon scripts or asset-inventory tooling that enumerate shares as part of normal operation.
**Escalation:** the same host fires multiple discovery-stage rules in one window, or share enumeration is followed by new SMB sessions to the enumerated targets → treat as a recon chain, promote to intrusion triage, and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the host's process-creation slice for the window — the discovery command sequence is the recon fingerprint.
- No host artifact to clean for the enumeration itself; remediation follows whatever the correlation sweep uncovers (lateral movement, planted tooling).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_netsh_firewall_rule_added"></a>
##### Firewall Rule Added via netsh

**Rule file:** `rules/sigma/proc_creation_win_netsh_firewall_rule_added.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1562.004 — Impair Defenses: Disable or Modify System Firewall |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `netsh.exe` (by path or `OriginalFileName`) with `advfirewall firewall add` or `firewall add` on the command line |

Detects `netsh advfirewall firewall add rule` / `netsh firewall add`, which opens an inbound or outbound path through the host firewall — commonly used to permit a C2 listener or an exfiltration channel, or to disable protection ahead of further action. Stated blind spot: this rule sees only the netsh-driven method; it has NO visibility into the `New-NetFirewallRule` PowerShell cmdlet path, which can add the identical rule without ever invoking netsh.exe.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\netsh.exe` |
| `OriginalFileName` | rule detection block | Catches a renamed netsh copy by its PE-header name |
| `CommandLine` | rule detection block | Full rule definition: direction, port, protocol, and the `program=` binary it permits |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Deployment automation vs. shell/script host |
| `User` | event source (Sysmon EID 1) | Account context — requires elevation |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of netsh.exe (Microsoft-signed; TI applies to the permitted program) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the binary named in the rule's `program=` argument (collect from disk) → VirusTotal; escalate at **≥ 5 malicious verdicts** — the permitted program is the substantive artifact.
- Internal-only: correlate the rule's direction/port/program against the change calendar and deployment records (the rule's own falsepositive guidance).
- Do not label the firewall change malicious without the citing VT verdict on the permitted program or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on a VT verdict ≥ 5 malicious for the permitted program, auto-add that hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   (process.executable : *\\netsh.exe or process.pe.original_file_name : "netsh.exe") and process.args : "firewall" and process.args : "add"
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; parse the full rule parameters from `process.args` and inspect the `program=` binary on disk (signature, path, drop time).
3. False-positive check: legitimate IT/deployment automation opening a required port for a new service — correlate the rule's direction/port/program against the change calendar.
**Escalation:** the rule permits an unsigned or user-writable-path program, opens an inbound port outside any change window, or the parent is a shell spawned by a remote-execution service → promote to the high-severity flow and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the full rule definition (`netsh advfirewall firewall show rule`) and hash the permitted binary before any change.
- Delete the unauthorized rule; remove the permitted binary and its persistence if TI-confirmed; audit the host firewall config for further additions, including any made via the PowerShell path this rule cannot see.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_netsh_portproxy_relay"></a>
##### Port-Proxy Relay Configured via netsh

**Rule file:** `rules/sigma/proc_creation_win_netsh_portproxy_relay.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1090.001 — Proxy: Internal Proxy |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `netsh.exe` (by path or `OriginalFileName`) with the contiguous phrase `portproxy add` on the command line |

Detects `netsh interface portproxy add v4tov4`, which configures the Windows TCP/IP stack itself to relay a local port to a remote host:port — a built-in, no-malware-required pivot/tunnel mechanism. No third-party tooling is needed and the relay survives process exit, which makes this a durable, low-footprint technique distinct from generic proxy/tunnel malware. The phrase is matched contiguously because the parameter names on a routine `delete` invocation also contain the substring `add`.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\netsh.exe` |
| `OriginalFileName` | rule detection block | Catches a renamed netsh copy by its PE-header name |
| `CommandLine` | rule detection block | Carries `listenport=`, `listenaddress=`, `connectport=`, `connectaddress=` — the relay's full wiring |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Deployment script vs. shell/remote-execution service |
| `User` | event source (Sysmon EID 1) | Account context — requires elevation |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of netsh.exe (Microsoft-signed; TI applies to the parent binary if suspect) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- `connectaddress=` IP from `CommandLine` → AbuseIPDB; escalate at **≥ 50% confidence score** — the relay's onward destination is the primary artifact.
- SHA-256 of the parent process binary → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: change calendar for a documented port-forward (container port exposure, WSL2 networking workaround); asset role of the connect target if internal.
- Do not label the relay malicious without the citing AbuseIPDB/VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the `connectaddress` IP scores ≥ 50% on AbuseIPDB or the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   (process.executable : *\\netsh.exe or process.pe.original_file_name : "netsh.exe") and process.args : "portproxy" and process.args : "add"
   ```
2. Relay-state check: run `netsh interface portproxy show all` on the host (EDR live response) — the relay persists after the process exits, so the alert may describe a still-active tunnel; identify who is connecting to the listen port from network telemetry.
3. False-positive check: a legitimate network engineer or deployment script configuring a documented port-forward (e.g. exposing a container's port, or a WSL2 networking workaround) — correlate against the change calendar.
**Escalation:** the `connectaddress` is external, the relay is live with established connections, or no change-calendar entry exists → page the IR lead; treat the host as a pivot node and trace both sides of the relay.

###### 5. Remediation & Evidence Preservation

- Record the full portproxy table and current connections to the listen port before teardown — the wiring is the evidence of what was reachable through the pivot.
- Delete the relay (`netsh interface portproxy delete v4tov4`), block the external `connectaddress` once TI-confirmed, and investigate the inbound peers that used the listen port.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_nltest_discovery"></a>
##### Domain Controller Discovery via Nltest

**Rule file:** `rules/sigma/proc_creation_win_nltest_discovery.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1018 — Remote System Discovery |
| Severity (`level`) | low |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `nltest.exe` with `/dclist:`, `/domain_trusts`, or `/dsgetdc:` on the command line |

Detects nltest.exe enumerating domain controllers or domain trusts — remote system discovery during recon. Deliberately demoted to low: a single execution floods on routine domain administration and is recorded (raw telemetry, hunting) rather than alerted on alone. The deployed enforcement is the Elastic threshold companion `rules/elastic/threshold/disc-win-nltest-discovery-repeat.ndjson` (severity medium): it alerts when **≥ 3** matching nltest executions occur on the same host (threshold field `host.name`, value 3) within its 10-minute detection window, evaluated every 10 minutes over a 20-minute lookback.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\nltest.exe` |
| `CommandLine` | rule detection block | Which enumeration verb ran and the target domain argument |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Admin console vs. script vs. remote-execution service |
| `User` | event source (Sysmon EID 1) | Account context — recon by a non-admin account is the interesting case |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the executing binary — TI check for a renamed/planted copy |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host (the companion's threshold key), timeline anchor, process-tree pivot |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts** (meaningful only for a non-stock copy — the system binary is Microsoft-signed).
- Internal-only: role of `User` and `Computer` (is this a domain admin's workstation?); case history; whether the companion threshold alert also fired for this host.
- A single nltest execution is telemetry, not an incident — escalate on repetition or correlation, with the evidence cited.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: triage-only — enrich and queue for analyst review; no automation. Higher-severity alerting is delegated to the threshold companion (medium), which follows the medium-flow policy when it fires.
**Analyst triage path:**
1. Verify and count with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *\\nltest.exe and process.args : (*dclist\:* or *domain_trusts* or *dsgetdc\:*)
   ```
   Bucket by `host.name` over 10-minute windows — ≥ 3 on one host mirrors the companion's alert condition.
2. Correlation sweep: same host ±30 min for the other discovery-stage rules (`proc_creation_win_net_share_recon`, `proc_creation_win_domain_group_discovery`, `proc_creation_win_user_discovery`) and for subsequent authentication toward the enumerated DCs.
3. False-positive check: domain administration and diagnostics.
**Escalation:** the threshold companion fires, or nltest recon co-occurs with other discovery/lateral-movement signals on the host → treat as a recon chain, promote to intrusion triage, and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the host's process-creation slice covering the enumeration window — verb sequence and cadence distinguish scripted recon from an admin's one-off diagnostic.
- No host artifact to clean for the enumeration itself; remediation follows what the correlation sweep uncovers.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_ntdsutil_ifm_dump"></a>
##### NTDS.dit Extraction via ntdsutil IFM Media Creation

**Rule file:** `rules/sigma/proc_creation_win_ntdsutil_ifm_dump.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1003.003 — OS Credential Dumping: NTDS |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `ntdsutil.exe` (by path or `OriginalFileName`) with both an NTDS-instance activation phrase (`ac i ntds` / `activate instance ntds`) and a media verb (`create full` / `ifm`) on the command line |

Detects ntdsutil.exe creating an Install-From-Media snapshot, which writes a copy of NTDS.dit (the full AD credential database) plus the SYSTEM hive to an operator-chosen path. Legitimate AD backup uses the identical syntax — the rule cannot separate the two on command line alone, so it is scoped to alert and be triaged against the change calendar, not to fire silently as high-confidence evil. Significant stated blind spot: the documented IFM workflow is normally driven interactively at successive `ntdsutil:` prompts, which puts none of the verbs on the launching command line — this rule only sees the less-common single-line form, and no console-input telemetry exists in this environment to close that gap.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\ntdsutil.exe` |
| `OriginalFileName` | rule detection block | Catches a renamed ntdsutil copy by its PE-header name |
| `CommandLine` | rule detection block | Activation phrase, media verb, and the destination path of the NTDS.dit/SYSTEM copy |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Backup scheduler vs. shell/remote-execution service |
| `User` | event source (Sysmon EID 1) | Must be a Domain Admin-equivalent for IFM to succeed — identity at stake |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of ntdsutil.exe (Microsoft-signed; TI applies to the parent binary if suspect) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host (a DC), timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary → VirusTotal; escalate at **≥ 5 malicious verdicts** (ntdsutil itself is Microsoft-signed).
- Destination path parsed from `CommandLine` → internal-only: confirm whether the IFM media exists there; the media is evidence, not a TI artifact.
- Internal-only: change calendar and backup schedule for a sanctioned IFM/backup job at this time; destination path plausibility (backup share vs. user-writable/removable/network staging path).
- Do not label the extraction malicious without the change-calendar miss plus corroborating evidence or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (usually no TI-confirmable artifact) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *\\ntdsutil.exe or process.pe.original_file_name : "ntdsutil.exe"
   ```
   Review `process.args` of each hit for the activation phrase plus `ifm`/`create full`. Querying the binary alone is deliberate: it also surfaces the interactive-console launches the rule itself cannot flag.
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; check the destination path for the written NTDS.dit/SYSTEM copies and any follow-on archiving or transfer of that media.
3. False-positive checks: a scheduled or operator-run Active Directory backup creating IFM media legitimately — correlate with the change calendar and the destination path. Note the rule's own caveat: the interactive-console form is invisible to this rule entirely, so absence of further alerts is not evidence of absence.
**Escalation:** no change-calendar entry, a staging-style destination (user-writable, removable, or network path), or follow-on compression/transfer of the media → page the IR lead immediately; treat as domain credential-database theft in progress.

###### 5. Remediation & Evidence Preservation

- Hash and secure the IFM output (NTDS.dit + SYSTEM hive) in place before removal; capture the process tree and any transfer activity.
- If theft is confirmed: assume every domain credential is exposed — perform the double krbtgt reset, force domain-wide password resets by tier, and revoke Kerberos tickets; delete the staged media only after hashing.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_pcalua_execution"></a>
##### Indirect Command Execution via Pcalua

**Rule file:** `rules/sigma/proc_creation_win_pcalua_execution.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1202 — Indirect Command Execution |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `pcalua.exe` with `-a` on the command line and a parent process other than `explorer.exe` |

Detects pcalua.exe (Program Compatibility Assistant) invoked with the `-a` flag from a parent that is not Explorer's own compatibility-troubleshooter flow. Legitimate PCA relaunches spawn `pcalua.exe -a` from explorer.exe; the identical command line spawned from a shell, script host, or Office application is the abuse case — the parent filter exists because without it the rule would be indistinguishable from the legitimate flow.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\pcalua.exe` |
| `CommandLine` | rule detection block | Carries the proxied target binary/command after `-a` — the primary artifact |
| `ParentImage` | rule detection block (filter) | Non-explorer parent is what fired the rule — identifies the abusing process |
| `ParentCommandLine` | event source (Sysmon EID 1) | Full context of the abusing parent |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of pcalua.exe (Microsoft-signed; TI applies to the proxied target) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **proxied target** binary named after `-a` (collect from disk or its own child EID 1 event) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: scheduled-task inventory for the documented benign edge case (a PCA relaunch driven by a task acting on the user's behalf).
- Do not label the target malicious without the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on a VT verdict ≥ 5 malicious for the proxied target, auto-add its hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : *\\pcalua.exe and process.args : "-a" and not process.parent.name : "explorer.exe"
   ```
2. Process-tree analysis: pivot both directions — upward on `process.parent.name` / `process.parent.args` (shell, script host, Office app?), and downward to the child pcalua spawned (the proxied target actually executing); inspect that binary on disk.
3. False-positive check: a legitimate PCA relaunch where explorer.exe is not the recorded parent (e.g. relaunched via a scheduled task acting on the user's behalf).
**Escalation:** the proxied target is unsigned or staged in a user-writable path, or the parent is an Office/mail process → promote to the high-severity flow and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect and hash the proxied target binary and export the two-sided process tree before cleanup.
- Remove the target binary and whatever persistence or document delivered the launching parent; hunt the target's hash fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_powershell_downloadstring"></a>
##### PowerShell Remote Download Cradle

**Rule file:** `rules/sigma/proc_creation_win_powershell_downloadstring.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution |
| Technique(s) | T1059.001 — Command and Scripting Interpreter: PowerShell; T1105 — Ingress Tool Transfer |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `powershell.exe`/`pwsh.exe` with a download-cradle token on the command line (`downloadstring`, `downloadfile`, `downloaddata`, `invoke-webrequest`, `invoke-restmethod`, `start-bitstransfer`, `webrequest::create`, `httpclient`) |

Detects PowerShell fetching (and typically executing) remote content via a WebClient/WebRequest/HttpClient/BITS download cradle — the classic fileless-payload delivery pattern. Stated overlap: this rule overlaps `proc_creation_win_powershell_encoded.yml` (the `-enc` flag itself) and `posh_ps_obfuscated_scriptblock.yml` (same technique on the 4104 script-block data source) — expect double-alerting where script-block logging is enabled; this rule covers hosts/configs where it isn't.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\powershell.exe` / `\pwsh.exe` |
| `CommandLine` | rule detection block | Carries the cradle token and the fetch URL — the primary artifacts |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (Office macro, script host, remote-execution service) |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the PowerShell binary (Microsoft-signed; TI applies to URL and payload) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- URL/domain parsed from `CommandLine` → AlienVault OTX; escalate on **any pulse match**.
- SHA-256 of the fetched payload (from disk via `downloadfile`/BITS destination, or the correlated Sysmon file events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: is the URL an internal config/update repository (the documented benign population)? Check deployment records.
- Do not call the URL or payload malicious without the citing OTX/VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host on an OTX pulse for the URL/domain or a payload VT verdict ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (TI not confirming) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : (*\\powershell.exe or *\\pwsh.exe) and process.args : (*downloadstring* or *downloadfile* or *downloaddata* or *invoke-webrequest* or *invoke-restmethod* or *start-bitstransfer* or *webrequest\:\:create* or *httpclient*)
   ```
2. Process-tree analysis: pivot on `process.parent.name` / `process.parent.args`; a cradle piped to `IEX` means the payload ran in-memory — check the same host's 4104 events (`posh_ps_obfuscated_scriptblock.yml`) for the script content, and enumerate PowerShell's children.
3. False-positive check: legitimate admin scripts that pull configuration or update files over HTTP.
**Escalation:** the URL is external with an OTX pulse, the payload executed (IEX or spawned children), or the parent is an Office/mail process → page the IR lead; sweep the fleet for other fetches of the same URL.

###### 5. Remediation & Evidence Preservation

- Capture the full command line and retrieve the payload (re-fetch in a sandbox if not on disk); hash it; export the child-process tree and correlated 4104 script blocks.
- Block the URL/domain once TI-confirmed; remove dropped files and any persistence installed; hunt the payload hash and URL fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_powershell_encoded"></a>
##### Suspicious PowerShell Encoded Command Execution

**Rule file:** `rules/sigma/proc_creation_win_powershell_encoded.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution |
| Technique(s) | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `powershell.exe`/`pwsh.exe` with a boundary-delimited `-EncodedCommand` or any of its `-`/`/`-prefixed abbreviations (`-e`, `-en`, `-enc`, `-enco…`, `-ec`, and the `/` mirrors), excluding command lines carrying the unrelated `-Encoding` cmdlet parameter |

Detects encoded PowerShell commands, a common obfuscation technique. The rule covers the abbreviation range because PowerShell resolves `-EncodedCommand` from any unambiguous prefix, and mirrors every entry with a `/` prefix since powershell.exe accepts `/` as a switch prefix identically to `-`. Documented residual gap: a tab-delimited `-enc` (tab as the argument separator, no adjacent space) still evades every entry — assessed low real-world likelihood and left as a stated gap rather than covered.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\powershell.exe` / `\pwsh.exe` |
| `CommandLine` | rule detection block | Carries the flag and the Base64 payload — decode it; the decoded script is the real evidence |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (Office macro, scheduled task, remote-execution service) |
| `User` | event source (Sysmon EID 1) | Account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the PowerShell binary (Microsoft-signed; TI applies to decoded artifacts) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- Decode the Base64 payload from `CommandLine` (UTF-16LE), then: SHA-256 of any payload the decoded script drops or fetches → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: compare the decoded script against known admin automation (deployment tooling legitimately uses encoding); check the correlated 4104 script-block events for the executed content.
- The encoded flag alone is not a verdict — the decoded content plus a cited TI verdict or internal case ID is what escalates it.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on a VT verdict ≥ 5 malicious for a decoded-payload hash, auto-add that hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   process.executable : (*\\powershell.exe or *\\pwsh.exe)
     and process.args : ("-e" or "-en" or "-enc" or -enco* or "-ec" or "-EncodedCommand" or "/e" or "/en" or "/enc" or /enco* or "/ec" or "/EncodedCommand")
     and not process.args : ("-Encoding" or -Encoding\:*)
   ```
2. Decode and read the payload; then process-tree analysis on `process.parent.name` / `process.parent.args` — an interactive admin console and a service-spawned encoded command are different verdicts.
3. False-positive check: legitimate administrative scripts that use encoding.
**Escalation:** the decoded script contains a download cradle, injection, credential access, or C2 addresses → promote to the high-severity flow (Tier B isolate on analyst confirm) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Preserve both the verbatim encoded command line and the decoded script as case evidence; export correlated 4104 events.
- Act on the decoded content: remove dropped payloads/persistence it created, block any embedded URLs/IPs once TI-confirmed, and hunt the same encoded string fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_psexec_client_side_launch"></a>
##### PsExec Client-Side Remote Execution Launch

**Rule file:** `rules/sigma/proc_creation_win_psexec_client_side_launch.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution, Lateral Movement |
| Technique(s) | T1569.002 — System Services: Service Execution |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `psexec.exe`/`psexec64.exe` (or `OriginalFileName` `psexec.c`) launched with a `\\host` remote-target argument on the command line |

Detects PsExec.exe itself being launched to initiate remote command execution — the LAUNCHING side of a PsExec deployment, complementary to the two target-side signals in this corpus: `system_win_remote_service_creation_psexec_style.yml` (the PSEXESVC service registered ON the target) and `proc_creation_win_lateral_tool_parent.yml` (a shell spawned WITH PSEXESVC.exe as parent, also on the target). The `\\host` remote-target argument is the trigger because it is what actually distinguishes "targets a remote host" from "runs locally"; `-accepteula` was deliberately dropped as an indicator — it is cached per-user after first run and also appears on purely local invocations.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms `\psexec.exe` / `\psexec64.exe` |
| `OriginalFileName` | rule detection block | Catches a renamed PsExec by its PE-header name (`psexec.c`) |
| `CommandLine` | rule detection block | Carries the `\\host` target(s), credentials flags, and the command to run remotely |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive admin shell vs. script vs. an already-compromised process |
| `User` | event source (Sysmon EID 1) | The account whose credentials drive the remote execution |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the PsExec binary — TI check for repacked/renamed variants |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Source host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 from `Hashes` → VirusTotal; escalate at **≥ 5 malicious verdicts** (the genuine Sysinternals binary is signed and clean — a hit here means a repacked variant).
- Internal-only: extract the target host from the `\\host` argument; check the change calendar and known admin workflows for a sanctioned deployment from this source host by this account.
- Do not label the launch malicious without the workflow miss plus corroborating target-side evidence or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action; on a VT verdict ≥ 5 malicious for the binary, auto-add its hash to the EDR blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-mapped channel):
   ```
   (process.executable : (*\\psexec.exe or *\\psexec64.exe) or process.pe.original_file_name : "psexec.c") and process.args : \\\\*
   ```
2. Cross-host pivot: on each target named in the `\\host` argument, look for the paired target-side signals — the PSEXESVC-style service creation and a shell with PSEXESVC.exe as parent — and for what the remote command actually did there.
3. False-positive check: legitimate administrative use of PsExec for remote troubleshooting or software deployment — a common, real IT-operations pattern; correlate the source host and target against the change calendar and known admin workflows.
**Escalation:** the target-side rules fire on the named host, the source is not an admin workstation, or the remote command is a shell/recon/credential command → treat as lateral movement in progress, promote to the high-severity flow, and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the source-side command line(s) and the target-side service/shell events as one correlated timeline — together they are the complete lateral-movement record.
- Reset the credentials of the account used; on each target, remove PSEXESVC remnants and whatever the remote command deployed; review the source host for the initial foothold.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_rar_archive_staging"></a>
##### Password-Protected Archive Staging via RAR/WinRAR

**Rule file:** `rules/sigma/proc_creation_win_rar_archive_staging.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Collection |
| Technique(s) | T1560.001 — Archive Collected Data: Archive via Utility |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `rar.exe`/`winrar.exe` (by image path or OriginalFileName) running the add-archive verb anchored directly after the binary name (`.exe a ` / `.exe" a `) with a space-separated password flag (` -p` or ` -hp`) |

Detects RAR creating a password-protected archive — the classic collection-staging step before exfiltration: bulk files are compressed and password-protected in one command, which both shrinks the transfer and defeats content-inspection egress controls that don't decrypt archives. The password requirement is deliberate: it is what separates staging-for-exfil from routine archiving, which rarely bothers with a password. The verb match is anchored to the binary name so an incidental " a " inside a filename on an extract command cannot fire it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Executing archiver path; a portable copy in a user-writable directory is itself suspicious |
| `OriginalFileName` | rule detection block | PE metadata catches a renamed `rar.exe`/`WinRAR.exe` |
| `CommandLine` | rule detection block | Verb, password flag, archive output path, and the file set being staged |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (interactive shell vs. script or C2 implant) |
| `User` | event source (Sysmon EID 1) | Account performing collection; scopes data-access review |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the archiver binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the executing archiver (`Hashes`) → VirusTotal; escalate at **≥ 5 malicious verdicts** (attacker-dropped portable RAR builds are frequently known; a clean verdict on the official WinRAR binary decides nothing by itself).
- Internal-only: archive output path and staged source paths parsed from `CommandLine` → data-classification and asset-owner lookup; change calendar for any sanctioned bulk transfer.
- The event carries no network artifact — egress confirmation comes from correlated network-family alerts, not from this event.
- An indicator here is only malicious with the citing VT verdict or an internal case ID; otherwise record it as unconfirmed.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the archiver-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : (*\\rar.exe or *\\winrar.exe) or process.pe.original_file_name : ("rar.exe" or "WinRAR.exe")
   ```
   The space-anchored verb (`.exe a `) and flag (` -p`/` -hp`) patterns cannot be expressed as KQL wildcards — confirm them by reading `process.args` in the returned events.
2. Process-tree pivot on `process.parent.name` / `process.parent.args`; sweep the host ±60 min for file-enumeration or discovery activity feeding the staged file set, and locate the archive on disk (path and size from the command line).
3. False-positive check: legitimate IT/backup tooling creating a password-protected archive for authorized data transfer — correlate the destination and archive contents against the change calendar.
**Escalation:** archive written to a network share or removable media, or any egress/exfiltration-family alert from the same host in the surrounding hour → treat as active exfiltration staging; page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect and hash the archive file before deletion; inventory the staged source paths to scope the data-exposure assessment (what would have left the estate).
- Remove the archive and, if the archiver is a dropped portable copy, the binary itself; hunt other hosts for the same archiver hash and command-line pattern.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_rdp_hijack_tscon"></a>
##### RDP Session Hijacking via Tscon

**Rule file:** `rules/sigma/proc_creation_win_rdp_hijack_tscon.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation, Lateral Movement |
| Technique(s) | T1574 — Hijack Execution Flow (per the rule's `attack.t1574` tag) |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `tscon.exe` executed with a command line containing `/dest:` |

Detects the use of tscon.exe to hijack an RDP session by passing a destination session ID. Redirecting a disconnected user's session to the attacker's own — without that user's credentials — requires SYSTEM context, so the parent lineage of the tscon call is the deciding triage signal.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\tscon.exe`) |
| `CommandLine` | rule detection block | Source session ID and `/dest:` target session name |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | SYSTEM-context shell or service parent = hijack pattern; help-desk tool = admin use |
| `User` | event source (Sysmon EID 1) | SYSTEM vs. named administrator decides intent plausibility |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (tscon itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from the parent's own Sysmon EID 1 event — `tscon.exe` is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: identify the owner of the `/dest:` target session (RDS session records / correlated logon telemetry); check the help-desk ticket queue and change calendar for a sanctioned session takeover.
- No external IP/domain artifact on this event — AbuseIPDB/OTX not applicable.
- Do not label the activity malicious without the citing VT verdict or an internal case ID; a SYSTEM-parent tscon is a strong behavioral signal but is documented as such, not asserted as attribution.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\tscon.exe and process.args : */dest\:*
   ```
2. Process-tree pivot: how did the caller obtain SYSTEM? Look for a preceding service creation, `sc config`, or scheduled-task alert on the same host; sweep the hijacked session's account for post-hijack activity.
3. False-positive check: IT administrators forcefully connecting to specific sessions — confirm the operator and ticket before closing.
**Escalation:** tscon parented by a SYSTEM-context process with no matching admin ticket, or the target session belongs to a privileged account → page the IR lead and treat the session owner's credentials and open applications as compromised.

###### 5. Remediation & Evidence Preservation

- Capture the RDS session records and the process tree before logoff clears them; screenshot/export the session ownership evidence.
- Force logoff of the hijacked session, reset the session owner's password, revoke their tokens and cached sessions; remove whatever privilege-escalation artifact gave the caller SYSTEM.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_reg_save_sam"></a>
##### SAM Hive Dump via Reg.exe

**Rule file:** `rules/sigma/proc_creation_win_reg_save_sam.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1003.002 — OS Credential Dumping: Security Account Manager |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `reg.exe` with a command line containing both `save` and `hklm\sam` |

Detects reg.exe saving the SAM registry hive to disk — offline credential theft (Credential Access). The saved hive yields local account password hashes once combined with the SYSTEM hive's boot key, so a companion `save hklm\system` on the same host is the expected second half of the technique.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\reg.exe`) |
| `CommandLine` | rule detection block | Hive saved and the output file path — the file to locate and quarantine |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (interactive admin shell vs. script host or implant) |
| `User` | event source (Sysmon EID 1) | Must already be elevated for the save to succeed; drives reset scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (reg.exe itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `reg.exe` is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Hive output path parsed from `CommandLine` → internal-only: confirm the file exists and quarantine it; the dump is evidence, not a TI artifact.
- Internal-only: change calendar and backup-runbook check for a sanctioned registry backup; case history for prior credential-access alerts on this host.
- No external IP/domain artifact on this event. Record the rule ID and the verbatim event as the cited evidence; do not assert attribution.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\reg.exe and process.args : *save* and process.args : *hklm\\sam*
   ```
2. Sweep the same host ±30 min for the companion saves: `process.args : (*hklm\\system* or *hklm\\security*)` — SAM plus SYSTEM confirms a usable credential dump, SECURITY adds cached domain credentials.
3. False-positive check: legitimate registry backups by administrators (rare; verify) — require the operator, ticket, and destination path to line up.
**Escalation:** companion SYSTEM/SECURITY hive save found, or the output file leaves the host (share path, subsequent archive/egress alert) → page the IR lead; treat every local account on the host as exposed.

###### 5. Remediation & Evidence Preservation

- Collect and hash the saved hive file(s), then remove them from disk; acquire the process tree and any staging directory contents.
- Rotate the local Administrator password (LAPS rotation if deployed) and all local accounts on the host; hunt for pass-the-hash-style logons using local accounts from this host afterward.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_regasm_regsvcs_bypass"></a>
##### Regasm/Regsvcs Proxy Execution

**Rule file:** `rules/sigma/proc_creation_win_regasm_regsvcs_bypass.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.009 — System Binary Proxy Execution: Regsvcs/Regasm |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `regasm.exe` or `regsvcs.exe` with a command line containing the `/u` uninstall switch or a user-writable staging path (`\appdata\`, `\temp\`, `\users\public\`, `\programdata\`, `\downloads\`) |

Detects regasm.exe or regsvcs.exe invoked with the uninstall switch (`/U`, the path attackers prefer since it runs the assembly's `[ComUnregisterFunction]`-attributed method) or against an assembly staged in a user-writable directory. A prior draft required a user-writable directory unconditionally, which a relative path or an unlisted directory trivially defeated; the `/U` flag is now matched independently of path.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Which proxy binary ran (`\regasm.exe` vs `\regsvcs.exe`) |
| `CommandLine` | rule detection block | `/u` switch and the target assembly path — the payload to collect |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Installer/CI runner vs. shell or script host |
| `User` | event source (Sysmon EID 1) | Service/build account vs. interactive user context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (the proxy binary itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the target **assembly** (collected from the path in `CommandLine`; the signed proxy binary's own hash is not the artifact of interest) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: software-deployment/CI calendar — is an install or build pipeline registering COM-interop assemblies on this host at this time? Asset role check (build agent vs. workstation).
- No external IP/domain artifact on this event.
- Without the VT verdict on the assembly or an internal case ID, log the finding as unconfirmed — the invocation shape alone does not prove a malicious payload.

###### 4. Containment Decision Flow

**Auto-containment:** Tier C — indicator block on TI-confirm: severity medium → on assembly VT verdict ≥ 5 malicious, auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : (*\\regasm.exe or *\\regsvcs.exe) and process.args : (*/u* or *\\appdata\\* or *\\temp\\* or *\\users\\public\\* or *\\programdata\\* or *\\downloads\\*)
   ```
2. Process-tree pivot: a shell, Office, or script-host parent outside an install window is the adversarial shape; check for children spawned by the proxy binary (the executed payload's follow-on activity).
3. False-positive check: legitimate .NET COM-interop assembly registration/unregistration during install or CI, especially from ProgramData or a temp staging directory.
**Escalation:** assembly VT-confirmed malicious, or the proxy binary spawns network-touching children with no matching deployment record → promote to the high-severity flow (Tier B isolate on analyst confirm) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect and hash the target assembly before deletion; capture the process tree including any children of the proxy binary.
- Remove the assembly and any registration artifacts it created; hunt other hosts for the same assembly hash or staging path.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_regsvr32_remote_sct"></a>
##### Regsvr32 Execution from Remote Server

**Rule file:** `rules/sigma/proc_creation_win_regsvr32_remote_sct.yml` · **Status:** stable · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.010 — System Binary Proxy Execution: Regsvr32 |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `regsvr32.exe` with a command line containing both `/i:http` and `scrobj.dll` |

Detects regsvr32.exe attempting to execute a remote script, known as the Squiblydoo bypass: the signed binary fetches a scriptlet over HTTP(S) and executes it via scrobj.dll, leaving no payload on disk before execution. Rule falsepositives: highly unlikely.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\regsvr32.exe`) |
| `CommandLine` | rule detection block | The full remote URL after `/i:` — the primary TI artifact — plus the scrobj.dll load |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (Office child, script host, shell) |
| `User` | event source (Sysmon EID 1) | Compromised account context; drives identity-kill scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (regsvr32 itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- Remote URL/domain parsed from `CommandLine` → AlienVault OTX; escalate on **any pulse match** for the URL or its registered domain.
- SHA-256 of the **parent** process binary and of any scriptlet retrieved for analysis → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: proxy/Zeek logs for whether the fetch succeeded and what answered.
- Per policy the critical-severity rule match plus the verbatim event is itself the cited evidence for containment; TI enrichment scopes the campaign, it does not gate the response.

###### 4. Containment Decision Flow

**Auto-containment:** Tier A — auto-isolate + identity kill: severity critical → EDR network isolation plus AD/IdP account disable and token/session/Kerberos-ticket revocation execute automatically on the rule match (no TI gate); the IR lead is paged.
**Analyst triage path (post-containment validation):**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\regsvr32.exe and process.args : */i\:http* and process.args : *scrobj.dll*
   ```
2. Process-tree pivot on `process.parent.name` / `process.parent.args` for the delivery vector; correlate Zeek http/dns for the URL fetch and enrich the serving IP/domain; sweep other hosts for the same URL.
3. False-positive check: the rule lists falsepositives as highly unlikely — an authorized red-team exercise window is effectively the only benign explanation; confirm against the exercise calendar before standing down.
**Escalation:** already at Tier A. Confirmed successful fetch (Zeek shows the scriptlet delivered) or the same URL on additional hosts → declare an active-intrusion incident and widen containment to those hosts.

###### 5. Remediation & Evidence Preservation

- Acquire host memory before reboot (the scriptlet payload may exist only in memory); export the Zeek http/dns slice for the URL and preserve the retrieved scriptlet if obtainable from a controlled environment.
- Perimeter/DNS-block the serving domain and IP; remove any persistence the scriptlet established (run keys, scheduled tasks, services) found in the follow-on process tree; reset the isolated user's credentials before re-enable.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_run_key_persistence"></a>
##### Registry Run Key Persistence via Reg.exe

**Rule file:** `rules/sigma/proc_creation_win_run_key_persistence.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `reg.exe` with a command line containing both `add` and `CurrentVersion\Run` |

Detects creation of an autorun entry under a CurrentVersion\Run key using reg.exe add — a common persistence mechanism. The command line names both the value written and the binary that will launch at logon, so the persistence payload is recoverable directly from this event.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\reg.exe`) |
| `CommandLine` | rule detection block | Run key hive (HKLM vs HKCU), value name, and the autorun target binary path |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Installer vs. shell/script-host delivery |
| `User` | event source (Sysmon EID 1) | HKCU writes scope to this user; HKLM writes imply elevation |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (reg.exe itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **autorun target binary** (collected from the path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: software-deployment calendar and installer inventory — does the value name/target match a package being rolled out? Case history for the same value name on other hosts.
- No external IP/domain artifact on this event.
- A run-key write is routine installer behavior; call it persistence only with the citing VT verdict on the target binary or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier C — indicator block on TI-confirm: severity medium → on target-binary VT verdict ≥ 5 malicious, auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\reg.exe and process.args : *add* and process.args : *CurrentVersion\\Run*
   ```
2. Collect and hash the autorun target binary; process-tree pivot on the parent — an Office, browser, or script-host ancestor turns a routine-looking write adversarial. Sweep other hosts for the same value name or target path.
3. False-positive check: installers legitimately registering startup entries.
**Escalation:** target binary VT-confirmed malicious, unsigned, or living in a user-writable path with a non-installer parent → promote to the high-severity flow (Tier B isolate on analyst confirm).

###### 5. Remediation & Evidence Preservation

- Export the Run key value (name + data) and collect/hash the target binary before removal.
- Delete the autorun value, remove the target binary, and re-scan the host's other autostart locations for siblings dropped in the same window.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_rundll32_inline_script"></a>
##### Rundll32 Executing Inline Script via mshtml

**Rule file:** `rules/sigma/proc_creation_win_rundll32_inline_script.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1218.011 — System Binary Proxy Execution: Rundll32 |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `rundll32.exe` with a command line containing `javascript:`, `vbscript:`, `runhtmlapplication`, or `mshtml` |

Detects rundll32.exe invoked with an inline `javascript:` or `vbscript:` payload via the `RunHTMLApplication` mshtml.dll export — a signed-binary proxy execution technique that runs attacker script without dropping a file. Both moniker forms achieve identical execution; anchoring only on `javascript:` (as a prior draft did) is trivially bypassed by `vbscript:`, so both monikers and the shared `mshtml`/`RunHTMLApplication` invariant are matched.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\rundll32.exe`) |
| `CommandLine` | rule detection block | The inline script itself — the payload is in this field, nowhere on disk |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Delivery vector (Office, browser, shell, script host) |
| `User` | event source (Sysmon EID 1) | Compromised account context |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (rundll32 itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `rundll32.exe` is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: read the inline script verbatim from `CommandLine` — it is the complete payload; record what it stages, fetches, or launches as evidence in the case.
- The inline-moniker pattern has no routine administrative use, but behavioral confidence is documented against the rule ID and the verbatim event — no attribution without a cited verdict or internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\rundll32.exe and process.args : (*javascript\:* or *vbscript\:* or *runhtmlapplication* or *mshtml*)
   ```
2. Process-tree pivot: capture children of the rundll32 instance (the script's follow-on actions) and the parent lineage; correlate any network activity from the host in the same minute window via Zeek.
3. False-positive check: extremely rare in legitimate administration; effectively none — verify only an authorized-exercise window before standing down.
**Escalation:** script content shows a download/launch stage, or the rundll32 instance spawned children → page the IR lead and treat the host as compromised pending containment.

###### 5. Remediation & Evidence Preservation

- Preserve the full `CommandLine` verbatim (it is the payload); acquire host memory if the script launched follow-on activity, since subsequent stages may be memory-only.
- Remove any persistence or dropped files identified from the script's actions; reset the initiating account's credentials if follow-on execution is confirmed.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_sc_config_binpath_change"></a>
##### Existing Service Reconfigured to a New Binary Path

**Rule file:** `rules/sigma/proc_creation_win_sc_config_binpath_change.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1543.003 — Create or Modify System Process: Windows Service |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `sc.exe` (by image path or OriginalFileName) with a command line containing the ` config ` verb and `binpath=` |

Detects `sc.exe config <service> binpath= <value>`, which changes what binary an already-existing service launches — stealthier than creating a new service because the service name, description, and any existing allow-listing stay unchanged; only the payload running under its identity changes. Stated blind spot (security review #233): the equivalent change via the Win32 `ChangeServiceConfigW` API or a raw registry write to the service's `ImagePath` never invokes sc.exe, and this rule has no visibility into either path.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\sc.exe`) |
| `OriginalFileName` | rule detection block | PE metadata catches a renamed sc.exe |
| `CommandLine` | rule detection block | Target service name and the new `binpath=` value — the payload to collect |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Patch-management agent vs. shell/script-host delivery |
| `User` | event source (Sysmon EID 1) | Must be elevated to reconfigure a service; drives reset scope |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (sc.exe itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **new service binary** (collected from the `binpath=` value in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: change calendar for an in-place upgrade touching this service; service-inventory diff (what was the previous `binpath` value?); case history for the service name.
- No external IP/domain artifact on this event.
- Reconfiguration is only malicious with the citing VT verdict or an internal case ID; document the old-vs-new path diff either way.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the new service binary's VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   (process.executable : *\\sc.exe or process.pe.original_file_name : "sc.exe") and process.args : *binpath=*
   ```
   The space-delimited ` config ` verb cannot be anchored in a KQL wildcard — read `process.args` in the results to separate `config` (this rule) from `create` (the sibling service-creation rule).
2. Pivot: record the service's prior binary path, collect and hash the new target; check for a service start/restart and the new binary's own process-creation event following the change.
3. False-positive check: legitimate IT/patch-management tooling repointing a service's binary during an in-place upgrade — correlate the target service name and new path against the change calendar.
**Escalation:** new binpath points to a user-writable path, an unsigned binary, or embeds a command interpreter → page the IR lead; the payload runs with the service's (typically SYSTEM) identity.

###### 5. Remediation & Evidence Preservation

- Record the old and new `binpath` values and collect/hash the new target binary before reverting.
- Revert the service to its verified original binary path, remove the planted binary, then audit all services on the host for the same modification window (covers the API/registry route this rule cannot see).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_scheduled_task"></a>
##### Scheduled Task Creation via Schtasks

**Rule file:** `rules/sigma/proc_creation_win_scheduled_task.yml` · **Status:** stable · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution, Persistence |
| Technique(s) | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Severity (`level`) | low |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `schtasks.exe` with a command line containing both `/create` and `/tn` |

Detects the creation of a new scheduled task using schtasks.exe. Task creation is a high-volume administrative operation; the rule exists as a triage and correlation signal, and the command line carries the task name and action needed to judge each instance.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\schtasks.exe`) |
| `CommandLine` | rule detection block | Task name (`/tn`), action binary (`/tr`), trigger, and run-as principal (`/ru`) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Installer/management agent vs. shell or script host |
| `User` | event source (Sysmon EID 1) | Who registered the task; SYSTEM run-as requests need elevation |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (schtasks itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the task **action binary** (collected from the `/tr` value in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: software-deployment calendar (installers create tasks constantly); task-name conventions — names imitating Windows defaults or random strings are the anomaly; case history for the same task name estate-wide.
- No external IP/domain artifact on this event.
- Volume alone means nothing here: a task is flagged malicious only on the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier D — triage-only: severity low → enrich and queue for analyst review; no automation.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\schtasks.exe and process.args : */create* and process.args : */tn*
   ```
2. Judge the task action: collect/hash the `/tr` target; a script-host or shell parent, a user-writable action path, or `/ru system` from a non-admin context moves this out of routine. Sweep for the same task name on other hosts.
3. False-positive checks: software installations and updates; legitimate administrative tasks.
**Escalation:** action binary VT-confirmed malicious, or the task creation correlates with another alert on the same host in ±30 min → promote severity and follow the correlated rule's containment flow.

###### 5. Remediation & Evidence Preservation

- Export the task XML (name, trigger, action, principal) and collect/hash the action binary before deletion.
- Delete the task, remove the action binary, and check the other persistence surfaces on the host (Run keys, services) for siblings from the same window.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_service_creation_sc"></a>
##### Windows Service Creation via Sc.exe

**Rule file:** `rules/sigma/proc_creation_win_service_creation_sc.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1543.003 — Create or Modify System Process: Windows Service |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `sc.exe` with a command line containing both `create` and `binpath` |

Detects creation of a new Windows service with sc.exe, frequently abused for persistence and privilege escalation — the service binary runs under the service's identity (typically SYSTEM) at every boot. Reconfiguration of an existing service's path is the sibling rule `proc_creation_win_sc_config_binpath_change`; the SCM's own record of the install lands as a Windows System 7045 event covered by the System-log family.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\sc.exe`) |
| `CommandLine` | rule detection block | New service name and `binpath` — the binary that will run as the service |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Installer vs. shell/script-host delivery |
| `User` | event source (Sysmon EID 1) | Must be elevated; a lateral-movement context often shows a remote-exec parent |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (sc.exe itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **service binary** (collected from the `binpath` value in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: software-deployment calendar; service-name conventions (PsExec-style random or single-word names are the anomaly); correlated System 7045 event for the SCM's own record.
- No external IP/domain artifact on this event.
- Service installation is routine installer behavior — malicious only with the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier C — indicator block on TI-confirm: severity medium → on service-binary VT verdict ≥ 5 malicious, auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\sc.exe and process.args : *create* and process.args : *binpath*
   ```
2. Collect/hash the binpath target; pivot the parent lineage — a service created from a WMI or PsExec-style remote-execution parent chains into the lateral-movement rules. Confirm whether the service was started and what it spawned.
3. False-positive check: legitimate software installing a service.
**Escalation:** service binary VT-confirmed malicious, binpath embedding a command interpreter or user-writable path, or a remote-execution parent → promote to the high-severity flow (Tier B isolate on analyst confirm) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the service definition (name, binpath, start type) and collect/hash the service binary before removal.
- Stop and delete the service, remove the binary, and sweep the estate for the same service name or binary hash on other hosts.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_sharphound_bloodhound_collection"></a>
##### SharpHound / BloodHound AD Collection Execution

**Rule file:** `rules/sigma/proc_creation_win_sharphound_bloodhound_collection.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1087.002 — Account Discovery: Domain Account |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | "sharphound" appearing in the image path, OriginalFileName, or command line; or a command line containing `--collectionmethod`, `-CollectionMethod`, or `Invoke-BloodHound` |

Detects SharpHound.exe (the .NET collector) or its command-line ingestor flags, and the BloodHound Python collector's distinctive `--collectionmethod` argument syntax — one of the earliest observable indicators of an AD compromise-path reconnaissance campaign. Stated blind spot (security review #233): SharpHound run via an in-memory/reflective loader (e.g. Cobalt Strike's execute-assembly) creates no new process, so no image or command line ever contains the indicators; this is common tradecraft, not a theoretical edge case, and the rule has no visibility into it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Collector binary path (often a user-writable staging directory) |
| `OriginalFileName` | rule detection block | PE metadata catches a renamed SharpHound.exe |
| `CommandLine` | rule detection block | Collection method(s), domain target, and output zip path |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive operator shell vs. implant delivery |
| `User` | event source (Sysmon EID 1) | The domain account doing the enumeration — the identity to contain |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the collector — the primary TI artifact |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the executing collector binary (`Hashes`) → VirusTotal; escalate at **≥ 5 malicious verdicts** (public SharpHound builds are widely known to VT).
- Internal-only: authorized-assessment/purple-team exercise calendar — the one sanctioned use; the initiating account's role and normal workstation; case history for prior discovery alerts from this host or account.
- No external IP/domain artifact on this event.
- Without the VT verdict or a matching exercise/case record, report the run as unconfirmed collection tooling — do not attribute.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the collector-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *sharphound* or process.pe.original_file_name : *sharphound* or process.args : (*sharphound* or *--collectionmethod* or *-CollectionMethod* or *Invoke-BloodHound*)
   ```
2. Identity sweep: enumerate what the initiating account touched — correlate LDAP/session enumeration side effects (surrounding discovery-family and auth-family alerts) and locate the output zip on disk.
3. False-positive check: a security team running SharpHound/BloodHound during an authorised AD attack-path assessment or purple-team exercise — confirm against the exercise calendar and the named operator.
**Escalation:** no matching exercise record, or follow-on credential-access alerts (Kerberoasting, DCSync) involving the same account/host → page the IR lead; assume the domain's attack-path graph is in adversary hands.

###### 5. Remediation & Evidence Preservation

- Collect and hash the collector binary and the output zip (the zip shows exactly what the adversary learned); capture the process tree.
- Disable/reset the initiating account on confirmation; review the collected attack paths and prioritize breaking them (privileged-session hygiene, ACL fixes) — the graph the adversary built is the remediation worklist.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_spooler_child_process_printnightmare"></a>
##### Print Spooler Service Spawning a Suspicious Child Process

**Rule file:** `rules/sigma/proc_creation_win_spooler_child_process_printnightmare.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation |
| Technique(s) | T1068 — Exploitation for Privilege Escalation |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | Parent image `\spoolsv.exe` spawning `cmd.exe`, `powershell.exe`, `pwsh.exe`, `rundll32.exe`, `mshta.exe`, or `regsvr32.exe` |

Detects spoolsv.exe (the Print Spooler, running as SYSTEM) spawning a command interpreter or script/LOLBin host — the characteristic endpoint of the PrintNightmare family of vulnerabilities (CVE-2021-1675/34527) and similar spooler-driver-loading exploit chains. Stated blind spot (security review #233): an in-process-only payload — a malicious driver DLL running entirely inside spoolsv.exe without calling CreateProcess — leaves no process-creation trace; the rule only catches exploitation that goes on to spawn a child, and no telemetry currently collected in this environment covers the in-process case.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `ParentImage` | rule detection block | Confirms the spooler (`\spoolsv.exe`) as the spawning process |
| `Image` | rule detection block | Which interpreter/LOLBin the exploit launched |
| `CommandLine` | event source (Sysmon EID 1) | The attacker's first SYSTEM-context command — read it verbatim |
| `ParentCommandLine` | event source (Sysmon EID 1) | Spooler service invocation context |
| `User` | event source (Sysmon EID 1) | Expected SYSTEM — confirms the privilege level obtained |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 of the child binary for TI lookup |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the child binary (`Hashes`) and of any payload the child then executes → VirusTotal; escalate at **≥ 5 malicious verdicts** (the listed children are themselves signed Windows binaries — their command lines and descendants carry the signal).
- Internal-only: host patch level against the CVEs referenced by the rule; print-server role inventory; any third-party print-management product known to run helpers from spooler context.
- No external IP/domain artifact on this event.
- Per policy the critical-severity rule match plus the verbatim event is the cited evidence for containment; enrichment scopes the intrusion, it does not gate the response.

###### 4. Containment Decision Flow

**Auto-containment:** Tier A — auto-isolate + identity kill: severity critical → EDR network isolation plus account disable and token/session/Kerberos-ticket revocation execute automatically on the rule match (no TI gate); the IR lead is paged.
**Analyst triage path (post-containment validation):**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.parent.name : "spoolsv.exe" and process.executable : (*\\cmd.exe or *\\powershell.exe or *\\pwsh.exe or *\\rundll32.exe or *\\mshta.exe or *\\regsvr32.exe)
   ```
2. Process-tree analysis: follow every descendant of the spooler child — the exploit's SYSTEM shell is stage one, not the goal; look for the driver DLL drop preceding the spawn and for account creation, persistence, or credential access after it.
3. False-positive check: a third-party print-management or driver-installation product that legitimately launches a helper process from spoolsv.exe context — baseline and exclude the specific child image path if confirmed.
**Escalation:** already at Tier A. Host is a domain controller or print server serving many clients → declare a major incident; check every other host running the vulnerable spooler configuration for the same parent/child pattern.

###### 5. Remediation & Evidence Preservation

- Acquire host memory before reboot (the loaded malicious driver DLL may be memory-resident); collect the spooler driver directories and hash any recently written driver DLLs.
- Patch the CVEs the rule references, remove the malicious driver and any persistence created by the SYSTEM child, and rotate credentials for accounts with sessions on the host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_user_discovery"></a>
##### Suspicious System Owner/User Discovery

**Rule file:** `rules/sigma/proc_creation_win_user_discovery.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1033 — System Owner/User Discovery |
| Severity (`level`) | low |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `whoami.exe` with a command line containing `/all` |

Detects the execution of whoami.exe with the /all flag, commonly used by attackers for reconnaissance. Per issue #217 this file is the logic-of-record but is deliberately not deployed as a per-event alert (a single execution floods on routine admin troubleshooting); the deployed enforcement is the Elastic threshold companion `rules/elastic/threshold/disc-win-user-discovery-repeat.ndjson`, which alerts at **≥ 3 matching events on the same host (`host.name`)**, evaluated every 10 minutes over a 20-minute lookback, at severity **medium**. A single deliberate execution is still recorded in raw telemetry for hunting — it just is not alerted on alone.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\whoami.exe`) |
| `CommandLine` | rule detection block | The `/all` flag — full token/group/privilege enumeration |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Interactive admin shell vs. script or implant — the strongest FP separator |
| `User` | event source (Sysmon EID 1) | Whose context is being enumerated |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (whoami itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `whoami.exe` is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: help-desk/troubleshooting ticket queue for the host; whether the initiating account normally administers it; case history for other discovery alerts on the same host.
- No external IP/domain artifact on this event.
- Recon commands are only evidence of compromise in context — cite the correlated alert or case ID, never the whoami event alone.

###### 4. Containment Decision Flow

**Auto-containment:** Tier D — triage-only: severity low → enrich and queue for analyst review; no automation. Alert-volume gating lives in the threshold companion (≥ 3 per host / 20-minute lookback).
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel; the companion's own query shape):
   ```
   process.executable : *\\whoami.exe and process.args : */all*
   ```
   Count occurrences per host over the window — repetition is what the companion alerts on.
2. Burst and context check: a script-host or implant-style parent repeating the command is automated recon; sweep the host ±30 min for other discovery-family alerts (net.exe, nltest) forming a recon chain.
3. False-positive check: administrator troubleshooting.
**Escalation:** discovery chain (two or more distinct discovery-family rules on the same host within 30 min) or a non-interactive parent → promote severity and page per the correlated rule's flow.

###### 5. Remediation & Evidence Preservation

- Export the host's process-creation slice for the recon window — the command sequence is the evidence of what the operator learned.
- No host artifact to clean for the discovery itself; remediation follows whatever delivery vector the parent lineage reveals.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_vss_delete_shadows"></a>
##### Shadow Copy Deletion via Vssadmin

**Rule file:** `rules/sigma/proc_creation_win_vss_delete_shadows.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1490 — Inhibit System Recovery |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `vssadmin.exe` with a command line containing both `delete` and `shadows` |

Detects deletion of Volume Shadow Copies via vssadmin — a hallmark of ransomware inhibiting system recovery. This is one of four recovery-inhibition primitives detected in this corpus (with the WMIC shadow-copy route, wbadmin catalog deletion, and bcdedit recovery-disable); any one firing puts the host on a pre-encryption footing until disproven.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\vssadmin.exe`) |
| `CommandLine` | rule detection block | Scope of deletion (`/all`, `/for=` volume, `/quiet`) |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Backup agent vs. shell/script/ransomware parent — the deciding context |
| `User` | event source (Sysmon EID 1) | Requires elevation; identifies the compromised account |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (vssadmin itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `vssadmin.exe` is Microsoft-signed; the parent is where ransomware shows itself) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: backup-software inventory (which agent, if any, legitimately prunes shadow copies on this host) and the change calendar; current backup/recovery state of the host.
- No external IP/domain artifact on this event.
- Label the event ransomware activity only with the citing VT verdict, a correlated Impact-tactic alert, or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\vssadmin.exe and process.args : *delete* and process.args : *shadows*
   ```
2. Ransomware-preparation sweep: query the same host ±30 min for the sibling primitives (`wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit`) and for mass file-modification or cipher/wipe activity; pivot the parent's full process tree.
3. False-positive check: backup software pruning shadow copies (rare; verify context).
**Escalation:** any second Impact-tactic rule firing on the same host — `proc_creation_win_wmic_shadowcopy_delete`, `proc_creation_win_wbadmin_delete_catalog`, or `proc_creation_win_bcdedit_recovery_disabled` — is treated as **ransomware-in-progress**: page the IR lead immediately and isolate without waiting for TI.

###### 5. Remediation & Evidence Preservation

- Verify recovery state before anything else: enumerate remaining shadow copies (`vssadmin list shadows`), confirm the last known-good off-host backup for this host, and isolate backup infrastructure from the potentially compromised network segment.
- Collect/hash the parent binary and its dropped files; if encryption has not begun, the priority is containment and backup verification — do not reboot or "clean" before imaging if ransomware is suspected.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_wbadmin_delete_catalog"></a>
##### Windows Backup Catalog or System State Backup Deleted via wbadmin

**Rule file:** `rules/sigma/proc_creation_win_wbadmin_delete_catalog.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1490 — Inhibit System Recovery |
| Severity (`level`) | critical |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `wbadmin.exe` (by image path or OriginalFileName) with a command line containing `delete` plus `catalog` or `systemstatebackup` |

Detects wbadmin.exe deleting the local backup catalog or an existing system-state backup — a third recovery-inhibition primitive alongside Volume Shadow Copy deletion (vssadmin/wmic) and disabling boot-repair (bcdedit): it specifically destroys Windows Server Backup's own catalog/backups, a distinct recovery path those two don't touch. CISA AA23-320A names this pattern for education-sector ransomware.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\wbadmin.exe`) |
| `OriginalFileName` | rule detection block | PE metadata catches a renamed wbadmin.exe |
| `CommandLine` | rule detection block | `catalog` vs `systemstatebackup` target and any version/quiet flags |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Backup-admin console vs. shell/script/ransomware parent |
| `User` | event source (Sysmon EID 1) | Requires elevation; identifies the compromised account |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (wbadmin itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `wbadmin.exe` is Microsoft-signed) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: backup-administration change calendar and the specific catalog/backup identifiers involved; the host's Windows Server Backup schedule and last successful backup.
- No external IP/domain artifact on this event.
- Per policy the critical-severity rule match plus the verbatim event is the cited evidence for containment; enrichment scopes the incident, it does not gate the response.

###### 4. Containment Decision Flow

**Auto-containment:** Tier A — auto-isolate + identity kill: severity critical → EDR network isolation plus account disable and token/session/Kerberos-ticket revocation execute automatically on the rule match (no TI gate); the IR lead is paged.
**Analyst triage path (post-containment validation):**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   (process.executable : *\\wbadmin.exe or process.pe.original_file_name : "wbadmin.exe") and process.args : *delete* and process.args : (*catalog* or *systemstatebackup*)
   ```
2. Ransomware-preparation sweep: query the same host ±30 min for the sibling primitives (vssadmin/wmic shadow-copy deletion, bcdedit recovery-disable) and for mass file writes; pivot the parent's process tree for the payload.
3. False-positive check: legitimate backup-retention cleanup by IT/backup-administration staff — correlate against the change calendar and the specific catalog/backup identifiers involved.
**Escalation:** already at Tier A. Any second Impact-tactic rule on the same host confirms **ransomware-in-progress** → declare a major incident, sweep every host reachable from this one, and put backup infrastructure on alert estate-wide.

###### 5. Remediation & Evidence Preservation

- Verify recovery state first: inventory what backup capability survives — remaining shadow copies, off-host/offline backup copies of this host, and the integrity of the backup server's own catalogs; isolate backup infrastructure from the affected segment.
- Collect/hash the parent payload before cleanup; rebuild the wbadmin catalog from surviving backup media once the host is verified clean; if encryption is suspected imminent, image before remediating.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_wmi_process_create"></a>
##### WMI Process Call Create

**Rule file:** `rules/sigma/proc_creation_win_wmi_process_create.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution |
| Technique(s) | T1047 — Windows Management Instrumentation |
| Severity (`level`) | medium |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `wmic.exe` with a command line containing `process`, `call`, and `create` |

Detects the use of WMIC to create a new process, a common technique for local or remote execution. With a `/node:` argument the same syntax executes on a remote host — the launched process then appears on the target parented by WmiPrvSE.exe, which is covered by the lateral-tool-parent rule.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\wmic.exe`) |
| `CommandLine` | rule detection block | The created process's command line, plus any `/node:`/`/user:` remote-execution arguments |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Admin console vs. script host or implant |
| `User` | event source (Sysmon EID 1) | The account whose rights the created process inherits |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (wmic itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the binary the WMI call launches (collected from the payload path in `CommandLine`) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: if `/node:` is present, resolve the target host in the asset inventory and check whether the initiating account administers it; remote-administration runbooks and the change calendar.
- No TI-eligible network artifact is asserted from this event alone; remote-target context is handled as internal asset lookup.
- Malicious only with the citing VT verdict or an internal case ID — WMIC execution is a routine administrative pattern.

###### 4. Containment Decision Flow

**Auto-containment:** Tier C — indicator block on TI-confirm: severity medium → on launched-binary VT verdict ≥ 5 malicious, auto-add the hash to the EDR blocklist and open an analyst ticket; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   process.executable : *\\wmic.exe and process.args : *process* and process.args : *call* and process.args : *create*
   ```
2. Follow the execution: locally, find the created process's own Sysmon EID 1 event; for `/node:` remote calls, pivot to the target host for a WmiPrvSE.exe-parented process in the same window (lateral-movement chain).
3. False-positive check: legitimate remote administration.
**Escalation:** launched payload VT-confirmed malicious, or a `/node:` call from a non-admin workstation → treat as lateral movement; promote to the high-severity flow and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect/hash the launched payload binary from its command-line path; capture the process tree on both source and (for remote calls) target hosts.
- Remove the payload and any persistence it created on every host it was pushed to; review the initiating account's recent authentications and reset credentials if the account is confirmed compromised.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_wmic_shadowcopy_delete"></a>
##### Shadow Copy Deletion via WMIC

**Rule file:** `rules/sigma/proc_creation_win_wmic_shadowcopy_delete.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1490 — Inhibit System Recovery |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (process_creation) |
| Trigger condition | `wmic.exe` (by image path or OriginalFileName) with a command line containing both `shadowcopy` and `delete` |

Detects `wmic shadowcopy delete` (or `wmic.exe shadowcopy where "..." delete`) — the WMIC-driven route to the same effect as the vssadmin-based detection: destroying Volume Shadow Copies to block recovery ahead of encryption. A distinct, genuinely complementary signal, not a duplicate: WMIC is a separate binary with its own command grammar, and ransomware operators (CISA AA23-320A names this explicitly for Vice Society/Rhysida activity) commonly favor it specifically because vssadmin-based detections are widely deployed and well known.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `Image` | rule detection block | Confirms the executing binary path (`\wmic.exe`) |
| `OriginalFileName` | rule detection block | PE metadata catches a renamed wmic.exe |
| `CommandLine` | rule detection block | Deletion scope, including any `where "..."` selector |
| `ParentImage`, `ParentCommandLine` | event source (Sysmon EID 1) | Storage-management script vs. shell/ransomware parent — the deciding context |
| `User` | event source (Sysmon EID 1) | Requires elevation; identifies the compromised account |
| `Hashes` | event source (Sysmon EID 1) | SHA-256 for TI lookup (wmic itself is Microsoft-signed) |
| `Computer`, `UtcTime`, `ProcessGuid` | event source (Sysmon EID 1) | Host, timeline anchor, process-tree pivot key |

###### 3. Enrichment Criteria

- SHA-256 of the **parent** process binary (from its own Sysmon EID 1 event — `wmic.exe` is Microsoft-signed; the parent is where the ransomware payload shows itself) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only: backup/storage-management software inventory for any tool that prunes shadow copies via WMIC on this host; change calendar; current recovery state.
- No external IP/domain artifact on this event.
- Label the event ransomware activity only with the citing VT verdict, a correlated Impact-tactic alert, or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** Tier B — auto-isolate on TI-confirm: severity high → auto EDR-isolate the host when the parent-binary VT verdict is ≥ 5 malicious; account actions on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; ECS-renamed channel):
   ```
   (process.executable : *\\wmic.exe or process.pe.original_file_name : "wmic.exe") and process.args : *shadowcopy* and process.args : *delete*
   ```
2. Ransomware-preparation sweep: query the same host ±30 min for the sibling primitives (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit`) and mass file-modification activity; pivot the parent's full process tree.
3. False-positive check: backup software or a storage-management script pruning shadow copies via WMIC — rare in practice; verify context and correlate against the change calendar.
**Escalation:** any second Impact-tactic rule firing on the same host — `proc_creation_win_vss_delete_shadows`, `proc_creation_win_wbadmin_delete_catalog`, or `proc_creation_win_bcdedit_recovery_disabled` — is treated as **ransomware-in-progress**: page the IR lead immediately and isolate without waiting for TI.

###### 5. Remediation & Evidence Preservation

- Verify recovery state before cleanup: enumerate surviving shadow copies, confirm the host's off-host backup coverage and last good restore point, and isolate backup infrastructure from the affected segment.
- Collect/hash the parent payload and its dropped files; if encryption has not begun, containment and backup verification take priority over host cleanup — image before remediating if ransomware is suspected.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### Windows Security Log — Authentication & Identity — 15 rules

<a id="auth_win_asreproast_no_preauth_tgt"></a>
##### AS-REP Roasting — TGT Requested for an Account Without Pre-Authentication

**Rule file:** `rules/sigma/auth_win_asreproast_no_preauth_tgt.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4768 TGT request with `PreAuthType` 0, excluding machine accounts (`TargetUserName` ending `$`) |

Detects a Kerberos AS-REQ for an account with pre-authentication disabled: without pre-auth the KDC returns an AS-REP encrypted with the account's password hash to any unauthenticated requester, crackable offline with no prior domain access. Very low volume where pre-auth is universally enforced — a hit usually means either a genuinely misconfigured account or an attacker who just set the flag. Machine accounts are excluded because they never legitimately carry DONT_REQUIRE_PREAUTH; one appearing here would be a different finding entirely.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the Kerberos AS-REQ event (4768) |
| `PreAuthType` | rule detection block | `0` = pre-auth disabled — the roastable condition |
| `TargetUserName` | rule detection block | The roastable account; its hash is what the AS-REP exposes |
| `IpAddress` | event source (standard) | Requesting client address (may be IPv6-mapped `::ffff:a.b.c.d`) — primary TI artifact |
| `TicketEncryptionType` | event source (standard) | RC4 (`0x17`) AS-REPs are far cheaper to crack than AES |
| `Computer` | event source (standard) | Issuing DC; timeline anchor |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB for routable external sources; escalate at **≥ 50% confidence**. Internal RFC1918 sources pivot to asset-owner lookup instead.
- Internal-only checks: was DONT_REQUIRE_PREAUTH set recently? Correlate account-changed events (4738) for the same `TargetUserName`; compare against the inventory of deliberately exempt legacy accounts.
- Do not label the requester malicious without the AbuseIPDB verdict or an internal case ID — a lone hit on a known-exempt account is a standing misconfiguration, not an incident.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for `IpAddress`, auto-disable the targeted account (its AS-REP is in the requester's hands and offline-crackable) and revoke its Kerberos tickets/sessions; no EDR isolation — containment here is account-centric.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4768 and winlog.event_data.PreAuthType : "0" and not winlog.event_data.TargetUserName : *$
   ```
2. Identity sweep: pull account-changed events for `TargetUserName` over the prior 24 h (a freshly set flag means the attacker already has write access to the account); sweep the same `IpAddress` for sibling 4768/4769 activity — roasting rarely arrives alone.
3. False-positive check: a legacy or third-party account deliberately configured with pre-authentication disabled for compatibility — inventory these and exclude them by name; each one is a standing credential-exposure risk worth tracking regardless.
**Escalation:** flag set recently with no change record, or the same source also generating RC4 service-ticket requests → page the IR lead.

###### 5. Remediation & Evidence Preservation

- Force a password reset on the targeted account — treat its current secret as exposed the moment the AS-REP was issued.
- Re-enable pre-authentication unless the account is a documented exception; if the flag was attacker-set, also investigate how the write access to the account object was obtained.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_audit_policy_changed"></a>
##### Audit Policy Changed

**Rule file:** `rules/sigma/auth_win_audit_policy_changed.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1562.002 — Impair Defenses: Disable Windows Event Logging |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Any Security 4719 ("System audit policy was changed") event |

Detects a Windows audit policy change. Attackers with administrative access commonly disable or narrow specific audit subcategories before acting, so those actions no longer generate the events this corpus's own detections depend on — this rule is partly a detection-integrity control for the rest of the rule set, not just a standalone technique detection.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the audit-policy change event (4719) |
| `SubjectUserName`, `SubjectUserSid` | event source (standard) | Account that changed the policy — triage focus |
| `CategoryId`, `SubcategoryGuid` | event source (standard) | Which audit subcategory was touched — maps to which detections lose telemetry |
| `AuditPolicyChanges` | event source (standard) | Whether success/failure auditing was added or removed — removal is the evasion direction |
| `Computer` | event source (standard) | Host whose policy changed |

###### 3. Enrichment Criteria

- Internal-only: change-management correlation (hardening rollouts produce planned hits); map the touched subcategory to the detections that depend on it; prior case history for `SubjectUserName`. This event carries no external artifact — AbuseIPDB/OTX/VT not applicable.
- Treat the change as unauthorized only after the change-record check comes back empty — an uncorrelated hit is unverified, not yet malicious.

###### 4. Containment Decision Flow

**Auto-containment:** severity high with no external-TI artifact → routes to analyst triage (15-minute SLA); Tier B (identity) on analyst confirmation that the change is unauthorized — disable `SubjectUserName` and revoke its sessions (internal confirmation substitutes for a TI verdict on this artifact-free event).
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4719
   ```
2. Identity sweep: all activity by `SubjectUserName` on the host ±1 h; check whether events from the removed subcategory go silent afterwards, and look for a paired re-enable (attackers often restore the policy after acting inside the gap).
3. False-positive check: legitimate, deliberate audit-policy tuning by IT/security staff (e.g. enabling a new subcategory as part of a hardening rollout) — expect occasional, planned hits; correlate with change-management records before escalating.
**Escalation:** auditing narrowed or disabled (not added) with no change record, or followed by a measurable gap in expected event volume → page the IR lead; the detection corpus itself is degraded.

###### 5. Remediation & Evidence Preservation

- Restore the audit policy (GPO re-apply or `auditpol /restore`) and verify with `auditpol /get /category:*` against the baseline.
- Treat the reduced-audit window as unobserved: sweep the surviving telemetry (Sysmon, network) for that window rather than assuming nothing happened in it.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_bruteforce_failed_logons"></a>
##### Repeated Failed Sign-Ins (Windows Security 4625)

**Rule file:** `rules/sigma/auth_win_bruteforce_failed_logons.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110 — Brute Force |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Any Security 4625 failed-logon event (single-event logic of record; alerting is done by the threshold companion) |

Identifies failed Windows logon events. This file is deliberately single-event logic only — the logic-of-record for the paired Elastic threshold rule `rules/elastic/threshold/auth-win-bruteforce-failed-logons.ndjson`, which alerts at **≥ 5 failures against one target account within a 5-minute window** (with a 10-minute lookback guaranteeing full window containment). The Sigma file stays `experimental` on purpose so it is not also deployed as a noisy per-event query rule.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the failed-logon event (4625) |
| `TargetUserName` | event source (standard) | Attacked account — the companion's counting key |
| `IpAddress`, `WorkstationName` | event source (standard) | Source of the attempts — primary TI artifact |
| `Status`, `SubStatus` | event source (standard) | Failure reason — separates password guessing from expired/locked/misconfigured credentials |
| `LogonType` | event source (standard) | Attack path context (network, RDP, interactive) |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB; escalate at **≥ 50% confidence** for routable external sources.
- Internal-only checks: is the account inside a mass password-reset rollout window; is the source a known authentication proxy (both are the rule's stated FP classes).
- A failure run alone proves pressure, not compromise — do not close as malicious without the TI verdict or a correlated success.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for the source, auto-disable the targeted account (temporary lock pending analyst review — it is under active attack) and block the source at the perimeter; no EDR isolation, containment is account-centric.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`), bucketing failures per 5-minute window against the companion's ≥ 5 threshold:
   ```
   winlog.event_id : 4625 and winlog.event_data.TargetUserName : "<user>"
   ```
2. Success check — the pivotal question: any 4624 for the same account from the same source after the failure run (`winlog.event_id : 4624 and winlog.event_data.TargetUserName : "<user>"`); a success converts brute-force pressure into compromise.
3. False-positive checks: high-volume legitimate failures during a mass password-reset rollout; load-balanced authentication proxies retrying with stale credentials.
**Escalation:** a success from the attacking source after the failure run → force reset, page the IR lead, and pivot to what the session did next.

###### 5. Remediation & Evidence Preservation

- Perimeter-block the confirmed source; force a password reset on the account if any success followed, and review the domain lockout policy against the observed attempt rate.
- Export the 4625/4624 slice for the account and source before index rollover — the attempt cadence is the evidence of automation.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_bruteforce_source_spray"></a>
##### Password Spray Indicator via Failed Logons From a Single Source (Windows Security 4625)

**Rule file:** `rules/sigma/auth_win_bruteforce_source_spray.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110.003 — Brute Force: Password Spraying |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4625 where `IpAddress` is not one of the four no-source sentinel values (`-`, `0.0.0.0`, `::`, empty string) |

Same base selection as `auth_win_bruteforce_failed_logons.yml`; logic-of-record for the paired Elastic threshold rule `rules/elastic/threshold/auth-win-bruteforce-source-spray.ndjson`, which buckets failures by source IP and alerts when **one source accrues ≥ 6 distinct target accounts within a 5-minute window** — the spray shape (few passwords × many accounts) that the per-account threshold cannot see. Known limitation carried from review: excluding the no-source sentinels also removes coverage for an on-host spray that logs no network source (`IpAddress` `-`); that population is out of this rule's scope.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the failed-logon event (4625) |
| `IpAddress` | rule detection block | Spray source — bucketing key and primary TI artifact (sentinel values excluded) |
| `TargetUserName` | event source (standard) | Swept account — the companion counts distinct values |
| `WorkstationName` | event source (standard) | Claimed source host name; NAT/proxy discriminator |
| `Status`, `SubStatus` | event source (standard) | Uniform failure reason across the account set is the spray signature |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only checks: is the source a NAT/proxy gateway or a known service host (the rule's own FP inventory); compare the swept-account list against real user populations behind that gateway.
- The distinct-account count is the internal corroboration — a TI-clean source with a genuine ≥ 6-account sweep still warrants a case, but cite the sweep evidence, not an assumed verdict.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for `IpAddress`, auto-block the source and auto-disable any swept account that logged a success from it during the spray window; remaining account actions on analyst confirm.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`), counting distinct target accounts per 5-minute window (≥ 6 matches the companion threshold):
   ```
   winlog.event_id : 4625 and winlog.event_data.IpAddress : "<ip>"
   ```
2. Success pivot: `winlog.event_id : 4624 and winlog.event_data.IpAddress : "<ip>"` — any hit converts the spray indicator into a confirmed compromise of that account.
3. False-positive checks: a misconfigured application or service account retrying the same stale credential against many resources from one host; NAT/proxy gateways where many real users' failed logons share one apparent source IP.
**Escalation:** any success from the spray source, or an external TI-confirmed source → page the IR lead and enumerate the full swept-account list for forced resets.

###### 5. Remediation & Evidence Preservation

- Block the source; force password resets for every swept account that shows a subsequent success, and review the rest for reuse of the sprayed password pattern.
- Export the full 4625/4624 slice for the source window — the account list and cadence are the campaign fingerprint.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_dcsync_replication_rights_used"></a>
##### DCSync — Directory Replication Rights Exercised by a Non-DC Account

**Rule file:** `rules/sigma/auth_win_dcsync_replication_rights_used.yml` · **Status:** experimental · **Severity:** critical

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1003.006 — OS Credential Dumping: DCSync |
| Severity (`level`) | critical |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4662 with `AccessMask` 0x100 (control access) and `Properties` containing one of the three DS-Replication extended-right GUIDs, excluding machine accounts (`SubjectUserName` ending `$`) |

Detects the directory-replication extended rights being exercised: holding DS-Replication-Get-Changes(-All) lets a principal ask a DC to replicate any account's password hashes — the mainline DCSync technique of Mimikatz `lsadump::dcsync` and Impacket `secretsdump.py`, needing no code execution on the DC itself; the third GUID covers the RODC filtered-set variant. The GUID filter is what makes 4662 deployable at all, and the trailing-`$` filter removes the DC-to-DC replication baseline. Accounts that legitimately replicate are site-specific and must be excluded per environment.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the directory object-access event (4662) |
| `AccessMask` | rule detection block | `0x100` — extended-right (control access) exercise |
| `Properties` | rule detection block | Which replication GUID was used (Get-Changes / Get-Changes-All / Filtered-Set) |
| `SubjectUserName` | rule detection block | Principal exercising replication rights — containment target |
| `SubjectDomainName`, `SubjectLogonId` | event source (standard) | Domain context; logon-session pivot to find where the session originated |
| `Computer` | event source (standard) | The DC that served the replication |

###### 3. Enrichment Criteria

- Internal-only: compare `SubjectUserName` against the site's replication allowlist (Azure AD Connect / Entra Connect, backup products) — a directory-replication event has no external artifact, so AbuseIPDB/OTX/VT do not apply; any change to the allowlist itself is a privileged-access event.
- `SubjectLogonId` → internal session trace: find the matching logon event to recover the source host/IP of the session that exercised the right.
- The rule match plus the verbatim 4662 is the cited evidence for a non-allowlisted account — attribution beyond that still requires the session trace.

###### 4. Containment Decision Flow

**Auto-containment:** severity critical → Tier A, automatic on rule match (behaviorally conclusive): disable `SubjectUserName`, revoke all its sessions and Kerberos tickets, EDR-isolate the session's source host once the logon-session pivot identifies it; page the IR lead.
**Analyst triage path** (runs in parallel with Tier A, to scope rather than decide):
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4662 and winlog.event_data.AccessMask : "0x100"
     and winlog.event_data.Properties : (*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* or *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2* or *89e95b76-444d-4c62-991a-0facbeda640c*)
   ```
2. Identity sweep: locate the 4624 whose logon ID matches this event's `SubjectLogonId` to recover the source workstation/IP; sweep all replication-GUID 4662 hits by the same account — Get-Changes-All means full hash replication was possible.
3. False-positive checks: Azure AD Connect / DirSync, Entra Connect, or a backup product whose service account holds replication rights by design (exclude those specific accounts by name); DC computer accounts replicating with each other are already removed by the trailing-`$` filter.
**Escalation:** already paged at Tier A; a confirmed non-allowlisted account means assume domain-wide credential compromise and open a major incident.

###### 5. Remediation & Evidence Preservation

- Export the DC Security-log slice and the session-trace events first; then reset the exercising account and audit the directory ACL to find who granted it replication rights, and when.
- Post-eviction: double-reset `krbtgt`, rotate all privileged credentials, and remove the replication grant; treat every domain secret as potentially replicated until the grant window is bounded.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_disabled_account_logon_attempt"></a>
##### Logon Attempt Against a Disabled Account

**Rule file:** `rules/sigma/auth_win_disabled_account_logon_attempt.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion, Persistence |
| Technique(s) | T1078.002 — Valid Accounts: Domain Accounts |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4625 whose `SubStatus` or `Status` equals 0xC0000072 — the account-disabled failure code (both hex casings, both fields, since the logon path determines which field carries it) |

A disabled account has no legitimate reason to ever authenticate again; a repeated or unexpected hit is a strong signal of either stale credential reuse (a former employee's account, or a service account that should have been rotated) or an attacker who obtained old credentials without knowing the account was already deprovisioned.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the failed-logon event (4625) |
| `SubStatus`, `Status` | rule detection block | `0xC0000072` — the specific account-disabled NTSTATUS code |
| `TargetUserName` | event source (standard) | The disabled account being attempted |
| `IpAddress`, `WorkstationName` | event source (standard) | Attempt source — primary TI artifact |
| `LogonType`, `ProcessName` | event source (standard) | Path: network attempt vs local service/scheduled-task retry |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB; escalate at **≥ 50% confidence** for external sources.
- Internal-only checks: when was the account disabled (account-disabled event 4725 / deprovisioning record) — a burst starting at the disable is the cached-credential shape; also whether the source host ever legitimately used this account.
- One attempt proves someone still holds the credential, not who — hold the verdict until the recurrence pattern and source context are established.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% for `IpAddress`, auto-add the source to the perimeter blocklist; no host or account automation without an analyst (the account is already disabled — keep it that way).
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4625 and (winlog.event_data.SubStatus : ("0xC0000072" or "0xc0000072") or winlog.event_data.Status : ("0xC0000072" or "0xc0000072"))
   ```
2. Timing pivot: compare the attempt timeline against the disable date. A single hit is ambiguous by itself — the additional signal needed is either sustained recurrence well past the disable window, a source the account never used, or multiple disabled accounts probed from one source.
3. False-positive check: an account disabled very recently while a client still has cached credentials and periodically retries (browser sync, mapped drive, scheduled task) — expect a short-lived burst right after any account disable, tapering off; sustained recurrence past that window is the more meaningful signal.
**Escalation:** sustained recurrence long after the disable, an external source, or a sweep across several disabled accounts → promote to identity-compromise triage and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Keep the account disabled; verify no re-enable (4722) or password-reset events followed the attempts.
- If the source is internal, find and remove the stored credential on that host (service, scheduled task, mapped drive); if the account is an unrotated service account, rotate the dependent systems.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_explicit_cred_account_sweep"></a>
##### Explicit-Credential Sign-In Recorded (Windows Security 4648)

**Rule file:** `rules/sigma/auth_win_explicit_cred_account_sweep.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110.003 — Brute Force: Password Spraying |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Any Security 4648 explicit-credential logon event (single-event logic of record; alerting is done by the threshold companion) |

Identifies "a logon was attempted using explicit credentials" events. This file is the logic-of-record for the paired Elastic threshold rule `rules/elastic/threshold/auth-win-explicit-cred-account-sweep.ndjson`, which buckets 4648 events by source host and alerts when **one host uses ≥ 6 distinct target accounts within a 5-minute window** — a password-spray / account-sweep indicator. Deliberately `experimental` so it is not also deployed as a noisy per-event query rule.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the explicit-credential logon event (4648) |
| `SubjectUserName` | event source (standard) | Session that supplied the credentials — the operator |
| `TargetUserName` | event source (standard) | Credential being used — the companion counts distinct values |
| `TargetServerName` | event source (standard) | Where each credential was pointed |
| `ProcessName` | event source (standard) | The tool making the attempts |
| `IpAddress` | event source (standard) | Network source when the initiating request is remote — TI artifact |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB when populated with a routable address; escalate at **≥ 50% confidence**.
- Internal-only checks: is the sweeping host an admin workstation, helpdesk seat, or backup/scanner service host (the rule's FP inventory); is `SubjectUserName` expected to touch many accounts.
- The ≥ 6-distinct-account sweep is the corroborating internal evidence — cite it and the operator context, not intent.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for `IpAddress`, auto-disable the operating account (`SubjectUserName`) and revoke its sessions; swept-account resets on analyst confirm.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`), counting distinct target accounts per 5-minute window (≥ 6 matches the companion threshold):
   ```
   winlog.event_id : 4648 and host.name : "<source_host>"
   ```
2. Tool pivot: group the hits by `ProcessName` and `TargetServerName` — one process sweeping many accounts toward many servers is the lateral/spray shape; correlate 4624/4625 outcomes for each swept account to see which credentials actually worked.
3. False-positive checks: IT help desk or password-reset tooling touching many accounts from one admin workstation; backup or scanning service accounts connecting to many targets with explicit credentials.
**Escalation:** sweep from a non-admin workstation, or swept credentials subsequently succeeding on new hosts → page the IR lead.

###### 5. Remediation & Evidence Preservation

- Disable and reset the operator account and any swept account confirmed abused; examine the source host for credential-harvesting or lateral tooling via the endpoint (Sysmon) family.
- Export the 4648 slice plus correlated 4624/4625 outcomes — the target-account list is the sweep's scope document.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_kerberoasting_rc4_spn_request"></a>
##### Kerberoasting — RC4 Service Ticket Requested for a User SPN

**Rule file:** `rules/sigma/auth_win_kerberoasting_rc4_spn_request.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4769 with `TicketEncryptionType` 0x17 (RC4-HMAC) and `Status` 0x0 (ticket issued), excluding machine-account SPNs (ending `$`) and krbtgt |

Kerberoasting requests a service ticket for a user-account SPN and cracks it offline; RC4 is requested deliberately because it is far cheaper to crack than AES. The two account filters are what keep this from being a per-logon firehose (machine accounts request RC4 tickets constantly; krbtgt appears in every TGT exchange), and success is required explicitly rather than by blacklisting one failure code. Requires the "Audit Kerberos Service Ticket Operations" subcategory on domain controllers.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the service-ticket request event (4769) |
| `TicketEncryptionType` | rule detection block | `0x17` RC4-HMAC — the downgrade that makes offline cracking cheap |
| `Status` | rule detection block | `0x0` — the ticket was actually issued |
| `ServiceName` | rule detection block | The roasted SPN account — its password is the exposure |
| `TargetUserName` | event source (standard) | Requesting principal (user@REALM) — the roasting actor |
| `IpAddress` | event source (standard) | Requesting client address (may be IPv6-mapped `::ffff:a.b.c.d`) — TI artifact |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB for routable external sources; escalate at **≥ 50% confidence**. Internal sources pivot to asset-owner lookup.
- Internal-only checks: the baseline of legacy RC4-only SPNs (the rule's own FP inventory); the requester's normal service-ticket profile.
- A verdict needs either the multi-SPN burst shape or a non-baselined requester plus the TI/internal citation — one RC4 ticket to one legacy SPN is not, by itself, an incident.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for `IpAddress`, auto-disable the requesting account (`TargetUserName`) and revoke its Kerberos tickets; forced reset of the roasted `ServiceName` account on analyst confirm.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4769 and winlog.event_data.TicketEncryptionType : "0x17" and winlog.event_data.Status : "0x0" and not winlog.event_data.ServiceName : (*$ or krbtgt*)
   ```
2. Burst-cardinality check: count distinct `ServiceName` values per requester (`TargetUserName` / `IpAddress`) over 10 minutes — a roasting run requests many SPNs at once; a single request is ambiguous and needs the burst shape or an off-baseline requester before any verdict.
3. False-positive checks: a legacy application or appliance whose service account genuinely still negotiates RC4 because it cannot do AES (baseline these SPNs and exclude them explicitly rather than weakening the rule); a domain still running at a functional level where RC4 is the negotiated default.
**Escalation:** multi-SPN burst from one requester, or the same principal also flagged by the AS-REP roasting or spray rules → page the IR lead; treat the roasted SPN passwords as exposed.

###### 5. Remediation & Evidence Preservation

- Reset every roasted service account to a long random password or migrate it to a gMSA; enforce AES on those accounts so RC4 tickets can no longer be minted for them.
- Hunt for post-roast use of the SPN accounts (new logons from unusual sources) — a cracked ticket's value is the follow-on authentication.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_pass_the_hash_logon"></a>
##### Pass-the-Hash Logon Pattern (LogonType 9, Negotiate)

**Rule file:** `rules/sigma/auth_win_pass_the_hash_logon.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Lateral Movement, Defense Evasion |
| Technique(s) | T1550.002 — Use Alternate Authentication Material: Pass the Hash |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4624 with `LogonType` 9 (NewCredentials) and `AuthenticationPackageName` Negotiate |

Detects the credential-injection logon shape used by `runas /netonly` and equivalent techniques — Mimikatz `sekurlsa::pth` uses this exact mechanism: a new logon session with supplied credentials (often an NTLM hash rather than a plaintext password) without replacing the current interactive session. The rule deliberately does not claim full signature completeness: the fuller published pattern also checks LogonProcessName ("seclogo"), which this rule does not select on. LogonType 9 is rare and has one narrow legitimate use, which is why this two-field combination is a meaningful signal rather than routine noise.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the successful-logon event (4624) |
| `LogonType` | rule detection block | `9` NewCredentials — the credential-injection session type |
| `AuthenticationPackageName` | rule detection block | `Negotiate` — completes the published PtH pair |
| `SubjectUserName` | event source (standard) | Interactive session that injected the credentials |
| `TargetOutboundUserName` | event source (standard) | The injected network-use credential — the account whose secret may be a passed hash |
| `IpAddress`, `Computer` | event source (standard) | Usually `-` for a locally initiated type-9 logon; `Computer` is the injection host |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB when populated with a routable address; escalate at **≥ 50% confidence** (on this logon type it is commonly the `-` sentinel — then no external artifact exists).
- Internal-only checks: baseline of administrators who legitimately use `runas /netonly`; whether `TargetOutboundUserName` is privileged; prior case history for the host.
- The event proves credential injection occurred, not that the injected secret was a hash — state that distinction in the case rather than asserting PtH outright.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for a populated `IpAddress`, auto-disable the injected-credential account (`TargetOutboundUserName`) and revoke its sessions/tickets; host isolation via correlated endpoint telemetry on analyst confirm.
**Analyst triage path** (usually no TI-confirmable artifact) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4624 and winlog.event_data.LogonType : 9 and winlog.event_data.AuthenticationPackageName : "Negotiate"
   ```
2. Identity sweep: in the raw event, LogonProcessName `seclogo` corroborates the published PtH pattern (the rule deliberately does not select on it); then sweep for network logons by `TargetOutboundUserName` to other hosts immediately after — the actual lateral movement. A single type-9 logon is ambiguous on its own: the deciding signals are the operator's `runas /netonly` baseline and what the injected account did next.
3. False-positive check: legitimate administrative use of `runas /netonly` (a documented, if uncommon, pattern for running network-only tooling under different credentials without a full re-login) — baseline expected accounts/hosts before escalating every hit.
**Escalation:** the injected credential is privileged, or follow-on network logons reach hosts the operator never touches → page the IR lead; treat the injected account's secret as compromised.

###### 5. Remediation & Evidence Preservation

- Reset the injected account's password and revoke its Kerberos tickets/sessions; if PtH is confirmed, the hash was obtained somewhere — investigate the injection host for credential dumping via the endpoint family's LSASS-access detections.
- Sweep for further sessions created by the same interactive operator session before it is torn down.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_priv_group_membership_change"></a>
##### Privileged Group Membership Change (Windows Security 4732/4728/4756)

**Rule file:** `rules/sigma/auth_win_priv_group_membership_change.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1098 — Account Manipulation; T1078 — Valid Accounts |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4732 (local), 4728 (global), or 4756 (universal) member-add where the target group is Administrators, Domain Admins, or Enterprise Admins by display name (`TargetUserName`) or well-known SID suffix (`TargetSid` ending -544/-512/-519) |

Detects a member added to a privileged group. The SID arm is locale- and rename-invariant, so the rule still fires if the group was renamed or the host uses a non-English display language — a name-only match would miss both. 4728/4756 only fire on Domain Controllers and require the "Audit Security Group Management" advanced audit subcategory.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Which scope of group was changed (4732 local / 4728 global / 4756 universal) |
| `TargetUserName` | rule detection block | Group display name |
| `TargetSid` | rule detection block | Group SID — rename/locale-invariant confirmation of which group |
| `MemberName`, `MemberSid` | event source (standard) | The principal that was added — removal/containment target |
| `SubjectUserName` | event source (standard) | Who performed the add |
| `Computer` | event source (standard) | Member host (4732) vs the DC (4728/4756) |

###### 3. Enrichment Criteria

- Internal-only: change-management/onboarding record for the add; AD lookup on `MemberSid` (a just-created account being elevated is the create-then-elevate pattern — pair with `auth_win_user_account_created`); case history for `SubjectUserName`. A group-membership event carries no external artifact — AbuseIPDB/OTX/VT not applicable.
- An add with no matching change record is unauthorized-until-explained, not yet malicious — the internal record check is the citation either way.

###### 4. Containment Decision Flow

**Auto-containment:** severity high with no external-TI artifact → routes to analyst triage (15-minute SLA); Tier B (identity) on analyst confirmation that no change record exists — remove the member from the group, disable the added account, and revoke sessions for both member and `SubjectUserName` pending review.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : (4732 or 4728 or 4756) and (winlog.event_data.TargetUserName : ("Administrators" or "Domain Admins" or "Enterprise Admins") or winlog.event_data.TargetSid : (*-544 or *-512 or *-519))
   ```
2. Identity sweep: was `MemberName` created recently (4720 for the same account)? What else did `SubjectUserName` do around the add? What did the new member do after — first privileged logons (4672), lateral activity?
3. False-positive check: approved IT/helpdesk workflows adding a new administrator during onboarding or a documented role change.
**Escalation:** no change record plus a newly created or dormant member account, or the add performed outside the provisioning process/hours → page the IR lead.

###### 5. Remediation & Evidence Preservation

- Remove the unauthorized member; disable it and reset its credentials; audit everything the account did while privileged before trusting any system it touched.
- Review how `SubjectUserName` obtained the rights to perform the add — the group change is often the second step, not the first.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_rdp_logon_type10"></a>
##### Interactive Logon via RDP (LogonType 10)

**Rule file:** `rules/sigma/auth_win_rdp_logon_type10.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Lateral Movement |
| Technique(s) | T1021.001 — Remote Services: Remote Desktop Protocol |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4624 with `LogonType` 10 (RemoteInteractive) |

Detects a session established over RDP (or another remote-desktop protocol Windows classifies the same way) — a primary lateral-movement and hands-on-keyboard vector. This is the network-independent, endpoint-side complement to `net_zeek_conn_external_rdp_inbound.yml`: it fires on the target host itself regardless of what the network sensor can see, including segments the campus sensor has no visibility into.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the successful-logon event (4624) |
| `LogonType` | rule detection block | `10` RemoteInteractive — an RDP-class session |
| `TargetUserName` | event source (standard) | Account that logged on |
| `IpAddress`, `WorkstationName` | event source (standard) | RDP client source — primary TI artifact |
| `Computer` | event source (standard) | RDP target host — where the in-session activity will appear |

###### 3. Enrichment Criteria

- `IpAddress` → AbuseIPDB; escalate at **≥ 50% confidence** for external sources; internal sources pivot to asset-owner lookup.
- Internal-only checks: is RDP intentionally enabled on `Computer`; the host's baseline of expected source/account pairs; correlation with `net_zeek_conn_external_rdp_inbound` for boundary-crossing sessions.
- One RDP logon carries no verdict by itself — the citation is the TI hit, the baseline deviation, or what the session did next.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% for `IpAddress`, auto-add the source to the perimeter blocklist; no host or account automation without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4624 and winlog.event_data.LogonType : 10
   ```
2. Baseline pivot: a single RDP logon is not adjudicable alone — routine volume is expected wherever RDP is intentionally enabled. The additional signal needed is deviation: a new source/account pairing, off-hours access, an external source, or in-session process activity on `Computer` that trips endpoint detections.
3. False-positive check: legitimate remote administration via RDP by IT staff or the account owner — expect routine volume on any host RDP is intentionally enabled on; baseline expected source hosts/accounts and alert on deviation rather than every hit.
**Escalation:** external or TI-confirmed source, or in-session activity firing endpoint-family rules → promote to the Tier B identity flow (terminate the session, disable the account) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- On confirmed misuse: log off/terminate the RDP session, disable and reset the account, and block the source; review everything the session executed on `Computer`.
- Reduce exposure where the alert revealed unexpected RDP reachability (firewall scope, NLA, jump-host policy).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_security_log_cleared"></a>
##### Security Audit Log Cleared (Windows Security 1102)

**Rule file:** `rules/sigma/auth_win_security_log_cleared.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Any Security 1102 ("The audit log was cleared") event |

The native Windows event for a Security-channel clear. More reliable than command-line-based detection alone (`proc_creation_win_clear_event_logs.yml`) since it fires regardless of the tool used to clear the log — kept alongside that rule, not as a replacement for it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the audit-log-cleared event (1102) |
| `SubjectUserName`, `SubjectUserSid` | event source (standard) | The account that cleared the log — 1102 embeds it |
| `SubjectLogonId` | event source (standard) | Session pivot toward how and from where the clearing session was established |
| `Computer` | event source (standard) | Host whose Security log was cleared — the investigation focus |

###### 3. Enrichment Criteria

- Internal-only: documented, change-managed maintenance-window check; case history for `SubjectUserName` and `Computer`. The event carries no external artifact — AbuseIPDB/OTX/VT not applicable.
- Events shipped to the SIEM before the clear survive it — the indexed history is the authoritative record of what the clear attempted to hide; cite from it, not from the (now empty) local log.

###### 4. Containment Decision Flow

**Auto-containment:** severity high with no external-TI artifact → routes to analyst triage (15-minute SLA); Tier B (identity) on analyst confirmation that no maintenance window applies — disable `SubjectUserName`, revoke its sessions, and treat `Computer` as compromised pending review.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 1102
   ```
2. Reconstruct the hidden window: query the already-indexed events for `Computer` in the hours before the clear — that is what the clear was meant to erase; correlate `proc_creation_win_clear_event_logs` hits for the tool used, and trace `SubjectLogonId` to the originating session.
3. False-positive check: none expected in steady state — scope any exception to a documented, change-managed maintenance window.
**Escalation:** any 1102 outside a documented maintenance window → page the IR lead; the steady-state expectation for this event is zero.

###### 5. Remediation & Evidence Preservation

- Export the indexed pre-clear window for `Computer` immediately (before rollover) — it is the surviving copy of the destroyed local log.
- Collect remaining local artifacts from the host (other channels, forensic triage image) before any cleanup; on confirmed hostile clear, follow the identity actions above and hunt the activity the clear was covering.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_sedebug_special_logon"></a>
##### Special-Privilege Logon Assigning SeDebugPrivilege (Windows Security 4672)

**Rule file:** `rules/sigma/auth_win_sedebug_special_logon.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation |
| Technique(s) | T1078 — Valid Accounts; T1134 — Access Token Manipulation |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4672 (special privileges assigned to new logon) with SeDebugPrivilege in `PrivilegeList`, excluding SYSTEM (`SubjectUserSid` S-1-5-18, which receives it on every boot) |

SeDebugPrivilege lets a process open and read the memory of any other process (e.g. LSASS) and is a common precursor to credential dumping or token theft. Requires the "Audit Special Logon" advanced audit subcategory, enabled by default in most modern audit-policy baselines.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the special-privilege logon event (4672) |
| `PrivilegeList` | rule detection block | Contains SeDebugPrivilege; the other listed privileges give session context |
| `SubjectUserSid` | rule detection block | SYSTEM is filtered; the SID of the privileged logon |
| `SubjectUserName`, `SubjectDomainName` | event source (standard) | Human-readable account identity |
| `SubjectLogonId` | event source (standard) | Correlate to the paired 4624 for logon type and source |
| `Computer` | event source (standard) | Host where the privileged session exists |

###### 3. Enrichment Criteria

- Internal-only: is the account an expected debugging/backup/monitoring identity on this host (the rule's FP class); prior case history. No external artifact on this event — AbuseIPDB/OTX/VT not applicable.
- A 4672 records capability, not action — never cite it alone as evidence of credential access.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium, internal-only enrichment → Tier D: enrich, queue for analyst review, no automation.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4672 and winlog.event_data.PrivilegeList : *SeDebugPrivilege* and not winlog.event_data.SubjectUserSid : "S-1-5-18"
   ```
2. Pair with the logon: match `SubjectLogonId` to its 4624 (logon type, source), then check whether the session actually used the capability — correlate the endpoint family's LSASS-access/credential-dump detections on `Computer` in the same window. Without that paired process telemetry the event is ambiguous and stays a context record, not a finding.
3. False-positive check: legitimate debugging, backup, or monitoring software running under a non-SYSTEM administrative account that requires SeDebugPrivilege.
**Escalation:** the same session trips a credential-access detection (e.g. LSASS dump) → escalate under that rule's Tier B flow and page the IR lead.

###### 5. Remediation & Evidence Preservation

- No remediation for the capability alone; on correlated abuse, follow the triggering credential-access rule's remediation (memory acquisition before cleanup, credential resets for exposed sessions).
- Review and trim which accounts are granted SeDebugPrivilege if the holder has no documented need.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_sensitive_group_recon"></a>
##### Object Access Against a Privileged AD Group

**Rule file:** `rules/sigma/auth_win_sensitive_group_recon.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1069.002 — Permission Groups Discovery: Domain Groups |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Security 4661 (handle to an object requested) whose `ObjectName` matches Domain Admins, Enterprise Admins, Schema Admins, or Administrators by display name (contains) or well-known SID/RID suffix (endswith -512/-519/-518/-544) |

4661 fires on read access as well as modification, making this a reconnaissance-capable signal — an attacker enumerating who is in these groups before targeting them — complementary to `auth_win_priv_group_membership_change.yml`, which only catches actual membership changes. The SID-suffix arm, not the name arm, is the rule's load-bearing detection path (name-only matching is not proven reliable for this event). Operational prerequisites: the "Audit SAM" and/or "Audit Directory Service Access" subcategory AND a SACL on the target group objects — 4661 is not emitted for arbitrary objects by default.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the handle-to-object request event (4661) |
| `ObjectName` | rule detection block | Which privileged group was touched (SID/RID suffix arm is load-bearing) |
| `SubjectUserName`, `SubjectUserSid` | event source (standard) | The enumerating account |
| `ObjectServer`, `ObjectType` | event source (standard) | SAM/DS object context for the access |
| `AccessList`, `AccessMask` | event source (standard) | Requested access — read-only enumeration vs write attempt |
| `SubjectLogonId` | event source (standard) | Session pivot to the source of the enumerating logon |

###### 3. Enrichment Criteria

- Internal-only: baseline of AD administration/audit tooling and the accounts that run it; case history for `SubjectUserName`. No external artifact on this event — AbuseIPDB/OTX/VT not applicable.
- Enumeration is only a finding with a pattern behind it — cite the multi-group access sequence or the account's lack of admin duties, never a single object touch.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium, internal-only enrichment → Tier D: enrich, queue for analyst review, no automation.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`) on the load-bearing SID/RID arm (confirm the name arm in the raw event):
   ```
   winlog.event_id : 4661 and winlog.event_data.ObjectName : (*-512 or *-519 or *-518 or *-544)
   ```
2. Recon-pattern pivot: a single incidental hit is ambiguous — domain-joined machines can reference these objects during normal Kerberos/Group Policy processing. The additional signal needed is one `SubjectUserName` touching several privileged groups in a short window, or an account with no admin duties doing it at all; then check for follow-on targeting of the enumerated members (spray, Kerberoast, explicit-credential hits against them).
3. False-positive checks: legitimate AD administration or auditing tooling enumerating privileged group membership in routine access reviews (baseline expected accounts/tools); workstations incidentally referencing these objects during normal Kerberos/Group Policy processing — scope the underlying SACL narrowly to reduce this.
**Escalation:** recon pattern from a non-admin account, or enumeration followed by authentication attacks against the enumerated members → promote to identity-compromise triage and page the IR lead.

###### 5. Remediation & Evidence Preservation

- On confirmed hostile recon: put the enumerated privileged accounts under heightened monitoring, review their exposure (SPNs, pre-auth, stale sessions), and investigate the enumerating account's origin session.
- Tighten the SACL scope if the alert volume shows incidental machine traffic.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_win_user_account_created"></a>
##### User Account Created (Windows Security 4720)

**Rule file:** `rules/sigma/auth_win_user_account_created.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1136.001 — Create Account: Local Account |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows Security) |
| Trigger condition | Any Security 4720 (user account created) event |

Detects new-account creation — a common persistence mechanism: an attacker with administrative access creates an account for durable access that survives a compromised credential's reset. Stated scope limit: 4720 alone means "an account was created" (local on a workstation, domain if raised on a DC), not "an admin account was created" — confirming elevation requires a follow-on 4732/4728 group-membership event for the same `TargetUserName` (covered independently by `auth_win_priv_group_membership_change.yml`); this rule does not perform that correlation.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Confirms the account-created event (4720) |
| `TargetUserName` | event source (standard) | The new account — watch it, don't just log it |
| `SubjectUserName` | event source (standard) | The creating account |
| `SamAccountName`, `DisplayName` | event source (standard) | Naming — lookalike or service-style names are a manual-creation tell |
| `Computer` | event source (standard) | Workstation (local account) vs DC (domain account) — different blast radius |

###### 3. Enrichment Criteria

- Internal-only: provisioning/HR onboarding record for `TargetUserName`; whether `SubjectUserName` is a sanctioned provisioning identity. An account-creation event carries no external artifact — AbuseIPDB/OTX/VT not applicable.
- The provisioning-record check is the citation — an unmatched creation is unexplained, and stays that way until the follow-on activity is examined.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium, internal-only enrichment → Tier D: enrich, queue for analyst review, no automation.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4720
   ```
2. Elevation correlation — the decisive follow-up: check for 4732/4728/4756 adds of the same `TargetUserName` (the priv-group rule's territory); creation alone is routine in an environment with regular turnover, so the verdict needs the provisioning record plus what the account did next (first logons, group adds, logon sources).
3. False-positive check: legitimate account provisioning by IT staff or automated onboarding tooling — expect routine volume in any environment with regular staff/student turnover; correlate with change-management records or HR onboarding events before escalating.
**Escalation:** creation plus a privileged-group add with no provisioning record, or creation by a non-provisioning account → treat as active persistence, apply the Tier B identity actions (disable the new account and the creator pending review), and page the IR lead.

###### 5. Remediation & Evidence Preservation

- On confirmed unauthorized creation: disable and remove the account, audit every logon and action it performed, and reset the creator account's credentials while investigating how the creator's access was obtained.
- Sweep for sibling creations by the same `SubjectUserName` — persistence accounts are often made in pairs.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### PowerShell Script Block Logging (EID 4104) — 7 rules

<a id="posh_credential_harvesting_scriptblock"></a>
##### PowerShell Credential-Harvesting Cmdlet Pattern

**Rule file:** `rules/sigma/posh_credential_harvesting_scriptblock.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Collection, Credential Access |
| Technique(s) | T1056.002 — Input Capture: GUI Input Capture |
| Severity (`level`) | high |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block whose text contains a browser credential/cookie-store path literal (`Login Data`, `\Cookies`, `Local State`) OR a DPAPI unprotect reference (`DPAPI`, `[System.Security.Cryptography.ProtectedData]`) |

Detects script blocks reading a browser's credential/cookie store directly — bypassing the browser process entirely — or referencing DPAPI's unprotect API against captured material; scoped to script-content patterns because PowerShell aliasing makes any single-cmdlet-name check trivially evadable. Two gaps the rule states plainly: simple string splitting (building the path via `-join`/concatenation) evades it, since 4104's deobfuscation only re-logs code that is subsequently parsed and executed, not ordinary runtime string values — and `posh_ps_obfuscated_scriptblock` is explicitly *not* a backstop for that case; and no console-input/keystroke telemetry exists in this environment to catch the same technique run interactively. `ConvertFrom-SecureString` is deliberately excluded (routine in ordinary credential-storage automation).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — shows which branch fired (browser-store path vs DPAPI) and the exact target file paths |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key — chunks of one logical script share an id; pivot to pull the full script |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path when the block ran from a file (empty for interactive/in-memory); collection target |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment and Sysmon-correlation anchors |

###### 3. Enrichment Criteria

- Decoded domain/URL recovered from the script block (exfil destination, stager source) → OTX; escalate on **any pulse match**.
- Hash of any dropped payload or tool the block references (via the host's Sysmon file-creation events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- If a decoded destination is a bare IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is a sanctioned credential-migration or password-manager-integration script known for this host (script hash/path baseline, change calendar, prior case history)?
- Do not label an indicator malicious without the citing TI verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when a decoded artifact confirms (OTX pulse on a decoded domain/URL, or VT ≥ 5 on a recovered payload hash); account actions on analyst confirm. No confirmable artifact → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; this channel is raw `winlog.*` — space-containing literals like `Login Data`/`Local State` don't express cleanly as wildcard tokens, so confirm those two by reading the returned blocks):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*\\Cookies* or *DPAPI* or *ProtectedData*)
   ```
2. Correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window — parent lineage and command line — then follow the Windows Process Creation family baseline. Static-decode any encoded segments of the block offline; never execute recovered script content.
3. False-positive check: a legitimate PowerShell credential-migration or password-manager-integration script referencing these same paths/APIs for a sanctioned purpose — baseline and exclude by script hash/path if recurring.
**Escalation:** DPAPI-unprotect usage outside the account's own profile context, a decoded exfil destination, or browser-store file access confirmed on disk → page the IR lead; treat browser-saved credentials on the host as exposed.

###### 5. Remediation & Evidence Preservation

- Export all 4104 chunks for the `ScriptBlockId` and collect the on-disk script (from `Path`) if present; record access times on the targeted browser credential-store files.
- Force resets for every credential saved in the host's browser profiles; revoke active sessions for those accounts and hunt post-event use of them from new source hosts.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_data_compression_staging"></a>
##### PowerShell-Native Data Compression Staging

**Rule file:** `rules/sigma/posh_data_compression_staging.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Collection |
| Technique(s) | T1560 — Archive Collected Data |
| Severity (`level`) | medium |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block referencing the .NET `System.IO.Compression` namespace, OR containing `Compress-Archive` together with a temp-style destination literal (`\Temp\`, `\AppData\Local\Temp\`, `$env:TEMP`) |

Detects PowerShell-native file bundling — the equivalent of the RAR/WinRAR staging pattern, favored when a target host has no third-party archiver. `Compress-Archive` alone is common in legitimate admin scripts, so the cmdlet branch requires a temp-style destination. The rule states this destination-path scoping as a real, accepted coverage gap, not just an FP-reduction measure: staging to any path outside the three temp-path strings — e.g. `C:\ProgramData\`, `C:\Users\Public\`, or a mapped share, all real-world staging choices — evades the `Compress-Archive` branch entirely.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — carries the archive destination path and the source file set being bundled |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key for chunked blocks |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path when run from a file; collection target |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment and Sysmon-correlation anchors |

###### 3. Enrichment Criteria

- Decoded domain/URL in the block (an upload/exfil destination alongside the compression) → OTX; escalate on **any pulse match**.
- Hash of any payload or tool the block drops or references → VirusTotal; escalate at **≥ 5 malicious verdicts**. The staged archive itself is the victim's own data — hash it for the evidence record, not for a TI verdict.
- Internal-only: does a known deployment/backup job own this script (script hash/path baseline, change calendar)? What data population does the source path hold?
- An archive at a temp path is not malicious on its own — do not label it so without a cited verdict or internal case.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host action. On OTX pulse or VT ≥ 5 for a decoded artifact, auto-add that indicator to the blocklist and open an analyst ticket; no TI confirmation → Tier D triage.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; the returned text decides the branch — the `Compress-Archive` branch also requires one of the temp-destination literals in the same block):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*System.IO.Compression* or *Compress-Archive*)
   ```
2. Locate the archive at the destination path parsed from `ScriptBlockText`: hash it, inventory its contents (what data was staged). Correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline), and check the host's subsequent hours for egress pairings (large HTTP POST / SMTP-attachment detections).
3. False-positive check: a legitimate PowerShell deployment/backup script that compresses files to a temp path as an intermediate step — baseline and exclude by script hash/path if recurring.
**Escalation:** archive contents include credential stores or sensitive data sets, or a paired egress event from the same host → promote to the high-severity flow (Tier B isolate) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect and hash the staged archive and the full 4104 chunk set before removal; the archive inventory drives any data-exposure notification scope.
- If egress is confirmed, treat as an exfiltration incident: block the destination, isolate the host, and reset the executing account's credentials.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_ps_ad_recon_admodule"></a>
##### Active Directory Query via Official ActiveDirectory Module

**Rule file:** `rules/sigma/posh_ps_ad_recon_admodule.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1087.002 — Account Discovery: Domain Account |
| Severity (`level`) | low |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block containing any of the official module's query cmdlets: `Get-ADUser`, `Get-ADGroup`, `Get-ADGroupMember`, `Get-ADDomainController` |

Detects the official Microsoft ActiveDirectory module's query cmdlets — legitimate, signed, and routinely used for ordinary IT/helpdesk administration, but also usable by an attacker who prefers built-in tooling over PowerView specifically to blend in with that routine traffic. Split from a single merged rule and kept at low severity: these cmdlets are harder to rename than PowerView's functions (dot-sourced from a signed module), so a hit is worth a look, but it must not compete for triage attention with a PowerView hit (see `posh_ps_ad_recon_powerview`).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — shows which query cmdlets ran and their scoping (filters, target groups, server parameters) |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key for chunked blocks |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path when run from a file; separates saved admin scripts from ad-hoc console use |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — the sanction check pivots on this pairing |

###### 3. Enrichment Criteria

- Internal-only (recon cmdlets carry no external-TI artifact — OTX/AbuseIPDB/VT not applicable): which account ran the query, from which host, and is that pairing sanctioned for AD administration (admin-group membership, asset role, change calendar, prior case history)?
- Internal-only: query breadth — enumeration of privileged groups or domain controllers from a non-admin workstation weighs heavier than a single user lookup from a helpdesk host.
- The cmdlet names alone prove nothing; assess only the account/host/scope context, and cite an internal case before treating a hit as recon.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: triage-only — enrich context, queue for analyst review, no automation.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*Get-ADUser* or *Get-ADGroup* or *Get-ADGroupMember* or *Get-ADDomainController*)
   ```
2. Correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline); check whether the same host/user also fired `posh_ps_ad_recon_powerview` or other discovery detections in the surrounding hour.
3. False-positive check: legitimate IT/helpdesk administration scripts using the official module for routine account or group management — the rule expects meaningful, recurring volume wherever AD administration is done via PowerShell rather than the GUI.
**Escalation:** unsanctioned account/host pairing, privileged-scope enumeration from a non-admin asset, or a co-occurring PowerView hit → escalate under the `posh_ps_ad_recon_powerview` flow.

###### 5. Remediation & Evidence Preservation

- For a sanctioned hit: record the baseline (script hash/path) and tune the exclusion rather than closing silently.
- For an unsanctioned hit: document what was enumerated (the query scope is the attacker's shopping list), review the executing account's recent activity, and hunt follow-on targeting of the enumerated objects; no host artifacts to clean for the query itself.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_ps_ad_recon_powerview"></a>
##### Active Directory Reconnaissance via PowerView

**Rule file:** `rules/sigma/posh_ps_ad_recon_powerview.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1087.002 — Account Discovery: Domain Account |
| Severity (`level`) | high |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block containing any of nine PowerView function names: `Get-NetDomain`, `Get-NetUser`, `Get-NetGroup`, `Get-NetComputer`, `Get-DomainUser`, `Get-DomainController`, `Get-DomainTrust`, `Invoke-ShareFinder`, `Find-DomainShare` |

Detects well-known PowerView cmdlets — a widely-used post-exploitation AD enumeration toolkit with no comparable legitimate-administration use case, unlike the official module (see the lower-severity `posh_ps_ad_recon_admodule`). Split from a single merged rule so PowerView's high-signal hits are not buried in routine helpdesk-administration noise. Known scope limit, stated rather than hidden: PowerView's function names are ordinary PowerShell functions an attacker can trivially rename before importing.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — which PowerView functions ran and against what scope (domain, groups, shares) |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key — the imported PowerView source itself often appears as a large chunked block |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path if PowerView was run from a file; collection target |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment targets |

###### 3. Enrichment Criteria

- Internal-only (recon cmdlets carry no external-TI artifact — OTX/AbuseIPDB/VT not applicable): which account ran it, from which host, and is any authorized assessment or red-team exercise on the engagement calendar covering that pairing?
- Internal-only: prior case history for the host/account; whether the host is a scoped assessment asset.
- Absent a documented engagement, a PowerView hit has no benign explanation in this corpus — but cite the internal case/engagement check either way before assessing.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: EDR-isolate the host. This event carries no external-TI artifact, so isolation fires on analyst confirm under the 15-minute high-severity SLA (Tier D until confirmed) rather than on a TI verdict; disable the executing account at the same time.
**Analyst triage path — 15-minute SLA:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*Get-NetDomain* or *Get-NetUser* or *Get-NetGroup* or *Get-NetComputer* or *Get-DomainUser* or *Get-DomainController* or *Get-DomainTrust* or *Invoke-ShareFinder* or *Find-DomainShare*)
   ```
2. Correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline); look for how PowerView arrived — a preceding download-cradle 4104 block or a dropped `.ps1` — and sweep other hosts for the same function names.
3. False-positive check: authorized security assessments or red-team exercises using PowerView on an isolated/scoped host — confirm against the engagement calendar, not verbal assurance.
**Escalation:** no matching engagement → treat as active post-exploitation reconnaissance; page the IR lead and assume the executing account is attacker-controlled.

###### 5. Remediation & Evidence Preservation

- Collect the PowerView script file (from `Path` or the Sysmon file-creation pivot) and the full 4104 chunk set; hash collected files for the evidence record.
- Reset the executing account's credentials and revoke its Kerberos tickets and sessions; assume the enumeration output (privileged-group membership, trust map, share list) is in attacker hands and hunt follow-on targeting of those objects.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_ps_amsi_bypass_attempt"></a>
##### PowerShell AMSI Bypass Attempt

**Rule file:** `rules/sigma/posh_ps_amsi_bypass_attempt.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1562.001 — Impair Defenses: Disable or Modify Tools |
| Severity (`level`) | high |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block containing any AMSI-internals token: `AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`, `AMSI_RESULT_NOT_DETECTED` |

Detects script content referencing AMSI internals in ways consistent with a bypass — reflectively patching the `amsiInitFailed` field, referencing `AmsiUtils`/`AmsiScanBuffer` directly, or forcing the `AMSI_RESULT_NOT_DETECTED` scan result. Disabling AMSI is a standard precursor to running otherwise-detectable malicious script content. Known scope limit the rule states: substring matching only, not regex — trivial string-splitting/concatenation of these literal tokens evades it; treat as a tripwire against the common copy-pasted public bypass one-liners, not a comprehensive control.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — which bypass primitive was used; the follow-on payload often appears in adjacent blocks from the same session |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key for chunked blocks |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path when run from a file; empty for the typical pasted one-liner |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment and Sysmon-correlation anchors |

###### 3. Enrichment Criteria

- Decoded domain/URL recovered from this or an adjacent follow-on block → OTX; escalate on **any pulse match**.
- Hash of any dropped payload (via the host's Sysmon file-creation events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- If a decoded destination is a bare IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: authorized AMSI research, red-team tooling, or security-product testing on record for this host (engagement calendar)?
- The bypass string itself proves tampering intent, not payload identity — cite the TI verdict or internal case before naming an indicator malicious.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when a decoded artifact confirms (OTX pulse or VT ≥ 5); no confirmable artifact → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*AmsiUtils* or *amsiInitFailed* or *AmsiScanBuffer* or *AMSI_RESULT_NOT_DETECTED*)
   ```
2. The bypass is stage-setting: pull the same host/user's surrounding 4104 events for the follow-on payload (static decode only — never execute recovered script content), and correlate to the launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline).
3. False-positive check: legitimate AMSI research, red-team tooling, or security-product testing performed by authorized staff on an isolated host — verify against the engagement calendar.
**Escalation:** a follow-on payload block is found, or the host's AV/EDR telemetry goes quiet after the bypass → page the IR lead.

###### 5. Remediation & Evidence Preservation

- Acquire host memory before any reboot — a successful patch lives in the PowerShell process's memory — and export the full 4104 set for the session window.
- Verify AMSI/AV provider health on the host after containment; reset the executing account's credentials; block any TI-confirmed indicator from the decoded payload.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_ps_obfuscated_scriptblock"></a>
##### Obfuscated or Encoded PowerShell Script Block

**Rule file:** `rules/sigma/posh_ps_obfuscated_scriptblock.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution, Defense Evasion |
| Technique(s) | T1059.001 — Command and Scripting Interpreter: PowerShell; T1027 — Obfuscated Files or Information |
| Severity (`level`) | high |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block matching **at least two of three** indicator classes: **execute** (boundary-anchored `IEX` forms, `Invoke-Expression`, `[scriptblock]::Create`, `.Invoke()`), **download** (`DownloadString`/`DownloadFile`/`DownloadData`, `Net.WebClient`, `Invoke-WebRequest`/`Invoke-RestMethod`, `Start-BitsTransfer`, boundary-anchored `iwr`/`irm` aliases including block-start position), **encode** (`FromBase64String`, `-EncodedCommand`, `-enc `, `-bxor`, `-bnot`) — i.e. execute+download, execute+encode, or download+encode |

Detects both classic attacker shapes: IEX+WebClient download cradles with no encoding at all, and IEX+FromBase64String with no network call. Improves on `proc_creation_win_powershell_encoded`, which only catches the literal `-enc`/`-EncodedCommand` flag: 4104 logs PowerShell's own deobfuscated script-block text, so this also catches base64/bitwise obfuscation and IEX-based cradles that never pass an encoding flag on the command line. A single bare indicator (just `Invoke-Expression`, just a `Net.WebClient` reference) no longer fires (#217 redesign). Known scope limit: substring matching, not regex — trivial string reconstruction (e.g. splitting `Net.WebClient` across concatenated literals) evades it; a tripwire to complement, not replace, behavioral detections.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | The deobfuscated content — static decode yields the URLs, IPs, and payloads that drive enrichment |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key for chunked blocks |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before decoding |
| `Path` | event source (4104) | On-disk `.ps1` path when run from a file; empty for in-memory cradles |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment and Sysmon-correlation anchors |

###### 3. Enrichment Criteria

- Decoded URL/domain (the cradle's download source or C2) → OTX; escalate on **any pulse match**.
- Hash of any dropped payload (via the host's Sysmon file-creation events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- If the decoded source is a bare IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: script hash/path baseline for known bootstrap/deployment scripts that legitimately pair two classes.
- Obfuscation alone is not a verdict — the decoded indicator plus its cited TI result is; never label without one.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when a decoded artifact confirms (OTX pulse, AbuseIPDB ≥ 50%, or VT ≥ 5); no confirmable artifact → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; deliberately broader than the rule — unanchored `IEX`, representative tokens per class — then confirm which two classes co-occur by reading the returned `ScriptBlockText`):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : (*Invoke-Expression* or *IEX* or *DownloadString* or *Net.WebClient* or *Invoke-WebRequest* or *FromBase64String* or *-EncodedCommand* or *-bxor*)
   ```
2. Static-decode the block offline (base64, XOR) — never execute recovered script content; then correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline) and check Sysmon file-creation events for a dropped payload.
3. False-positive check: legitimate administrative or deployment scripts that combine two of these categories for non-malicious reasons — rare, but e.g. a bootstrap script that both downloads and dynamically invokes trusted, signed local content.
**Escalation:** decode yields an external URL/IP **and** there is evidence the cradle ran (child process, dropped file, or a matching network connection) → treat as an active intrusion; page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export and reassemble all 4104 chunks for the `ScriptBlockId` before decoding; archive both the raw and decoded forms.
- Block TI-confirmed URLs/IPs at the perimeter; collect and hash any dropped payload; remove whatever launcher the process correlation surfaces (Run key, scheduled task, service) under that rule family's flow.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="posh_ps_reverse_shell"></a>
##### PowerShell Reverse Shell via TCPClient

**Rule file:** `rules/sigma/posh_ps_reverse_shell.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Execution |
| Technique(s) | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Severity (`level`) | high |
| Data source | Winlogbeat (PowerShell/Operational) |
| Trigger condition | A 4104 script block containing `Net.Sockets.TCPClient` AND at least one stream-I/O indicator: `GetStream()`, `NetworkStream`, `.Read(`, `.Write(` |

Detects script content constructing a raw TCP socket and reading/writing its network stream — the core mechanic of every public PowerShell reverse-shell one-liner (Nishang's `Invoke-PowerShellTcp` and the canonical circulated snippets). Requires both indicator categories together: a bare `Net.Sockets.TCPClient` reference alone is common in benign port-check scripts and would be pure noise. Two stated limits: the two categories aren't proven to reference the *same* socket object (this stack has no AST/variable-binding analysis), and a TcpListener bind-shell indicator was deliberately dropped rather than silently included under a title that doesn't cover it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Channel scoping — script-block logging events (4104) only |
| `ScriptBlockText` | rule detection block | Recovered script content — carries the connect-back host and port, the primary pivot and TI artifact |
| `ScriptBlockId` | event source (4104) | Reassembly/dedup key for chunked blocks |
| `MessageNumber`, `MessageTotal` | event source (4104) | Chunk ordering — export every chunk before analysis |
| `Path` | event source (4104) | On-disk `.ps1` path when run from a file; empty for the typical pasted one-liner |
| `Computer`, `UserID` | event source (4104) | Host and executing-account SID — containment targets |

###### 3. Enrichment Criteria

- Decoded connect-back domain/URL → OTX; escalate on **any pulse match**.
- Hash of any dropped payload the shell fetches (via the host's Sysmon file-creation events) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- If the connect-back target is a bare IP (the common form) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is the destination a scoped assessment box (engagement calendar)? Does Zeek show the session actually established?
- An unestablished connect attempt is still an incident lead, but label the destination malicious only with the citing TI verdict or internal case.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the decoded connect-back indicator confirms (OTX pulse, AbuseIPDB ≥ 50%) or a fetched-payload hash hits VT ≥ 5; no confirmable artifact → Tier D with 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; the punctuation-heavy `.Read(`/`.Write(` indicators don't query cleanly — confirm them by reading the returned block):
   ```
   winlog.event_id : 4104 and winlog.event_data.ScriptBlockText : *Net.Sockets.TCPClient* and winlog.event_data.ScriptBlockText : (*GetStream* or *NetworkStream*)
   ```
2. Extract the connect-back host:port from `ScriptBlockText` statically (never execute recovered script content); confirm the session in Zeek conn telemetry — established vs failed, bytes each way, duration — a live two-way session changes urgency entirely. Correlate the 4104 event to its launching process via the host's Sysmon process-creation events in the same window (then follow the Windows Process Creation family baseline).
3. False-positive check: legitimate network-diagnostic, port-scanning, or custom TCP-based automation tooling that constructs a TCPClient and separately reads/writes a stream elsewhere in the same script — uncommon but possible; correlate the destination and surrounding script content before escalating.
**Escalation:** Zeek shows an established session with sustained two-way traffic to the decoded destination → active interactive access; page the IR lead and treat every credential usable from that session as exposed.

###### 5. Remediation & Evidence Preservation

- Acquire host memory and the process tree before killing the session; export the full 4104 chunk set and the Zeek conn records for the destination.
- Perimeter-block the connect-back destination once TI-confirmed; reset the executing account's credentials and any used during the session window; hunt persistence installed during the session (new services, tasks, Run keys, dropped files).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### Windows System Log — Service Control Manager & Event Log Service — 6 rules

<a id="system_win_driver_service_installed"></a>
##### Kernel or File-System Driver Service Installed

**Rule file:** `rules/sigma/system_win_driver_service_installed.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation, Defense Evasion |
| Technique(s) | T1068 — Exploitation for Privilege Escalation |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 7045 where `ServiceType` equals `0x1` (kernel) or `0x2` (file-system driver) exactly, or contains the descriptive strings `kernel` / `file system driver` |

Detects registration of a driver-class service — rare and genuinely notable on an endpoint, and a real privilege-escalation/defense-evasion primitive when malicious (a vulnerable-signed "BYOVD" or unsigned driver executes arbitrary code in kernel context). The rule states its own limits: System 7045 carries no code-signing field, so it only proves a driver-class service was registered — every signature/trust judgment belongs in triage; and the rendering of `ServiceType` has not been validated against a real 7045 event, which is part of why the rule remains `experimental`. Hex values are matched by exact equality (not `contains`) so the rule does not fire on the routine user-mode types `0x10`/`0x20`.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 7045 (new service installed) |
| `ServiceType` | rule detection block | Driver-class discriminator (`0x1` kernel / `0x2` file-system) |
| `ServiceName` | event source (System 7045) | Compare against the environment's known-good driver-service baseline |
| `ImagePath` | event source (System 7045) | Path to the `.sys` driver file — the collection and hash pivot |
| `StartType` | event source (System 7045) | Boot/system-start drivers load earliest and persist across reboot |
| `Computer` | event source (System channel) | Host; the record timestamp anchors the timeline |

###### 3. Enrichment Criteria

- Driver file at `ImagePath` → VirusTotal; escalate at **≥ 5 malicious verdicts**. The 7045 event carries no hash: a driver is loaded by the kernel, not spawned, so no Sysmon EID 1 exists for the driver itself — collect the file from disk and hash it. The *installer's* Sysmon EID 1 (the tool that registered the service, same window) is the process-side pivot.
- Internal-only checks: known-good driver baseline (AV/EDR agents, VPN clients, virtualization tooling, printer/peripheral drivers), software-deployment records, change calendar.
- A driver-class 7045 alone proves registration, nothing more — no maliciousness call without the VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on a VT verdict ≥ 5 for the collected driver-file hash, auto-add the hash to the EDR blocklist; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; System channel is raw `winlog.*`):
   ```
   winlog.event_id : 7045 and winlog.event_data.ServiceType : ("0x1" or "0x2" or *kernel*)
   ```
   Review `winlog.event_data.ServiceType` in the results by eye as well — the descriptive-string rendering is the unvalidated case.
2. Pivot to the installer: Sysmon EID 1 on the host ±5 minutes around the 7045 — which process registered the driver, launched by whom.
3. False-positive checks: legitimate AV/EDR agent, VPN client, virtualization platform, or printer/peripheral driver installation or update — baseline the known-good driver service names and exclude them by name.
**Escalation:** driver file fails offline signature validation, appears on a published vulnerable-driver blocklist, or returns VT ≥ 5 → page the IR lead; treat the kernel as potentially compromised.

###### 5. Remediation & Evidence Preservation

- Before removal: collect and hash the `.sys` file at `ImagePath`, export the service registry key (`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`), and record whether the driver actually loaded.
- Cleanup: delete the service registration, remove the driver file, reboot to unload. If a malicious driver ran in kernel context, on-host telemetry from that period is untrustworthy — prefer reimage on confirmation.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="system_win_eventlog_cleared"></a>
##### Event Log Cleared (Windows System 104)

**Rule file:** `rules/sigma/system_win_eventlog_cleared.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 104 ("the <log> log was cleared") — fires for any log channel cleared, no filters |

Detects the native event the Windows Event Log service emits whenever any channel (Security, System, Application, …) is cleared. More reliable than command-line-based detection alone (`proc_creation_win_clear_event_logs.yml`) since it fires regardless of the tool used — kept alongside that rule and `auth_win_security_log_cleared.yml`, not a replacement for either. A log clear is an anti-forensics act: the interesting question is always what it was meant to conceal.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 104 (log cleared) |
| `Channel` | event source (System 104) | Which log was cleared — a Security-channel clear is the highest-signal case |
| `SubjectUserName`, `SubjectDomainName` | event source (System 104) | Account that performed the clear — identity pivot |
| `BackupPath` | event source (System 104) | Backup file path when the clearing tool saved one — collect it if present |
| `Computer` | event source (System channel) | Host; the record timestamp marks the end of the destroyed local window |

###### 3. Enrichment Criteria

- The 104 event itself carries no hashable artifact; the TI target is the clearing tool: correlate Sysmon EID 1 on the host in the surrounding minutes (`wevtutil.exe`, PowerShell, or an unknown binary) and submit that binary's SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only checks: approved log-retention/rotation maintenance schedule; is `SubjectUserName` an expected admin or service account for this host; prior case history on the host.
- The clear is proven by the event itself; who and why are not — cite the correlated process evidence or an internal case ID before labeling it hostile.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the clearing tool's hash is VT-confirmed ≥ 5; account actions on analyst confirm. No TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 104 and host.name : "<host>"
   ```
   Read the cleared channel and the initiating account from the matched documents.
2. Pivot: Sysmon EID 1 on the host ±10 minutes to find the clearing process and its parent; then sweep the host's other alerts — this event derives most of its meaning from what surrounds it.
3. False-positive check: scheduled log-retention or rotation tooling that clears logs as part of approved maintenance — confirm against the maintenance schedule.
**Escalation:** the clear co-occurs with any other alert on the same host (any family, ±24 h) → treat as high-priority anti-forensics concealing that activity; page the IR lead.

###### 5. Remediation & Evidence Preservation

- Pull the SIEM's forwarded copy of the cleared channel for the affected window — the shipped copy survives local clearing; export it before index rollover and hunt the concealed activity there. Collect `BackupPath` if the event names one.
- Restore audit capability: verify the Event Log service is running and the cleared channel is receiving events again; revert any audit-policy changes found alongside the clear.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="system_win_eventlog_service_tamper"></a>
##### Windows Event Log Service Reconfigured or Disabled (Windows System 7040)

**Rule file:** `rules/sigma/system_win_eventlog_service_tamper.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion |
| Technique(s) | T1562.002 — Impair Defenses: Disable Windows Event Logging |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 7040 (service start-type changed) where `param1`, the service display name, contains `Event Log` |

Detects the Event Log service itself being disabled or demoted — an attacker switching off logging ahead of other activity. Known scope limits stated by the rule: it only catches a start-type *change* (7040) — an attacker who stops the running service directly (7036, not currently collected) is not covered; and `param1` is the localized service display name, so the `Event Log` match is English-only and a non-English host needs its locale-specific string added.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 7040 (service start-type changed) |
| `param1` | rule detection block | Service display name — confirms the target is the Windows Event Log service |
| `param2` | event source (System 7040) | Old start type — the value to restore |
| `param3` | event source (System 7040) | New start type — `disabled` or a demotion confirms the tamper direction |
| `Computer` | event source (System channel) | Host; the record timestamp starts the at-risk logging window |

###### 3. Enrichment Criteria

- The 7040 event carries no hashable artifact; the TI target is the process that changed the start type: correlate Sysmon EID 1 on the host in the surrounding minutes (`sc.exe`, `reg.exe`, PowerShell, MMC, or an unknown binary) and submit that binary's SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only checks: approved endpoint-hardening or migration change records; asset owner; whether the same change appears on other hosts (sanctioned rollout vs. targeted tamper).
- The start-type change is proven; intent is not — cite the correlated process evidence or a change record before calling it hostile.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the reconfiguring tool's hash is VT-confirmed ≥ 5; account actions on analyst confirm. No TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 7040 and winlog.event_data.param1 : "Windows Event Log"
   ```
   (On a non-English host, substitute the localized display name — the same limit the rule documents.)
2. Read `param2`/`param3` for direction, then pivot to Sysmon EID 1 ±10 minutes for the process that made the change. A start-type change alone does not stop the already-running service — logging continues until a stop or reboot, so act inside that window.
3. False-positive check: approved endpoint-hardening or migration scripts that intentionally reconfigure the Event Log service's start type — confirm against the change record.
**Escalation:** the 7040 co-occurs with any other alert on the same host (any family, ±24 h), or `param3` shows `disabled` with no matching change record → high-priority anti-forensics; page the IR lead.

###### 5. Remediation & Evidence Preservation

- Restore audit capability first: revert the start type to the `param2` value (normally automatic start), start the service if stopped, and confirm new events are flowing from the host again.
- Pull the SIEM's forwarded copies covering the tamper-to-restoration gap — the shipped copy of pre-tamper events survives anything done locally; treat purely local logs from the gap as incomplete and hunt the interval activity in forwarded telemetry.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="system_win_remote_service_creation_psexec_style"></a>
##### Remote-Style Service Creation (PsExec Pattern)

**Rule file:** `rules/sigma/system_win_remote_service_creation_psexec_style.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1543.003 — Create or Modify System Process: Windows Service |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 7045 with `ServiceName` exactly `PSEXESVC` |

Detects PsExec's default temporary service name on the target host — used by the legitimate Sysinternals tool and by virtually every reimplementation (Impacket's psexec.py, CrackMapExec, most C2 lateral-movement modules) unless explicitly overridden. It fires at service registration itself, before any payload executes, complementing `proc_creation_win_lateral_tool_parent.yml`, which only fires later if the service goes on to spawn a shell. Known, accepted limitation stated by the rule: an operator who renames the service (`-r <name>` in PsExec) evades it. The lateral-movement context is real, but the event itself — a service registered on this host — is a persistence/privilege-escalation primitive, hence the T1543.003 tagging.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 7045 (new service installed) |
| `ServiceName` | rule detection block | `PSEXESVC` — the PsExec-family default |
| `ImagePath` | event source (System 7045) | Path to the dropped service executable — the hash pivot |
| `AccountName` | event source (System 7045) | Account the service runs as |
| `StartType` | event source (System 7045) | Demand-start is the tool's normal pattern |
| `Computer` | event source (System channel) | Target host; the record timestamp orders a multi-host sweep |

###### 3. Enrichment Criteria

- Service binary at `ImagePath` → VirusTotal; escalate at **≥ 5 malicious verdicts**. The hash comes from the correlated Sysmon EID 1 event for that binary (when the service starts), not from the 7045 event itself, which carries no hash field. A clean verdict on a genuine Sysinternals binary does not make the use authorized — authorization is an internal question.
- Internal-only checks: change calendar and the known-admin source-host list (legitimate PsExec use is a real IT-operations pattern here per the rule's own falsepositives); case history for the initiating account.
- Do not label the session malicious without the TI verdict or an internal case ID — the service name alone is tool identification, not intent.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the target host when the service-binary hash is VT-confirmed ≥ 5; disable the initiating account on analyst confirm. No TI confirmation → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify and fleet-sweep with KQL (index `logstash-*`):
   ```
   winlog.event_id : 7045 and winlog.event_data.ServiceName : "PSEXESVC"
   ```
   Count distinct `host.name` values over the last 24 h — one host reads as targeted admin activity or a single pivot; several reads as a campaign.
2. Identity sweep: correlate the Security-channel network logon (4624 LogonType 3) on the target in the same minute to identify the initiating account and source host; pivot Sysmon EID 1 for what the service executed.
3. False-positive check: legitimate administrative use of PsExec for remote troubleshooting or software deployment — correlate against the change calendar and known admin source hosts before treating as malicious.
**Escalation:** `PSEXESVC` registered on two or more hosts in a short window, or an initiating account/source host outside the admin baseline → treat as active lateral movement; page the IR lead.

###### 5. Remediation & Evidence Preservation

- Collect and hash the service executable at `ImagePath` and export the 7045 plus the correlated logon events before any cleanup; PsExec normally removes its service on exit, so a still-registered `PSEXESVC` is itself worth noting.
- Delete any leftover service registration and binary; treat the initiating account's credentials as exposed on this host — reset and revoke its sessions on confirmation; sweep for the same service creation fleet-wide.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="system_win_service_installed"></a>
##### New Service Installed (Windows System 7045)

**Rule file:** `rules/sigma/system_win_service_installed.yml` · **Status:** stable · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1543.003 — Create or Modify System Process: Windows Service |
| Severity (`level`) | medium |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 7045 for any new service registration, unless `ImagePath` starts with a standard OS/program directory (bare, quoted, `%SystemRoot%`, and NT-path forms are all excluded) |

Native, tool-agnostic coverage of every new service registration, complementing `proc_creation_win_service_creation_sc.yml` (which only catches `sc.exe`). The rule is explicit that its common-directory allowlist is a volume heuristic only, not a hardening guarantee: registering a service already requires the same admin/SYSTEM privilege needed to write into the excluded directories, so any attacker who can trigger this event at all can place their binary in an excluded path and generate no alert. It exists to suppress routine installer/patch/agent noise and must not be relied on as evasion-resistant.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 7045 (new service installed) |
| `ImagePath` | rule detection block | Service binary path — a non-standard location is what alerted; primary pivot |
| `ServiceName` | event source (System 7045) | Baseline lookup and removal key |
| `ServiceType`, `StartType` | event source (System 7045) | Auto-start services carry the most persistence weight |
| `AccountName` | event source (System 7045) | Run-as account — LocalSystem means SYSTEM-level persistence |
| `Computer` | event source (System channel) | Host; the record timestamp anchors the install window |

###### 3. Enrichment Criteria

- Service binary at `ImagePath` → VirusTotal; escalate at **≥ 5 malicious verdicts**. The hash comes from the correlated Sysmon EID 1 event for that binary, not from the 7045 event itself (7045 carries no hash field); failing that, collect the file from disk and hash it.
- Internal-only checks: software-deployment and patch-management records for the install; known-service baseline for `ServiceName`; asset owner for context on the unusual path.
- An unusual install path is a lead, not a verdict — no maliciousness call without the VT result or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on a VT verdict ≥ 5 for the service-binary hash, auto-add the hash to the EDR blocklist; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 7045 and host.name : "<host>"
   ```
   Review `winlog.event_data.ImagePath` and `winlog.event_data.ServiceName` in the results — the alerting event is the one whose path falls outside the standard OS/program directories.
2. Pivot to the installer: Sysmon EID 1 ±5 minutes around the 7045 for the registering process; classify the `ImagePath` location (user profile, temp, custom drive) and check whether the binary is first-seen in the environment.
3. False-positive checks: legitimate software installers, patch management, and endpoint agents that install services outside the standard OS/program directories (e.g. a vendor tool that installs to a user profile or a custom drive).
**Escalation:** `ImagePath` in a user-writable directory and the binary unknown to deployment records, or an auto-start service registered outside any change window → promote to the high-severity flow (Tier B isolate on analyst confirm).

###### 5. Remediation & Evidence Preservation

- Before removal: collect and hash the binary at `ImagePath`, and export the service registry key (`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`).
- Cleanup: stop and delete the service, remove the binary, then watch the host for re-creation — service persistence is commonly reinstalled by a second mechanism.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="system_win_suspicious_service_binpath_lolbin"></a>
##### New Service Installed With a LOLBin as its Binary

**Rule file:** `rules/sigma/system_win_suspicious_service_binpath_lolbin.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence, Privilege Escalation |
| Technique(s) | T1543.003 — Create or Modify System Process: Windows Service |
| Severity (`level`) | high |
| Data source | Winlogbeat (Windows System) |
| Trigger condition | System 7045 where `ImagePath` contains any of `cmd.exe`, `powershell.exe`, `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe` |

Detects a service whose `ImagePath` is itself a living-off-the-land binary rather than a dedicated service executable — the service exists purely as a persistence wrapper to auto-run a one-liner (or a VBS/JS payload via wscript/cscript) as SYSTEM at boot. Orthogonal to `system_win_service_installed.yml`'s path-based noise filter: this rule fires regardless of install path, because a service binary that IS a LOLBin is unusual no matter where it is installed from.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Selects System 7045 (new service installed) |
| `ImagePath` | rule detection block | Carries the LOLBin plus its full argument string — payload path, encoded command, or URL live here |
| `ServiceName` | event source (System 7045) | Baseline-exclusion key for the sanctioned-wrapper false positive |
| `StartType` | event source (System 7045) | Auto-start confirms boot persistence intent |
| `AccountName` | event source (System 7045) | Run-as account — typically LocalSystem for this pattern |
| `Computer` | event source (System channel) | Host; the record timestamp anchors the install window |

###### 3. Enrichment Criteria

- The LOLBin named in `ImagePath` is Microsoft-signed — its own hash is not the signal. The TI target is the script/payload file referenced in the `ImagePath` argument string: collect it and submit its SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**. The hash comes from the file (or the correlated Sysmon EID 1 event when the service runs), not from the 7045 event itself.
- Any URL or domain embedded in the argument string → OTX; escalate on any pulse match.
- Internal-only checks: baseline of sanctioned wrapper services by exact `ServiceName`; change calendar for the install.
- Cite the payload's TI verdict or an internal case ID before calling the service malicious — the wrapper shape alone is the alert, not the proof.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the referenced payload's hash is VT-confirmed ≥ 5 (or its embedded URL/domain returns an OTX pulse); account actions on analyst confirm. No TI-confirmable artifact → Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   winlog.event_id : 7045 and winlog.event_data.ImagePath : (*cmd.exe* or *powershell.exe* or *rundll32.exe* or *mshta.exe* or *regsvr32.exe* or *wscript.exe* or *cscript.exe*)
   ```
2. Parse the full `ImagePath` argument string: extract and collect any referenced script or payload file, decode any base64/encoded command, and note any URL. Confirm whether the service has already run via the LOLBin's Sysmon EID 1 with matching arguments (service-start 7036 is not collected in this environment).
3. False-positive check: a legitimate scheduled-task-style service wrapper that intentionally launches powershell.exe/cmd.exe to run an internal script — baseline and exclude these specific service names by exact match.
**Escalation:** encoded command or external URL in the argument string, or evidence the service already executed → page the IR lead; treat as active SYSTEM-level persistence.

###### 5. Remediation & Evidence Preservation

- Collect the referenced script/payload files and export the service registry key (`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`) before deletion; capture the decoded command content as evidence.
- Cleanup: stop and delete the service, remove the payload files, and hunt sibling persistence — the same one-liner frequently also exists as a scheduled task or Run key on the host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### Zeek Network Telemetry — 21 rules

<a id="net_zeek_conn_external_rdp_inbound"></a>
##### RDP Connection Originating From Outside Private Address Space

**Rule file:** `rules/sigma/net_zeek_conn_external_rdp_inbound.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Lateral Movement |
| Technique(s) | T1021.001 — Remote Services: Remote Desktop Protocol |
| Severity (`level`) | high |
| Data source | Zeek conn |
| Trigger condition | TCP connection to responder port 3389 where the originator address falls outside all three RFC1918 blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) |

Detects a genuinely externally-sourced RDP session — not merely RDP "seen by the sensor" — by CIDR-checking the originator against RFC1918 space instead of assuming boundary sensor placement. Stated limit: if the campus addressing plan uses ranges outside the three RFC1918 blocks (e.g. carrier-grade NAT space, RFC6598 100.64.0.0/10), internal sources in those ranges wrongly appear external — verify against the real addressing plan before relying on this in production.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `id.resp_p` | rule detection block | Confirms the RDP service port (3389) |
| `proto` | rule detection block | Confirms TCP transport |
| `id.orig_h` | rule detection block | External originator — primary TI artifact |
| `id.resp_h` | event source (Zeek conn.log) | Internal RDP responder — containment target |
| `id.orig_p` | event source (Zeek conn.log) | Originator port; ties the flow to related sessions |
| `conn_state`, `history`, `duration`, `orig_bytes`, `resp_bytes` | event source (raw Zeek conn.log) | Established interactive session vs. unanswered probe |

###### 3. Enrichment Criteria

- `id.orig_h` (external originator) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: asset inventory on `id.resp_h` — is it a sanctioned, firewalled remote-desktop gateway? Check the change calendar and the firewall rule set for an intentional exposure.
- Case history: prior alerts for the same external source (scanning, brute force) raise confidence.
- An external address touching 3389 is not by itself malicious — cite the AbuseIPDB verdict or an internal case before labeling it so.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the internal responder `id.resp_h` when the external originator is AbuseIPDB-confirmed at ≥ 50% confidence; account actions on analyst confirm. Without TI confirmation: Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; Zeek fields are ECS-mapped):
   ```
   destination.port : 3389 and network.transport : "tcp" and not (source.ip : "10.0.0.0/8" or source.ip : "172.16.0.0/12" or source.ip : "192.168.0.0/16")
   ```
2. Session-vs-probe check: `conn_state`/`history`/`duration`/`resp_bytes` are not indexed — pull the flow's raw conn.log record; an unanswered probe (near-zero bytes) triages very differently from a long bidirectional session. Then confirm an actual interactive logon on the responder: `winlog.event_id : 4624 and winlog.event_data.LogonType : "10"`.
3. Endpoint pivot: sweep `id.resp_h`'s Sysmon process-creation events in the session window for the logon's child processes; follow the Windows Process Creation family baseline for anything spawned.
4. False-positive checks: an intentionally provisioned, firewalled remote-desktop gateway (allowlist its specific source/destination pair rather than excluding port 3389 broadly); internal ranges not covered by the three RFC1918 blocks (e.g. CGN 100.64.0.0/10). A NAT or port-forward boundary between sensor and client can also present a translated public source for an operationally internal session — distinguishing this needs the raw conn.log context plus the addressing plan.
**Escalation:** established session (meaningful bidirectional bytes) plus a matching LogonType 10 logon on the responder → page the IR lead; treat `id.resp_h` as compromised pending review.

###### 5. Remediation & Evidence Preservation

- Export the conn.log slice for the `id.orig_h` ↔ `id.resp_h` pair and the responder's Security log window (4624/4625) before rollover.
- Close the exposure: remove or restrict the firewall/NAT rule publishing 3389; force traffic through the sanctioned gateway path.
- If a logon succeeded: reset the accounts used, revoke their sessions and tickets, and hunt lateral movement originating from `id.resp_h`.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and both endpoint addresses.

<a id="net_zeek_conn_icmp_tunnel_large"></a>
##### Unusually Large ICMP Flow (Possible ICMP Tunnel)

**Rule file:** `rules/sigma/net_zeek_conn_icmp_tunnel_large.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1095 — Non-Application Layer Protocol |
| Severity (`level`) | medium |
| Data source | Zeek conn |
| Trigger condition | ICMP flow whose originator has sent more than 1,000,000 cumulative bytes across the whole tracked flow |

Detects the data volume ICMP tunneling tools (icmpsh, ptunnel, icmptunnel) reach when moving real data, which ordinary ping traffic essentially never does. The rule states its own limit: `orig_bytes` is cumulative for the entire Zeek-tracked flow, not per packet, so it conflates duration with size — a very long-running monitoring flow can accumulate volume slowly, and flow duration must be checked alongside the byte count before escalating.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `proto` | rule detection block | ICMP flow selector |
| `orig_bytes` | rule detection block | Cumulative originator bytes — the 1,000,000-byte threshold |
| `id.orig_h` | event source (Zeek conn.log) | Internal sender — containment target |
| `id.resp_h` | event source (Zeek conn.log) | Remote endpoint — primary TI artifact |
| `duration` | event source (raw Zeek conn.log) | Separates a slow multi-day monitoring flow from a dense transfer |
| `resp_bytes` | event source (raw Zeek conn.log) | Return-direction volume — tunnel channels are bidirectional |

###### 3. Enrichment Criteria

- `id.resp_h` (remote endpoint) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: asset role of `id.orig_h` — is it a known monitoring server (Smokeping/Nagios/MTR host) with a documented reason to ping this destination continuously?
- Compute effective rate (`orig_bytes` ÷ `duration`, from the raw conn.log): a dense burst is the tunnel shape; a trickle over days is the monitoring shape.
- Volume alone is not a verdict — pair the byte count with the AbuseIPDB result or an internal case before calling the flow malicious.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On AbuseIPDB ≥ 50% confirmation of `id.resp_h`, auto-add the IP to the perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   network.transport : "icmp" and source.bytes > 1000000
   ```
2. Duration and direction check: `duration` and `resp_bytes` are not indexed — the flow needs its raw conn.log record to separate a long-lived monitoring flow from a dense transfer and to see whether data flowed both ways.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events in the flow window for the process generating ICMP (tunnel clients run as ordinary user processes); follow the Windows Process Creation family baseline for what you find.
4. False-positive checks: continuous ICMP-based network monitoring (Smokeping, Nagios, MTR, keepalive checks) running for a very long uninterrupted period against one destination; path-MTU discovery or diagnostic tooling issuing many deliberately oversized ping payloads (e.g. `ping -s`) in one troubleshooting session.
**Escalation:** dense transfer rate from a non-monitoring host plus a responsible process identified on `id.orig_h` → treat as an active covert channel; promote to the high-severity flow (Tier B isolate of the sending host).

###### 5. Remediation & Evidence Preservation

- Export the full conn.log slice for the `id.orig_h` ↔ `id.resp_h` pair before rollover — the byte/duration series is the channel evidence.
- Block or rate-limit ICMP to the remote endpoint at the perimeter; if a tunnel client is found, hash its binary for VT, remove it, and remove whatever launcher persists it.
- Review what data the sending host could reach — a confirmed tunnel is an exfiltration path, not just a C2 channel.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and both endpoints.

<a id="net_zeek_conn_smb_lateral_admin"></a>
##### SMB Connection Crossing Private/Public Address Boundary

**Rule file:** `rules/sigma/net_zeek_conn_smb_lateral_admin.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Lateral Movement |
| Technique(s) | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| Severity (`level`) | high |
| Data source | Zeek conn |
| Trigger condition | TCP connection to responder port 445 unless both originator and responder are inside RFC1918 space — internal-to-internal is the only traffic excluded |

SMB legitimately stays entirely internal on a well-run network; a session with either leg outside private address space is either external exposure of an internal share or lateral-movement tooling reaching across a boundary — distinguishable from the address ranges alone, without assuming where the sensor sits. Same stated limit as the RDP sibling rule: internal ranges not covered by the three RFC1918 blocks will wrongly appear external — verify the addressing plan.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `id.resp_p` | rule detection block | Confirms the SMB service port (445) |
| `proto` | rule detection block | Confirms TCP transport |
| `id.orig_h` | rule detection block | Originator — determines the flow's direction across the boundary |
| `id.resp_h` | rule detection block | Responder — the other leg; one of the two is the external TI artifact |
| `id.orig_p` | event source (Zeek conn.log) | Originator port context |
| `conn_state`, `history`, `duration`, `orig_bytes`, `resp_bytes` | event source (raw Zeek conn.log) | Established session and transfer volume vs. blocked/reset attempt |

###### 3. Enrichment Criteria

- Whichever of `id.orig_h` / `id.resp_h` is outside RFC1918 → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is this a documented cross-site file-share replication link? Check the change calendar and the firewall configuration for the specific pair.
- Direction matters: internal originator → external 445 is possible data movement or credential exposure to an attacker-controlled server; external originator → internal responder is an exposed share. Record which shape this event is.
- Neither shape is malicious without the AbuseIPDB verdict or an internal case ID — cite one before acting.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the internal leg when the external leg is AbuseIPDB-confirmed at ≥ 50% confidence; account actions on analyst confirm. Without TI confirmation: Tier D with 15-minute analyst SLA; Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   destination.port : 445 and network.transport : "tcp" and not ((source.ip : "10.0.0.0/8" or source.ip : "172.16.0.0/12" or source.ip : "192.168.0.0/16") and (destination.ip : "10.0.0.0/8" or destination.ip : "172.16.0.0/12" or destination.ip : "192.168.0.0/16"))
   ```
2. Establishment check: `conn_state`/`history`/`orig_bytes`/`resp_bytes` are not indexed — pull the raw conn.log record; a perimeter-blocked attempt (rejected/reset, no payload) triages differently from an established session moving bytes.
3. Endpoint pivot: on the internal leg, sweep Sysmon process-creation events in the flow window for the process that opened or served the session; follow the Windows Process Creation family baseline.
4. False-positive checks: a deliberate, firewalled cross-site file-share replication link with one leg outside private address space (allowlist the specific source/destination pair rather than excluding port 445 broadly); internal ranges not covered by the three RFC1918 blocks. An edge NAT can also translate a peer's address so an operationally internal session shows a public leg — the raw conn.log context plus the addressing plan is needed to distinguish.
**Escalation:** established cross-boundary session with meaningful transfer volume, or the internal leg hosts sensitive shares → page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the conn.log slice for the pair (and the internal host's Security log window if a logon accompanied the session) before rollover.
- Block 445 across the boundary at the perimeter — SMB should never cross it; allowlist only the documented replication pair if one exists.
- If credentials were presented outbound, treat them as exposed: reset and revoke. Review share ACLs on an exposed internal responder.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and both endpoints.

<a id="net_zeek_conn_tor_exit_node"></a>
##### Connection to Tor's Default OR or Directory Port

**Rule file:** `rules/sigma/net_zeek_conn_tor_exit_node.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1090.003 — Proxy: Multi-hop Proxy |
| Severity (`level`) | medium |
| Data source | Zeek conn |
| Trigger condition | TCP connection to responder port 9001 (Tor onion-router) or 9030 (directory authority) |

Detects a campus host acting as, or connecting out to, a Tor relay — anonymized C2 or policy-violating anonymization. The rule states its gaps plainly: obfs4 and other pluggable-transport bridges use arbitrary non-default ports, and meek/domain-fronting transports tunnel over 443 and are invisible to a port check — this catches default-configuration Tor only. Port 9001 is also a common alternate application port (some Tomcat, JBoss, etcd, HSQLDB deployments), so a hit is a weak indicator until the destination is verified.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `id.resp_p` | rule detection block | 9001 vs 9030 — OR circuit vs directory fetch |
| `proto` | rule detection block | Confirms TCP transport |
| `id.orig_h` | event source (Zeek conn.log) | Internal client — containment target |
| `id.resp_h` | event source (Zeek conn.log) | Remote endpoint — primary TI artifact |
| `service` | event source (Zeek conn.log) | Protocol Zeek recognized on the port (TLS on a real OR port) |
| `duration`, `orig_bytes`, `resp_bytes` | event source (raw Zeek conn.log) | Long-lived circuit vs. one-shot probe |

###### 3. Enrichment Criteria

- `id.resp_h` → AbuseIPDB; escalate at **≥ 50% confidence** (relay and exit addresses are widely reported).
- Internal-only: is `id.orig_h` a sanctioned research or CS-department host with a documented reason to run a relay/bridge? Check asset owner and prior case history.
- Verify the destination is actually Tor before treating the hit as Tor — port 9001 alone does not establish it (see the false-positive list).
- No verdict without the AbuseIPDB citation or an internal case — a port number is not evidence of intent.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On AbuseIPDB ≥ 50% confirmation of `id.resp_h`, auto-add the IP to the perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   destination.port : (9001 or 9030) and network.transport : "tcp" and source.ip : "<orig_h>"
   ```
2. Behavior check: sweep the same source for repeated connections to multiple distinct destinations on these ports (`destination.port : (9001 or 9030)` without the source clause, bucketed by `source.ip`/`destination.ip`) — circuit-building touches several relays; a single hit to one host is more likely an unrelated service. Circuit longevity (`duration`, byte counts) needs the raw conn.log record.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events in the window for the client process (a Tor client/browser bundle, or something else entirely that happens to use the port); follow the Windows Process Creation family baseline.
4. False-positive checks: a deliberately operated Tor relay/bridge (unusual on a campus network but possible for a research or CS-department host — allowlist by source if intentional); port 9001 as an alternate application port for unrelated services (Tomcat, JBoss, etcd, HSQLDB) — verify the destination before treating a hit as Tor.
**Escalation:** destination confirmed as Tor infrastructure plus a non-sanctioned client process on the internal host → treat as anonymized C2 or deliberate evasion; promote to the high-severity flow (Tier B isolate of `id.orig_h`).

###### 5. Remediation & Evidence Preservation

- Export the conn.log slice for `id.orig_h` — the full set of touched relay addresses is the circuit evidence.
- Remove the Tor client/relay software (or apply the policy action if this is misuse rather than compromise); block the confirmed relay IPs at the perimeter.
- If the client process was not user-installed, treat the host as compromised and follow the endpoint family baseline for the process found.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and endpoints.

<a id="net_zeek_dns_crypto_mining_pool"></a>
##### DNS Query for a Known Cryptocurrency Mining Pool

**Rule file:** `rules/sigma/net_zeek_dns_crypto_mining_pool.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Impact |
| Technique(s) | T1496 — Resource Hijacking |
| Severity (`level`) | medium |
| Data source | Zeek dns |
| Trigger condition | DNS query exactly matching one of 11 mining-pool operator domains, or a dot-anchored subdomain of one (e.g. `.nanopool.org`) |

Detects a host resolving a well-known cryptomining pool — unauthorized cryptojacking (a compromised host or a misused campus machine) reaching a pool to submit shares. Two honesty caveats the rule itself states: the hardcoded operator list needs periodic maintenance and is a starting point, not complete (severity is medium precisely to match that staleness risk); and the rule matches the observed query, not the response — any host that can send a DNS packet can emit an arbitrary label under a real operator domain, so a hit is an emission signal, not proof the query resolved or that a mining session followed.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `query` | rule detection block | Matched pool operator domain — primary TI artifact |
| `id.orig_h` | event source (Zeek dns.log) | Querying host — containment target |
| `id.resp_h` | event source (Zeek dns.log) | Resolver used (flags rogue-resolver bypass) |
| `qtype_name` | event source (Zeek dns.log) | Query type context |
| `rcode_name` | event source (Zeek dns.log) | Did the query actually resolve |
| `answers` | event source (Zeek dns.log) | Resolved pool server IPs, if any |

###### 3. Enrichment Criteria

- `query` domain → OTX: escalate on any pulse match for the exact or registered domain.
- If the query resolved, enrich the `answers` IPs → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is `id.orig_h` on an isolated segment doing deliberate, authorized crypto/security research? Check asset owner and case history; check for repeated queries over hours (share-submission cadence) rather than a one-off lookup.
- A single emission-shaped hit with no resolution and no pulse proves nothing — hold the label until a TI verdict or internal case supports it.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On an OTX pulse (or AbuseIPDB-confirmed answer IP), auto-add the domain to the DNS/perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   source.ip : "<orig_h>" and dns.question.name : ("<pool_domain>" or *.<pool_domain>)
   ```
   Drop the `source.ip` clause to sweep the fleet for other hosts querying the same operator.
2. Cadence check: bucket the host's hits over hours — real mining resolves its pool repeatedly and long-term; check `dns.response_code` and `dns.answers` to confirm resolution rather than bare emission.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events for the responsible process — miners are long-running, CPU-bound, and often persisted; hash the binary for VT (≥ 5 malicious verdicts) and follow the Windows Process Creation family baseline.
4. False-positive checks: deliberate, authorized crypto/security research on an isolated segment; a hit on a random-looking subdomain of a real operator is an emission signal only — do not treat a hit alone as proof a mining session followed.
**Escalation:** recurring resolved queries plus a responsible process on the host → confirmed cryptojacking; promote to the high-severity flow (Tier B isolate of the querying host).

###### 5. Remediation & Evidence Preservation

- Export the dns.log slice for `id.orig_h` (and the conn.log flows to any resolved pool IPs) before rollover.
- Kill the miner process, remove its persistence (scheduled task/service/run key — whatever the endpoint pivot found), and hash the binary before deletion.
- Block the operator domain(s) and resolved IPs; then work backwards to initial access — a dropped miner means something delivered it.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs and the miner binary; record the UTC window and source host.

<a id="net_zeek_dns_dga_nxdomain_burst"></a>
##### NXDOMAIN Response for a DGA-Characteristic Domain Name

**Rule file:** `rules/sigma/net_zeek_dns_dga_nxdomain_burst.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1568.002 — Dynamic Resolution: Domain Generation Algorithms |
| Severity (`level`) | medium |
| Data source | Zeek dns |
| Trigger condition | DNS response `rcode_name: NXDOMAIN` for a query containing a 20+ character alphanumeric label |

Detects the structural shape of DGA malware probing for its next-active C2 domain (most candidates never resolve). The rule states its own limits: label length is a proxy for entropy, and per-source burst cardinality cannot be expressed in a single Sigma condition — burst confirmation is an analyst step below. Rule falsepositives: typo'd or stale internal hostnames retried by misconfigured clients; CDN/cloud failover schemes probing several long randomized candidate hostnames.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `query` | rule detection block | Candidate DGA domain — primary TI artifact |
| `rcode_name` | rule detection block | Confirms non-resolution (NXDOMAIN) |
| `id.orig_h` | event source (Zeek dns.log) | Internal querying host — containment target |
| `id.resp_h` | event source (Zeek dns.log) | Resolver used (flags rogue-resolver bypass) |
| `qtype_name` | event source (Zeek dns.log) | Query type context |
| `answers` | event source (Zeek dns.log) | Non-empty on a later sibling hit = the campaign's live domain |

###### 3. Enrichment Criteria

- `query` domain → OTX: escalate on any pulse match for the exact or registered domain.
- If a related query from the same `id.orig_h` later resolves, enrich the answer IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: burst confirmation — count distinct long-label NXDOMAIN queries from the same source over 10 minutes; ≥ 10 distinct is a strong DGA signal (the cardinality check the Sigma rule cannot express).
- A single NXDOMAIN with no pulse and no burst is not malicious — do not label it so without a cited verdict.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On OTX pulse or AbuseIPDB ≥ 50% confirmation, auto-add the domain to the DNS/perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify and burst-check with KQL (index `logstash-*`; Zeek fields are ECS-mapped):
   ```
   dns.response_code : "NXDOMAIN" and source.ip : "<orig_h>"
   ```
   Bucket `dns.question.name` over 10-minute windows; count distinct long-label queries.
2. Pivot for the live domain: `source.ip : "<orig_h>" and dns.response_code : "NOERROR"` in the surrounding hour — a resolving sibling with a similar shape is the live C2 candidate; enrich its answer IP.
3. Endpoint pivot: correlate the host's Sysmon process-creation events in the same window to find the querying process (then follow the Windows Process Creation family baseline).
4. False-positive checks: internal search-domain suffixes appended to hostnames; CDN failover probes.
**Escalation:** confirmed burst plus a resolving sibling domain → treat as active C2; promote to the high-severity flow (Tier B isolate of the querying host).

###### 5. Remediation & Evidence Preservation

- Export the full Zeek dns.log slice for the source host before index rollover — the query-name set is the campaign fingerprint.
- If a live C2 domain is identified: perimeter-block the domain and answer IPs, EDR-isolate the host, acquire memory, identify the beaconing process, and hash its binary for VT.
- Endpoint persistence cleanup follows whatever launcher is found (Run key / scheduled task / service).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and source IP.

<a id="net_zeek_dns_doh_non_standard"></a>
##### DNS Lookup for a Known Public DNS-over-HTTPS Provider — Blind to Hardcoded-IP DoH Clients

**Rule file:** `rules/sigma/net_zeek_dns_doh_non_standard.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1572 — Protocol Tunneling |
| Severity (`level`) | low |
| Data source | Zeek dns |
| Trigger condition | Plain DNS query exactly matching one of 9 public DoH resolver hostnames (including Firefox's canary domain `use-application-dns.net`), or a dot-anchored subdomain of one |

Catches only the plaintext lookup phase a client performs before establishing the encrypted DoH channel (or a browser probing DoH availability) — it cannot see the DoH traffic itself, which is opaque HTTPS and never appears in dns.log, and a client using a hardcoded resolver IP skips this lookup entirely and is invisible to this rule. The risk flagged is that DoH bypasses the organization's DNS-based filtering and detection — not that DoH itself is malicious. The rule also matches the observed query, not the response, so an arbitrary emitted label under a real provider domain produces a hit without any real DoH bootstrap.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `query` | rule detection block | Matched DoH provider hostname (or canary domain) |
| `id.orig_h` | event source (Zeek dns.log) | Querying host — where the DoH client runs |
| `id.resp_h` | event source (Zeek dns.log) | Resolver that served the lookup |
| `rcode_name` | event source (Zeek dns.log) | Canary check: NXDOMAIN to `use-application-dns.net` disables Firefox DoH |
| `answers` | event source (Zeek dns.log) | Resolver IPs the DoH channel will connect to next |

###### 3. Enrichment Criteria

- `query` domain → OTX: escalate on any pulse match — a genuine provider hostname should be clean, so a pulse points at lookalike or emission abuse rather than the provider.
- Internal-only: is this an organization-approved DoH provider (allowlist), and does browser fleet policy already enable DoH by default? Check whether the filtering resolver NXDOMAINs the Firefox canary as intended.
- One lookup is adoption signal, not exfiltration — no maliciousness label without a TI verdict or an internal case tying the host to something more.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: triage-only — enrich and queue for analyst review; no automated blocking or host action.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   source.ip : "<orig_h>" and dns.question.name : ("<provider_domain>" or *.<provider_domain>)
   ```
   A fleet sweep on `dns.question.name : "use-application-dns.net"` counts DoH-probing Firefox installs across hosts.
2. Follow-through check: did the host then open sustained encrypted sessions to the resolved provider IPs (pivot `source.ip : "<orig_h>" and destination.ip : "<answer_ip>"`)? A lookup with no follow-on channel is likely a background browser probe. Note the rule's own blind spot: absence of further hits here proves nothing about hardcoded-IP DoH clients.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events to identify the querying application — a stock browser with DoH defaults reads very differently from an unfamiliar binary bootstrapping an encrypted resolver.
4. False-positive checks: organization-approved DoH usage (allowlist the provider rather than treating every hit as an incident); browsers with DoH enabled by default performing routine background lookups; a random-looking subdomain hit is an emission signal only.
**Escalation:** the same host also showing C2-shaped alerts (DGA burst, tunneling, TXT abuse) or a non-browser process establishing the DoH channel → treat as deliberate detection evasion and hand to the IR lead for severity promotion.

###### 5. Remediation & Evidence Preservation

- Export the dns.log slice for the host (lookups plus canary responses) before rollover.
- Enforce the enterprise browser policy for DoH (disable, or standardize on the approved provider); confirm the filtering resolver NXDOMAINs the Firefox canary so compliant browsers self-disable.
- If a non-browser DoH client was found, treat it under the endpoint family baseline — the DoH lookup is then a symptom, not the incident.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and source host.

<a id="net_zeek_dns_tunneling_high_entropy"></a>
##### DNS Query with High-Entropy Long Subdomain Label (Possible Tunneling)

**Rule file:** `rules/sigma/net_zeek_dns_tunneling_high_entropy.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control, Exfiltration |
| Technique(s) | T1071.004 — Application Layer Protocol: DNS |
| Severity (`level`) | medium |
| Data source | Zeek dns |
| Trigger condition | DNS query name containing a run of 50+ contiguous alphanumeric characters in a label |

Detects the shape tunneling tools (iodine, dnscat2, DNSExfiltrator) produce when smuggling base32/base64/hex-encoded data through subdomain labels. Honesty caveat carried from the rule: there is no native entropy function and Zeek's dns.log has no entropy field, so label length is the standard proxy for entropy — a long label is not itself proof of encoding, and the cardinality of unique labels under one parent domain is the analyst's real confirmation signal.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `query` | rule detection block | The long-label query name; its registered (parent) domain is the TI artifact |
| `id.orig_h` | event source (Zeek dns.log) | Querying host — containment target |
| `id.resp_h` | event source (Zeek dns.log) | Resolver used (tunnels ride the recursive path) |
| `qtype_name` | event source (Zeek dns.log) | Tunnel record types (TXT/NULL/CNAME) vs plain A/AAAA |
| `rcode_name` | event source (Zeek dns.log) | Tunnel servers answer; NXDOMAIN runs look more DGA-shaped |
| `answers` | event source (Zeek dns.log) | Return-channel content, when present |

###### 3. Enrichment Criteria

- Registered (parent) domain of `query` → OTX: escalate on any pulse match.
- Internal-only: cardinality confirmation — count distinct long-label queries under the same parent domain from `id.orig_h` over 10-minute windows; a steady stream of unique labels is the tunneling volume signal a single-event rule cannot express.
- Internal-only: allowlist check — is the parent domain a known CDN/cloud-storage service seen repeatedly from legitimate hosts?
- Length alone convicts nothing; pair the cardinality evidence with an OTX pulse or an internal case before labeling the domain.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On an OTX pulse for the parent domain, auto-add it to the DNS/perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   source.ip : "<orig_h>" and dns.question.name : *
   ```
   KQL cannot express the 50-character run — confirm it on the returned `dns.question.name` values (or the raw dns.log slice), then bucket unique long-label names under the same parent domain over 10-minute windows.
2. Channel check: inspect `dns.question.type` and `dns.answers` on the matching events — TXT/NULL/CNAME answers carrying content indicate a bidirectional channel, not just outbound encoding.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events in the window to find the querying process; follow the Windows Process Creation family baseline for it.
4. False-positive checks: some CDN/cloud-storage services (S3 presigned URLs, Akamai, some CDN edge nodes) use long content-hash subdomains — rare on a campus network but worth an allowlist entry if seen repeatedly from the same legitimate service; long DKIM/SPF/verification TXT-adjacent A/AAAA lookups from mail or identity providers.
**Escalation:** sustained unique-label cadence under one parent domain plus a responsible process on the host → active DNS tunnel; promote to the high-severity flow (Tier B isolate of the querying host).

###### 5. Remediation & Evidence Preservation

- Export the full dns.log slice for `id.orig_h` before rollover — for a tunnel, the query-name set IS the smuggled payload; preserve it intact.
- Block the parent domain at the resolver/perimeter; identify and remove the tunnel client and its launcher on the endpoint; hash the binary for VT.
- Assess what data the host could reach during the tunnel's active window — treat a confirmed tunnel as exfiltration until scoped.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and source host.

<a id="net_zeek_dns_txt_answer_abuse"></a>
##### TXT Record Answer with Encoded-Looking Payload (Possible C2 Download Direction)

**Rule file:** `rules/sigma/net_zeek_dns_txt_answer_abuse.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1071.004 — Application Layer Protocol: DNS |
| Severity (`level`) | medium |
| Data source | Zeek dns |
| Trigger condition | DNS event with `qtype_name: TXT` whose answer content contains a run of 40+ base64-charset characters (`[a-zA-Z0-9+/=]`) |

Detects the download half of TXT-based DNS C2 (Cobalt Strike's DNS-TXT channel, Empire, Merlin): payload rides in the answer while the query name stays short and unremarkable, which is why the upload-side sibling `net_zeek_dns_txt_record_abuse` — whose only content selector is the query name — structurally cannot catch this direction. Same length-as-entropy proxy caveat as the query-side rules; the charset here adds `+/=` because answer content is not label-constrained and real TXT-C2 chunks are typically base64. That same property makes DKIM keys — themselves long base64 blobs — a stronger false-positive source here than on the sibling.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `qtype_name` | rule detection block | Confirms the TXT record type |
| `answers` | rule detection block | The encoded-looking payload — both signal and evidence |
| `query` | event source (Zeek dns.log) | Queried name; its registered domain is the TI artifact |
| `id.orig_h` | event source (Zeek dns.log) | Querying host — containment target |
| `id.resp_h` | event source (Zeek dns.log) | Resolver used |
| `rcode_name` | event source (Zeek dns.log) | Response status context |

###### 3. Enrichment Criteria

- Registered domain of `query` → OTX: escalate on any pulse match.
- Internal-only: cadence check — regular, repeated TXT queries to the same domain from `id.orig_h` are the C2 polling shape; a one-off lookup is far more likely mail-infrastructure verification.
- Internal-only: legitimate-shape check — does the queried name follow the DKIM selector convention (`<selector>._domainkey.<domain>`), and is the source a mail server with reason to fetch it?
- A long base64 answer is not a verdict — DKIM keys are exactly that. Cite the OTX pulse or an internal case first.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On an OTX pulse for the queried domain, auto-add it to the DNS/perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   dns.question.type : "TXT" and source.ip : "<orig_h>"
   ```
   KQL cannot express the 40-character base64 run — confirm it on the returned `dns.answers` values (or the raw dns.log slice), and bucket hits by queried domain over time to expose polling cadence.
2. Direction pairing: check the same host against the upload-side sibling (`dns.question.type : "TXT"` hits with long query labels) — both directions active against one domain is a strong bidirectional-channel signal.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events in the window for the querying process; follow the Windows Process Creation family baseline.
4. False-positive checks: DKIM public-key TXT records return a long base64 `p=...` value as the answer itself — a stronger false-positive source here than on the query-side sibling, since the DKIM key IS the long base64 blob; SPF/DMARC includes and domain-verification tokens returned as TXT answer content.
**Escalation:** sustained polling cadence from a non-mail host plus a responsible process → active C2 download channel; promote to the high-severity flow (Tier B isolate of the querying host).

###### 5. Remediation & Evidence Preservation

- Export the dns.log slice with full `answers` content before rollover — the answer payload is the delivered C2 tasking/stage; preserve it verbatim for decoding during analysis.
- Block the domain at the resolver/perimeter; on the endpoint, identify the client process, hash its binary for VT, and remove it plus its launcher.
- Sweep the fleet for other hosts querying the same domain — a TXT-C2 domain is rarely used by only one implant.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and source host.

<a id="net_zeek_dns_txt_record_abuse"></a>
##### TXT Record Query with Encoded-Looking Payload (Possible C2/Exfil Channel)

**Rule file:** `rules/sigma/net_zeek_dns_txt_record_abuse.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control, Exfiltration |
| Technique(s) | T1071.004 — Application Layer Protocol: DNS |
| Severity (`level`) | medium |
| Data source | Zeek dns |
| Trigger condition | DNS query with `qtype_name: TXT` whose query name contains a run of 40+ contiguous alphanumeric characters |

Detects the upload direction of TXT-based DNS C2/exfil: the same encoded-payload shape as `net_zeek_dns_tunneling_high_entropy` but scoped to TXT specifically, the record type most C2 frameworks (Empire, Merlin, some Cobalt Strike DNS profiles) favor because it carries more payload per query. Honesty caveats carried from the rule: length stands proxy for entropy, and this is a per-query structural indicator, not a volume/burst detector — per-source cardinality over a time window cannot be expressed in a single Sigma detection, so the volume half is an analyst step (a threshold companion is a noted future option, deliberately not built).

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `qtype_name` | rule detection block | Confirms the TXT record type |
| `query` | rule detection block | Long-label query name — payload carrier; its registered domain is the TI artifact |
| `id.orig_h` | event source (Zeek dns.log) | Querying host — containment target |
| `id.resp_h` | event source (Zeek dns.log) | Resolver used |
| `rcode_name` | event source (Zeek dns.log) | A consistently answering domain indicates a live server side |
| `answers` | event source (Zeek dns.log) | Non-empty encoded answers = the download direction is active too |

###### 3. Enrichment Criteria

- Registered domain of `query` → OTX: escalate on any pulse match.
- Internal-only: volume confirmation — count distinct long-label TXT queries from `id.orig_h` to the same parent domain over 10-minute windows; a steady stream of unique labels is the exfil/beacon cadence the rule itself cannot measure.
- Internal-only: mail-context check — DKIM/SPF/DMARC lookups explain most legitimate long TXT queries; confirm whether the source and domain fit that picture.
- One structurally suspicious query is a lead, not a finding — the label waits for the OTX verdict or an internal case.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: no automatic host isolation. On an OTX pulse for the parent domain, auto-add it to the DNS/perimeter blocklist and open an analyst ticket.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   dns.question.type : "TXT" and source.ip : "<orig_h>"
   ```
   KQL cannot express the 40-character run — confirm it on the returned `dns.question.name` values (or the raw dns.log slice), then count distinct long-label queries under the same parent domain per 10-minute window.
2. Direction pairing: inspect `dns.answers` on the same events and check the download-side sibling (`net_zeek_dns_txt_answer_abuse`) for the same domain — encoded content in both directions is the full C2 loop.
3. Endpoint pivot: sweep `id.orig_h`'s Sysmon process-creation events in the window for the querying process; follow the Windows Process Creation family baseline.
4. False-positive checks: DKIM/SPF/DMARC TXT lookups for domains with long selector or policy strings; some SaaS domain-verification TXT records use long random tokens.
**Escalation:** confirmed unique-label burst to one parent domain plus a responsible process on the host → active exfil/C2 channel; promote to the high-severity flow (Tier B isolate of the querying host).

###### 5. Remediation & Evidence Preservation

- Export the full dns.log slice for `id.orig_h` before rollover — the ordered query-name set is the exfiltrated payload itself; preserve it intact for reconstruction.
- Block the parent domain at the resolver/perimeter; identify and remove the client tool and its launcher on the endpoint; hash the binary for VT.
- Scope the exfiltration: estimate volume from the label count × label size, and determine what data the host could access in the active window.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash exported logs/screenshots; record the UTC window and source host.

<a id="net_zeek_executable_download"></a>
##### Executable or Script Payload Downloaded Over HTTP (Zeek Files)

**Rule file:** `rules/sigma/net_zeek_executable_download.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1105 — Ingress Tool Transfer |
| Severity (`level`) | low |
| Data source | Zeek files.log |
| Trigger condition | files.log record whose `source` is `HTTP` and whose `mime_type` matches one of ten executable/script types (PE `application/x-dosexec`, ELF, shared-lib/PIE, shell/Python/Perl/Ruby shebang scripts, `@echo off`-style batch, bare `.lnk`, Mach-O) |

Detects executable or script payloads transferred over plain HTTP as classified by Zeek's own content-magic engine. The rule states its own limits: network-layer download detection alone cannot distinguish attacker staging from routine software updates (files.log carries no HTTP hostname — that lives in http.log, joined only by `uid`); archive/container formats (`.zip`/`.iso`) produce no `mime_type` at all, so a wrapped EXE is invisible; `.ps1`/`.vbs`/`.js`/`.wsf` type as `text/plain` and are permanently uncovered; the batch and interpreter entries are shebang/content-anchored and miss common authoring variants. Deliberately `level: low` for those reasons.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `source` | rule detection block | Confirms the carrying protocol is HTTP |
| `mime_type` | rule detection block | Content-derived payload class (Zeek's magic, not the server's declared type) |
| `id.orig_h` | event source (Zeek files.log) | Internal downloading host — containment target |
| `id.resp_h` | event source (Zeek files.log) | Serving host — primary TI artifact |
| `uid` | event source (Zeek files.log) | Join key to http.log for URL/hostname context |
| `filename` | event source (Zeek files.log) | Declared name when the transfer carries one — attacker-controllable, context only |

###### 3. Enrichment Criteria

- Payload SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**. The files.log record itself yields no hash — obtain one if file hashing is enabled on the sensor, or once the payload is retrieved from the endpoint.
- `id.resp_h` (serving IP) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: correlate http.log by `uid` (raw Zeek log) for the URL and server host; check whether the source host is patch-management/provisioning infrastructure (cloud-init, PXE, internal mirrors).
- A matching MIME type alone is not a verdict — label nothing malicious without the VT/AbuseIPDB citation or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: enrich and queue for analyst review; no automated action.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.files" and zeek.source : "HTTP" and mime_type : ("application/x-dosexec" or "application/x-executable" or "application/x-sharedlib" or "text/x-shellscript" or "text/x-python" or "text/x-perl" or "text/x-ruby" or "text/x-msdos-batch" or "application/x-ms-shortcut" or "application/x-mach-o-executable")
   ```
2. Endpoint hand-off: on the `id.orig_h` host, sweep Sysmon process-creation telemetry in the surrounding window for the downloading process (browser, script host, LOLBin) and any child execution of the payload.
3. False-positive checks (from the rule): legitimate software distribution, installers, and update downloads; internal patch-management or deployment traffic; provisioning/configuration-management scripts fetched over plaintext HTTP — the dominant real source of the script-type hits.
**Escalation:** VT ≥ 5 on the payload hash, or evidence the payload executed on the endpoint → promote to Tier B (isolate the downloading host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Retrieve and quarantine the payload from the endpoint; record its SHA-256 before deletion. Export the files.log and correlated http.log slices for the `uid`.
- If confirmed malicious: perimeter-block the serving IP (and URL once identified), remove any persistence the payload installed, and re-image or verify-clean the host per the endpoint findings.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_http_cobalt_strike_beacon"></a>
##### HTTP Request to a Known Default C2 Beacon URI

**Rule file:** `rules/sigma/net_zeek_http_cobalt_strike_beacon.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1071.001 — Application Layer Protocol: Web Protocols |
| Severity (`level`) | low |
| Data source | Zeek http |
| Trigger condition | HTTP `GET` whose `uri` contains one of six stock C2-profile paths: `/pixel.gif`, `/__utm.gif`, `/jquery-3.3.1.min.js`, `/jquery-3.3.2.min.js`, `/en_US/all.js`, `/dpixel` |

Detects GETs to URI paths that several widely-used default (un-customized) C2 profiles for Cobalt Strike and similar frameworks reuse. The rule is explicit about its own weakness: the list is non-exhaustive, any operator who customizes their profile (routine tradecraft) evades it entirely, and several paths are extremely common legitimate filenames (real jQuery CDN releases, the classic Google Analytics `__utm.gif` beacon), so the false-positive:true-positive ratio on real traffic is realistically thousands to one. Treat it as a hunt-query starting point, not a production alert.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `method` | rule detection block | Confirms the request verb (GET) |
| `uri` | rule detection block | The matched stock-profile path |
| `id.orig_h` | event source (Zeek http.log) | Internal requesting host — containment target |
| `id.resp_h` | event source (Zeek http.log) | Destination server — primary TI artifact |
| `host` | event source (Zeek http.log) | Requested HTTP Host header — domain TI artifact |
| `status_code` | event source (Zeek http.log) | Response check the rule's own FP note demands |
| `user_agent` | event source (Zeek http.log) | Stock C2-profile UAs are a supporting (not conclusive) indicator |

###### 3. Enrichment Criteria

- `host` / full URL → OTX; escalate on **any pulse match**.
- `id.resp_h` → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is the destination a known CDN or analytics provider the org legitimately uses? Check proxy/egress baselines and prior case history for the destination.
- The URI match alone proves nothing — these are real, common filenames; no malicious label without the TI citation.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: enrich and queue for analyst review; no automated action.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.http" and http.request.method : "GET" and url.path : (*/pixel.gif* or */__utm.gif* or */jquery-3.3.1.min.js* or */jquery-3.3.2.min.js* or */en_US/all.js* or */dpixel*)
   ```
2. Beacon-cadence check: bucket the source→destination pair over time — repeated identical GETs at a regular interval with near-constant response sizes is the beaconing shape; a single request in browsing context is not.
3. Endpoint hand-off: on the `id.orig_h` host, find the requesting process via Sysmon process-creation telemetry in the same window — a browser fetching a CDN asset and an unknown binary polling `/dpixel` triage very differently.
4. False-positive checks (from the rule): legitimate sites genuinely serving a matching file at that literal path — check the response (`status_code`, response size, destination reputation) before escalating.
**Escalation:** regular-interval repetition plus an OTX pulse or AbuseIPDB ≥ 50% on the destination → treat as active C2; promote to Tier B (isolate the requesting host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the full http.log and conn.log slices for the source→destination pair — the request timing series is the beacon evidence.
- If C2 is confirmed: perimeter-block the destination IP/domain, isolate the host, acquire memory, identify the beaconing process, and hash its binary for VT; remove whatever launcher persists it.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_http_exfil_large_post"></a>
##### Large HTTP POST Request Body

**Rule file:** `rules/sigma/net_zeek_http_exfil_large_post.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Exfiltration |
| Technique(s) | T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol |
| Severity (`level`) | medium |
| Data source | Zeek http |
| Trigger condition | HTTP `POST` with `request_body_len` greater than 5,000,000 bytes (5 MB) |

Detects a single plain-HTTP POST uploading more than 5 MB — a coarse but useful signal for bulk exfiltration of staged/archived data to an attacker-controlled or abused endpoint. The rule is honest that 5 MB is a starting threshold, not a validated baseline for any specific deployment: expect meaningful false positives from legitimate large uploads (backups, media, package repos) until tuned against real traffic.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `method` | rule detection block | Confirms the request verb (POST) |
| `request_body_len` | rule detection block | Upload volume — the exfil-size signal |
| `id.orig_h` | event source (Zeek http.log) | Internal uploading host — containment target |
| `id.resp_h` | event source (Zeek http.log) | Receiving server — primary TI artifact |
| `host` | event source (Zeek http.log) | Destination hostname — domain TI artifact |
| `uri` | event source (Zeek http.log) | Upload endpoint path (API upload routes vs arbitrary paths) |
| `status_code` | event source (Zeek http.log) | Whether the server accepted the upload |

###### 3. Enrichment Criteria

- `host` / destination URL → OTX; escalate on **any pulse match**.
- `id.resp_h` → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is the destination a sanctioned backup/storage/CI endpoint? Check the asset owner of the source host and the change calendar for scheduled data moves.
- Volume alone is ambiguous — do not label the transfer exfiltration without the TI verdict or corroborating staging evidence on the endpoint.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on OTX pulse or AbuseIPDB ≥ 50% for the destination, auto-add it to the perimeter blocklist; no host action without an analyst.
**Analyst triage path:**
1. Verify and scope with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.http" and http.request.method : "POST" and http.request.body.bytes > 5000000
   ```
   Then sum upload bytes per source→destination pair over the last 24 h — repeated large POSTs to one unsanctioned destination outweigh a single hit.
2. Endpoint hand-off: on the `id.orig_h` host, find the uploading process via Sysmon process-creation telemetry, and look backward for archive-staging activity (RAR/7-Zip/compression commands) preceding the POST.
3. False-positive checks (from the rule): legitimate large file uploads — backups, cloud-storage sync clients, CI/CD artifact pushes, video/media uploads, software update mirrors; tune the threshold or allowlist known-legitimate destinations before relying on this in production.
**Escalation:** staging evidence on the endpoint, or repeated large POSTs to a TI-confirmed destination → promote to Tier B (isolate the uploading host), page the IR lead, and open a data-exposure assessment.

###### 5. Remediation & Evidence Preservation

- Export http.log and conn.log byte counts for the pair — the volume series bounds what may have left. On the endpoint, identify what was staged (archive files, recently-read data sets) before any cleanup.
- Block the destination, remove the uploading tool and its persistence, and reset credentials the uploading process had access to if compromise is confirmed.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_port_scan"></a>
##### Network Port or Address Scan Detected (Zeek Notice)

**Rule file:** `rules/sigma/net_zeek_port_scan.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Discovery |
| Technique(s) | T1046 — Network Service Discovery |
| Severity (`level`) | medium |
| Data source | Zeek notice.log |
| Trigger condition | notice.log entry whose `note` is `Scan::Port_Scan`, `Scan::Address_Scan`, or `Scan::Random_Scan` |

Consumes Zeek's own scan-detection notices rather than raw connection events: the sensor's scan policy aggregates connection behavior and emits a notice once a source crosses its distinct-port/distinct-address thresholds, so a single alert already summarizes many probes (e.g. the Port_Scan notice message states the source "probed N+ distinct ports"). The notice only exists where that scan policy is loaded on the sensor.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `note` | rule detection block | Which scan shape fired (port / address / random) |
| `src` | event source (Zeek notice.log) | The scanning host — primary TI artifact and containment target |
| `msg` | event source (Zeek notice.log) | Human summary incl. the threshold crossed |
| `id.orig_h`, `id.resp_h` | event source (Zeek notice.log) | Endpoint pair of the triggering connection, when attached |

###### 3. Enrichment Criteria

- `src` (scanner IP) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is `src` on the authorized vulnerability-scanner / asset-discovery allowlist? Check the change calendar for scheduled scans and prior case history for the host.
- An aggregated notice is Zeek's judgment that scanning occurred, not that it was hostile — do not label the source malicious without the AbuseIPDB verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% for an external `src`, auto-add it to the perimeter blocklist; no host action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.notice" and note : ("Scan::Port_Scan" or "Scan::Address_Scan" or "Scan::Random_Scan")
   ```
2. Scope the scan from conn data: `event.dataset : "zeek.conn" and source.ip : "<src>"` — count distinct `destination.ip` / `destination.port` values in the window to map what was probed, and look for established sessions to previously-probed ports (successful follow-through).
3. Endpoint hand-off: if `src` is an internal host, find the scanning process via its Sysmon process-creation telemetry in the same window (nmap-style tooling, script hosts, or an implant enumerating the network).
4. False-positive checks (from the rule): authorized vulnerability scanners and asset-discovery sweeps; network monitoring and availability checks.
**Escalation:** an internal `src` not on the scanner allowlist, or scan activity followed by established connections/authentication against probed services → promote to Tier B (isolate the scanning host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the notice.log entry and the conn.log slice for `src` — the probed-target set is the scope evidence for anything downstream.
- If an internal scanner is confirmed compromised: isolate, identify and remove the scanning tool/implant, and review the probed services for successful logons or exploitation follow-up.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_smtp_attachment_executable"></a>
##### Executable Payload Sent as an Email Attachment (Zeek Files) — Plaintext SMTP Only

**Rule file:** `rules/sigma/net_zeek_smtp_attachment_executable.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Initial Access |
| Technique(s) | T1566.001 — Phishing: Spearphishing Attachment |
| Severity (`level`) | medium |
| Data source | Zeek files.log |
| Trigger condition | files.log record whose `source` is `SMTP` and whose `mime_type` matches the same ten executable/script types as the HTTP download sibling |

Detects an executable or script MIME type extracted from an SMTP attachment — the classic spearphishing-attachment delivery. Carry the title's own caveat: the sensor can only see attachment bytes in **plaintext SMTP**; any STARTTLS or implicit-TLS session (the default for submission on 587/465 on essentially every modern client and provider) is entirely opaque, so practical coverage is unencrypted MTA-to-MTA relay on port 25, not general inbound phishing. `mime_type` is content-derived (Zeek's own magic, not the declared Content-Type); a payload matching none of Zeek's narrow signatures — archives/containers, `.ps1`/`.vbs`/`.js`/`.wsf` — produces no `mime_type` at all and can never fire this rule.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `source` | rule detection block | Confirms the carrying protocol is SMTP |
| `mime_type` | rule detection block | Content-derived payload class of the attachment |
| `filename` | event source (Zeek files.log) | MIME-declared name — fully attacker-controlled (double/spoofed extensions); context only, never a type signal |
| `id.orig_h`, `id.resp_h` | event source (Zeek files.log) | Sending and receiving MTA/host pair |
| `uid` | event source (Zeek files.log) | Join key to smtp.log for sender/subject/recipients |

###### 3. Enrichment Criteria

- Attachment SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**. The event yields no hash field — obtain one if file hashing is enabled on the sensor, or once the message is retrieved from the mail store.
- Sending IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: correlate smtp.log by `uid` (raw Zeek log) for sender, subject, and recipient set — files.log does not carry them; then sweep the mail store for other copies of the same message.
- The MIME type proves an executable was mailed, not that it is malicious — no verdict without the VT/AbuseIPDB citation or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% (or VT ≥ 5 on the attachment hash), auto-block the sending IP at the mail perimeter; message and host actions stay with the analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.files" and zeek.source : "SMTP" and mime_type : ("application/x-dosexec" or "application/x-executable" or "application/x-sharedlib" or "text/x-shellscript" or "text/x-python" or "text/x-perl" or "text/x-ruby" or "text/x-msdos-batch" or "application/x-ms-shortcut" or "application/x-mach-o-executable")
   ```
2. Recipient sweep: identify every mailbox that received the message (smtp.log recipients, mail-store search), then endpoint hand-off — on each recipient's host, sweep Sysmon process-creation telemetry for execution of the attachment (mail client or archive tool spawning the payload).
3. False-positive checks (from the rule): legitimate IT-distributed software, scripts, or installers sent by email — and note the rule's own calibration warning that a developer or vendor emailing a `.py`/`.rb`/`.pl` script attachment is genuinely common, not a rare edge case.
**Escalation:** VT ≥ 5 on the attachment, or any evidence of execution on a recipient host → promote to Tier B (isolate the affected endpoint), page the IR lead, and treat it as an active phishing incident.

###### 5. Remediation & Evidence Preservation

- Quarantine/pull the message from all recipient mailboxes; preserve one copy with full headers, and hash the attachment before removal.
- Block the sending infrastructure at the mail gateway; notify recipients; if executed, run the endpoint IR path (process tree, persistence removal, credential exposure review) on each affected host.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_smtp_mass_outbound"></a>
##### SMTP Session with an Anomalously Deep Transaction Count — Plaintext SMTP Only

**Rule file:** `rules/sigma/net_zeek_smtp_mass_outbound.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1071.003 — Application Layer Protocol: Mail Protocols |
| Severity (`level`) | medium |
| Data source | Zeek smtp |
| Trigger condition | smtp.log record with `trans_depth` greater than 20 — one SMTP session pipelining 20+ sequential MAIL FROM/RCPT TO/DATA cycles |

A normal end-user client sends one message per session, occasionally a handful; a single connection sustaining dozens is the shape of mass-mailing malware or spam-relay abuse. The rule is explicit about its limits: `trans_depth` is a proxy for "many messages from one host", not a literal recipient count; Zeek writes one smtp.log line per transaction, so one over-threshold session produces roughly (`trans_depth` − 20) separate alerts, not one; the logic has no directionality check despite the filename; and — carry the title's caveat — it is blind to any STARTTLS/implicit-TLS session, making its real-world coverage plaintext port-25 relay abuse, not general mass-mail detection.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `trans_depth` | rule detection block | Transaction depth — how far past the threshold the session ran |
| `id.orig_h` | event source (Zeek smtp.log) | Session originator — containment target if internal |
| `id.resp_h` | event source (Zeek smtp.log) | Peer MTA — TI artifact |
| `mailfrom`, `rcptto` | event source (Zeek smtp.log) | Claimed sender and recipient set per transaction |
| `subject` | event source (Zeek smtp.log) | Campaign clustering across the session's messages |

###### 3. Enrichment Criteria

- Peer IP (`id.resp_h`, or `id.orig_h` when the deep session is inbound) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: is the originating host on the known mail-relay/mailing-list inventory? Compare against the host's own historical `trans_depth` baseline and check the change calendar for bulk-notification jobs.
- Deep pipelining by an authorized relay is normal operation — no malicious label without the AbuseIPDB verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% for the external peer, auto-add it to the perimeter blocklist; no host action without an analyst. Expect the per-transaction alert fan-out noted above — dedupe to one case per session.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.smtp" and trans_depth > 20
   ```
   Bucket by `source.ip` to see which host is driving depth and whether it recurs across sessions.
2. Read the session's `mailfrom`/`rcptto`/`subject` series in the raw smtp.log — one sender fanning to many external recipients with templated subjects is the mass-mail shape; a relay forwarding varied legitimate mail is not.
3. Endpoint hand-off: if the originator is an internal non-relay host, find the mailing process via its Sysmon process-creation telemetry (mass-mailer malware, script host, or an unexpected service talking SMTP).
4. False-positive checks (from the rule): a legitimate internal mail relay, mailing-list server, or bulk-notification system (registrar, LMS, alumni newsletter) pipelining many messages through one authorized connection — allowlist known relay hosts by source IP.
**Escalation:** an internal non-relay host sustaining deep sessions, or message content confirming spam/malware distribution → promote to Tier B (isolate the originating host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the full smtp.log slice for the session(s) — sender/recipient/subject series is the campaign evidence; capture conn.log for session timing and volume.
- If an internal host is confirmed abused: isolate it, remove the mailing tool and its persistence, review how it was compromised, and notify the mail team to assess blocklist/reputation damage to the org's sending domains.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_ssh_bruteforce"></a>
##### SSH Password Guessing / Brute Force (Zeek Notice)

**Rule file:** `rules/sigma/net_zeek_ssh_bruteforce.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110 — Brute Force |
| Severity (`level`) | high |
| Data source | Zeek notice.log |
| Trigger condition | notice.log entry whose `note` is `SSH::Password_Guessing` or `SSH::Login_By_Password_Guesser` |

Consumes the aggregated notices of Zeek's SSH brute-force detection policy: `SSH::Password_Guessing` fires once a single source accumulates 30 failed authentications within 30 minutes (the policy's defaults), and `SSH::Login_By_Password_Guesser` fires when a source already flagged as guessing subsequently logs in successfully — the second notice is a probable-compromise signal, not just an attempt. The notices only exist where that policy is loaded on the sensor; sub-threshold cadences are covered by the two session-cadence companions in this playbook.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `note` | rule detection block | Guessing in progress vs guesser subsequently logged in |
| `src` | event source (Zeek notice.log) | The guessing source — primary TI artifact |
| `msg` | event source (Zeek notice.log) | Human summary incl. the connection count observed |

###### 3. Enrichment Criteria

- `src` (guessing IP) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: identify the targeted host(s) and their criticality from conn/ssh data; check whether `src` is a known automation host with stale credentials (the rule's own leading FP class).
- The Password_Guessing notice is an aggregate of failures, not proof of hostility — cite the AbuseIPDB verdict or an internal case before labeling; a Login_By_Password_Guesser notice, however, is itself the cited evidence of a successful login by a flagged guesser.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: on AbuseIPDB ≥ 50%, auto EDR-isolate `src` when it is an internal host; for an external `src` the automated action is the perimeter block of the confirmed IP, with account actions on analyst confirm. Without a TI hit: Tier D with the 15-minute analyst SLA, Tier B on analyst confirm.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.notice" and note : ("SSH::Password_Guessing" or "SSH::Login_By_Password_Guesser")
   ```
   Then scope the sessions: `event.dataset : "zeek.ssh" and source.ip : "<src>"` — target spread (one host = brute force; many = credential sweep).
2. On the targeted host(s), confirm the attempt/outcome series in its own auth telemetry (Linux auth.log or Windows Security logons) — which accounts were tried, and did any succeed.
3. Endpoint hand-off: if `src` is internal, find the guessing process on it via Sysmon process-creation telemetry (hydra-style tooling, scripted ssh loops, or an implant).
4. False-positive checks (from the rule): misconfigured clients or automation retrying stale credentials; users repeatedly mistyping passwords.
**Escalation:** any `SSH::Login_By_Password_Guesser` notice, or a successful authentication from `src` found on a target → treat the target as compromised: page the IR lead, force-reset the account(s) involved, and promote containment of the target host.

###### 5. Remediation & Evidence Preservation

- Export notice.log plus the ssh.log/conn.log slices for `src` and the auth-log window from each target — the failure/success series is the incident timeline.
- On confirmed success: reset the guessed credential, revoke the account's sessions/keys, review the target for post-login activity and persistence (new authorized_keys, cron, services), and block `src` at the perimeter.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_ssh_session_cadence"></a>
##### SSH Session Cadence — Complementary Brute-Force Coverage Below detect-bruteforcing's Threshold

**Rule file:** `rules/sigma/net_zeek_ssh_session_cadence.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110 — Brute Force |
| Severity (`level`) | medium |
| Data source | Zeek ssh |
| Trigger condition | any ssh.log session record whose `client` version banner starts with `SSH-` — effectively every fully-parsed SSH session; the alerting count lives in the threshold companion, not this per-event match |

The Sigma file is the logic-of-record; the deployed alert is its Elastic threshold companion `rules/elastic/threshold/net-zeek-ssh-session-cadence.ndjson`, which fires when one `source.ip` establishes **≥ 5 SSH sessions within a 10-minute lookback** (evaluated every 5 minutes). That closes the recall gap below the sensor's 30-failures-in-30-minutes notice threshold — but the rule's own honest framing applies: 5-in-10 is the same ~1 session/minute steady-state rate, so its value is burst detection latency (fires in ~5–6 minutes) and independence from the unreliable `auth_success` field (live-verified entirely absent, not false, on failed-auth records), not a lower rate floor. The genuinely slower attacker is the sustained companion's job (next section). Known limitation: `client` is optional in Zeek's schema — sessions whose banner the sensor never saw (lossy vantage, mid-stream capture) are silently uncounted.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `client` | rule detection block | Client version banner — proves a real parsed SSH handshake; tool fingerprint (library banners vs OpenSSH) |
| `id.orig_h` | event source (Zeek ssh.log) | The counted source — containment target |
| `id.resp_h` | event source (Zeek ssh.log) | Target host per session — spread analysis |
| `auth_attempts` | event source (Zeek ssh.log) | Attempts within each session |
| `auth_success` | event source (Zeek ssh.log) | Unreliable by design here — absent (not false) on failed-auth records; never treat absence as failure proof |
| `server` | event source (Zeek ssh.log) | Server banner — which service was targeted |

###### 3. Enrichment Criteria

- Source IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: check the source against the admin/automation inventory (Ansible, deployment scripts, health checks), the bastion/jump-host list, and the operator's own workstation — the rule names these as its likeliest benign sources.
- Session cadence is behavior, not verdict — no malicious label without the AbuseIPDB citation or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50%, auto-block the source IP at the perimeter; no host action without an analyst.
**Analyst triage path:**
1. Verify the burst with KQL (index `logstash-*`; this is the companion's own counting query):
   ```
   event.dataset : "zeek.ssh" and client : SSH-* and source.ip : "<orig_h>"
   ```
   Count sessions per 10-minute bucket against the companion's ≥ 5 threshold; check the 30-minute view too (the sustained companion's window).
2. Target-spread pivot: distinct `destination.ip` values — one target repeatedly is brute-force shape; many targets in sequence is a sweep or lateral movement.
3. On the target(s), confirm outcomes in their own auth telemetry (auth.log / Windows Security) — Zeek's `auth_success` cannot be trusted for this. Endpoint hand-off: if the source is internal, find the connecting process via its Sysmon process-creation telemetry.
4. False-positive checks (from the rule): admin or automation tools making several sequential connections; a jump host/bastion proxying multiple real users; the operator's own workstation during interactive mesh/OpenWrt admin work — flagged by the rule as the most likely first real firing.
**Escalation:** a successful authentication on a target following the burst, or cadence continuing past triage from an unrecognized source → promote to Tier B (isolate an internal source, or lock down the targeted accounts) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the ssh.log slice for the source across the full window plus each target's auth-log excerpt — the cadence series plus outcomes is the case evidence.
- On confirmed brute force: block the source, force-reset any account with a post-burst success, review targets for persistence (authorized_keys additions), and rate-limit/key-only the exposed SSH services where feasible.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_ssh_session_cadence_sustained"></a>
##### Sustained Low-and-Slow SSH Session Cadence — Below detect-bruteforcing AND net_zeek_ssh_session_cadence's Own Rate Floor

**Rule file:** `rules/sigma/net_zeek_ssh_session_cadence_sustained.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110 — Brute Force |
| Severity (`level`) | medium |
| Data source | Zeek ssh |
| Trigger condition | identical detection block to the previous section — any ssh.log record whose `client` banner starts with `SSH-`; the two rules differ only in their threshold companions |

The deployed alert is `rules/elastic/threshold/net-zeek-ssh-session-cadence-sustained.ndjson`: **≥ 15 SSH sessions from one `source.ip` within a 30-minute lookback** (evaluated every 5 minutes) — roughly 0.5 sessions/minute, genuinely below both the sensor's notice threshold (~1/minute) and the 5-in-10 companion (the same ~1/minute rate). It closes the concrete evasion the shorter rule documented: one connection every 2 minutes = 15 sessions/30 min, previously invisible everywhere — at OpenSSH's default 6 tries per connection, up to ~180 guesses/hour with zero signal. Honest framing carried from the rule: this moves the rate floor, it does not close the problem — ~14 sessions/31 minutes (~162 guesses/hour) still evades it, and no per-source threshold at any value catches a distributed attack where many sources each stay under it. The `client`-optional undercounting limitation is inherited from the sibling.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `client` | rule detection block | Client banner — parsed-handshake proof and tool fingerprint |
| `id.orig_h` | event source (Zeek ssh.log) | The counted source — containment target |
| `id.resp_h` | event source (Zeek ssh.log) | Target host per session — spread analysis |
| `auth_attempts` | event source (Zeek ssh.log) | Per-session attempt count — multiplies the guess-rate estimate |
| `auth_success` | event source (Zeek ssh.log) | Same unreliability as the sibling — absent on failed-auth records |

###### 3. Enrichment Criteria

- Source IP → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: the 30-minute window makes routine configuration-management sweeps and monitoring the likeliest benign match — check the automation inventory, bastion list, and specifically whether the source is the SOC's own broker host, whose containment dispatcher legitimately opens SSH sessions to every router in a tenant's inventory (deliberately not excluded at the query level).
- No malicious label without the AbuseIPDB citation or an internal case ID — a slow cadence is exactly the pattern where patience beats assumption.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50%, auto-block the source IP at the perimeter; no host action without an analyst.
**Analyst triage path:**
1. Verify the sustained pattern with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.ssh" and client : SSH-* and source.ip : "<orig_h>"
   ```
   Count sessions per 30-minute bucket against the companion's ≥ 15 threshold, then extend the lookback hours backward — a low-and-slow campaign's distinguishing evidence is persistence across many windows.
2. Compare the inter-session interval: near-constant spacing (e.g. one connection every ~2 minutes for hours) is automation, benign or hostile; ragged human-shaped timing points at interactive admin work.
3. On the target(s), pull the auth outcome series from their own auth telemetry. Endpoint hand-off: for an internal source, find the connecting process via its Sysmon process-creation telemetry — a cron-driven guessing loop and an Ansible run look identical on the wire but not on the endpoint.
4. False-positive checks (from the rule): admin/automation over a longer window (configuration-management sweeps, health checks); a bastion proxying users over an extended period; the operator's own long admin session; the SOC broker's containment dispatch fan-out.
**Escalation:** metronomic cadence from an unrecognized source sustained across multiple windows, or any target-side authentication success → promote to Tier B (isolate/block the source, lock down targeted accounts) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the full multi-hour ssh.log series for the source — the interval pattern is the primary evidence and disappears at rollover; pair it with each target's auth-log excerpt.
- On confirmation: block the source, reset any credential with a post-campaign success, audit targets for persistence, and consider fail2ban/key-only enforcement on the targeted services; if the source was the compromised broker host, treat it under the SOC-infrastructure compromise path, not as an FP.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_ssl_expired_cert_connection"></a>
##### TLS Connection with Expired Certificate

**Rule file:** `rules/sigma/net_zeek_ssl_expired_cert_connection.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1071.001 — Application Layer Protocol: Web Protocols |
| Severity (`level`) | low |
| Data source | Zeek ssl |
| Trigger condition | ssl.log record whose `validation_status` contains `certificate has expired` |

Detects a TLS connection whose certificate chain failed validation as expired — a weak but real signal for abandoned/unmaintained infrastructure being reused as C2 or exfil infrastructure, and for stale internal services worth a hygiene flag regardless of intent. The `validation_status` string comes from the sensor's certificate-validation policy (which must be loaded for the field to exist at all); the exact wording is OpenSSL's own expired-certificate verdict, confirmed against Zeek's source rather than guessed.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `validation_status` | rule detection block | The validation failure — confirms "expired", not another chain error |
| `id.orig_h` | event source (Zeek ssl.log) | Internal connecting host — containment target |
| `id.resp_h` | event source (Zeek ssl.log) | TLS server — primary TI artifact |
| `server_name` | event source (Zeek ssl.log) | SNI the client requested — names the service |
| `version` | event source (Zeek ssl.log) | TLS version — dated stacks corroborate abandoned infrastructure |

###### 3. Enrichment Criteria

- `id.resp_h` (destination IP) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: if the destination is an internal service, route to a certificate-hygiene ticket (owner lookup, renewal), not an incident; if external, check egress baselines — is this destination new for the org?
- An expired certificate is negligence until proven otherwise — no C2 label without the AbuseIPDB verdict or corroborating beacon evidence with a case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: enrich and queue for analyst review; no automated action.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.ssl" and tls.validation_status : *certificate has expired*
   ```
2. Recurrence pivot: `source.ip : "<orig_h>" and destination.ip : "<resp_h>"` over the last 24 h — regular-interval reconnects to one expired-cert endpoint is beacon shape; a one-off browse is not. Certificate subject/issuer details are confirmed in the raw Zeek ssl.log.
3. Endpoint hand-off: on the internal source host, find the connecting process via its Sysmon process-creation telemetry — a browser hitting a stale intranet page and an unknown binary reconnecting on a timer resolve very differently.
4. False-positive check (from the rule): legitimate internal services with lapsed certificate renewal — common enough on campus networks to warrant a hygiene ticket rather than a security incident on first sight; correlate with the destination before escalating.
**Escalation:** external destination with AbuseIPDB ≥ 50% plus a regular reconnect cadence → treat as suspected C2; promote to Tier B (isolate the connecting host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the ssl.log and conn.log slices for the source→destination pair — the reconnect timing series and certificate details are the evidence.
- Suspected C2: perimeter-block the destination, isolate the host, identify and remove the connecting binary and its persistence. Internal hygiene: open a renewal ticket with the service owner and track to closure.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="net_zeek_ssl_self_signed_c2"></a>
##### TLS Connection with Self-Signed Certificate (Possible C2)

**Rule file:** `rules/sigma/net_zeek_ssl_self_signed_c2.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Command and Control |
| Technique(s) | T1573.002 — Encrypted Channel: Asymmetric Cryptography |
| Severity (`level`) | low |
| Data source | Zeek ssl |
| Trigger condition | ssl.log record whose `validation_status` contains `self signed` or `self-signed` (both OpenSSL wordings — the phrasing changed across OpenSSL major versions) |

Detects a TLS connection presenting a self-signed certificate. Many C2 frameworks — default Cobalt Strike, Metasploit, Sliver, Mythic — generate self-signed certificates for their HTTPS listeners rather than obtaining a CA-signed one. Like its expired-cert sibling, the `validation_status` field only exists when the sensor's certificate-validation policy is loaded; the rule matches both historical and current OpenSSL wordings precisely so a wording drift cannot silently disable it.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `validation_status` | rule detection block | Confirms the self-signed verdict specifically |
| `id.orig_h` | event source (Zeek ssl.log) | Internal connecting host — containment target |
| `id.resp_h` | event source (Zeek ssl.log) | TLS server — primary TI artifact |
| `server_name` | event source (Zeek ssl.log) | SNI — default C2 listeners often present none or a placeholder |
| `version`, `cipher` | event source (Zeek ssl.log) | TLS stack fingerprint context |

###### 3. Enrichment Criteria

- `id.resp_h` (destination IP) → AbuseIPDB; escalate at **≥ 50% confidence**.
- Internal-only: check the destination against the known internal self-signed inventory (IoT, printers, captive portals, lab/dev) and baseline volume — the rule expects meaningful volume on most networks and directs baselining/allowlisting by destination.
- Self-signed is normal for a large class of internal devices — no C2 label without the AbuseIPDB verdict or beacon-cadence corroboration recorded in a case.

###### 4. Containment Decision Flow

**Auto-containment:** severity low → Tier D: enrich and queue for analyst review; no automated action.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`):
   ```
   event.dataset : "zeek.ssl" and tls.validation_status : (*self signed* or *self-signed*)
   ```
2. Sort hits by destination novelty: an internal printer seen daily is baseline; a first-seen external `id.resp_h` on a non-standard port is the interesting residue. For that residue, run the reconnect-cadence check on the source→destination pair and read the certificate subject/issuer in the raw Zeek ssl.log (default C2 listener certs are often distinctive or empty).
3. Endpoint hand-off: on the internal source host, identify the connecting process via its Sysmon process-creation telemetry — the self-signed signal only becomes an incident when the client process is unexplained.
4. False-positive checks (from the rule): internal services, IoT devices, printers, captive portals, and lab/dev environments routinely use self-signed certificates — baseline and allowlist known internal self-signed endpoints by destination.
**Escalation:** first-seen external destination with AbuseIPDB ≥ 50%, or regular-interval reconnects from an unexplained process → treat as suspected C2; promote to Tier B (isolate the connecting host) and page the IR lead.

###### 5. Remediation & Evidence Preservation

- Export the ssl.log/conn.log slices for the pair, including certificate details from the raw log — the cert fingerprint identifies sibling C2 infrastructure if reused.
- Suspected C2 confirmed: perimeter-block the destination, isolate the host, capture memory before killing the beaconing process, hash its binary for VT, and remove its persistence. Benign device: add it to the self-signed baseline so it stops resurfacing.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### Linux Authentication (auth.log) — 5 rules

<a id="auth_linux_invalid_user_ssh_attempt"></a>
##### SSH Login Attempt for a Nonexistent User

**Rule file:** `rules/sigma/auth_linux_invalid_user_ssh_attempt.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Credential Access |
| Technique(s) | T1110.001 — Brute Force: Password Guessing |
| Severity (`level`) | medium |
| Data source | Filebeat (Linux auth.log) |
| Trigger condition | A Linux auth event (`event.module: system`) whose `message` contains both the tokens `invalid` and `user` — OpenSSH's rejection lines for an authentication attempt against a username that does not exist on the host |

Detects SSH authentication attempts against nonexistent accounts — the bulk of real-world SSH brute-force and credential-stuffing traffic (attackers guessing usernames, not just passwords for known accounts). Operational caveat the rule states itself: one attack burst writes several matching auth.log lines per attempt (the standalone "Invalid user" line plus paired failure/close lines), so expect multiple alerts per attempt; the rule is held at experimental pending a paired per-source threshold companion.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `event.module` | rule detection block | Scopes to the Linux auth pipeline (`system`) |
| `message` | rule detection block | The raw rejection line — carries the attempted username and the client IP |
| `user.name`, `source.ip`, `event.outcome` | event source (parsed SSH auth lines) | Populated on the companion "Failed password for invalid user …" lines; the standalone "Invalid user …" line carries the username and client IP only inside `message` |
| `source.geo.country_name` | event source (external client IPs) | Geographic context for the attacking source |
| `host.name` | event source | Target host of the attempts |
| `@timestamp` | event source | Timeline anchor for burst measurement |

###### 3. Enrichment Criteria

- SSH client source IP (from `source.ip` on companion lines, or parsed from `message` on the standalone line) → AbuseIPDB; escalate at **≥ 50% confidence score**.
- Internal-only checks: is the attempted username a stale/mistyped service or automation account (asset inventory, prior case history)? Is this host intentionally SSH-exposed?
- A guessed-username attempt is expected Internet noise on any exposed host — label the source malicious only with the citing AbuseIPDB verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity medium → Tier C: on AbuseIPDB ≥ 50% for the source IP, auto-add that IP to the perimeter blocklist; no host or account action without an analyst.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; Linux auth fields are already ECS):
   ```
   event.module : "system" and message : "invalid" and message : "user"
   ```
2. Burst/cardinality check: over the surrounding hour, count distinct attempted usernames and distinct source IPs (pivot on the companion failure lines' `source.ip` / `user.name`); many usernames from one source is the meaningful brute-force signal.
3. Then sweep the same source for any `event.outcome : "success"` login — an accepted login from a source that was guessing usernames changes the incident class entirely.
4. False-positive check: a misconfigured monitoring/automation account or client retrying a stale/mistyped username — usually low-volume and self-correcting.
**Escalation:** sustained high-volume hits against many distinct usernames from one source, or any subsequent successful login from that source IP → open an intrusion case and move to the account-compromise flow for the accepted account.

###### 5. Remediation & Evidence Preservation

- Export the auth.log slice for the host and UTC window (all lines from the source IP, not just rule matches) — the username list is the campaign fingerprint.
- Confirm no successful authentication followed from the same source; if one did, treat that account as compromised (reset credentials, review its session activity).
- Review the host's SSH exposure: confirm Internet-facing SSH is intended and perimeter/rate-limit posture matches policy; keep the TI-confirmed source blocked.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_linux_ssh_authorized_keys_change"></a>
##### Reference to authorized_keys in Linux Auth Log

**Rule file:** `rules/sigma/auth_linux_ssh_authorized_keys_change.yml` · **Status:** experimental · **Severity:** medium

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1098.004 — Account Manipulation: SSH Authorized Keys |
| Severity (`level`) | medium |
| Data source | Filebeat (Linux auth.log) |
| Trigger condition | A Linux auth event (`event.module: system`) whose `message` mentions `authorized_keys` — most commonly a logged privileged command (e.g. `sudo vim ~/.ssh/authorized_keys`) touching the file |

Detects auth.log references to `authorized_keys` — SSH public-key persistence works by adding an attacker's key to a user's `~/.ssh/authorized_keys`. Honesty caveat carried from the rule: this only catches edits made through a mechanism that gets logged to auth.log (sudo, or any other command auth.log records). A process running as the account's own UID writing directly to its own authorized_keys file produces no auth.log entry and is invisible to this rule — that requires file-integrity monitoring the repo does not currently collect. Treat this as a narrow, best-effort signal, not authorized_keys change detection in general.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `event.module` | rule detection block | Scopes to the Linux auth pipeline (`system`) |
| `message` | rule detection block | The full logged line — for sudo-mediated edits it carries the invoking account, TTY, and the exact `COMMAND=` that touched the file |
| `host.name` | event source | Host whose authorized_keys file was referenced |
| `@timestamp` | event source | Change time — the anchor for the change-calendar check |

###### 3. Enrichment Criteria

- Internal-only artifact class: no external TI artifact on this event.
- Internal-only checks: change-management records for a scheduled key rotation or config push; the invoking account (parsed from `message`) against the host's admin baseline; prior case history for the account and host.
- If the log line alone cannot establish what was written to the file, say so in the case notes — the file's content is the evidence, not the mention of it.

###### 4. Containment Decision Flow

**Auto-containment:** none — Internal-only artifact class, severity medium with no TI-confirmable artifact → Tier D: enrich and queue for analyst review.
**Analyst triage path:**
1. Verify with KQL (index `logstash-*`; Linux auth fields are already ECS):
   ```
   event.module : "system" and message : "authorized_keys"
   ```
2. Identity sweep: parse the invoking account from `message`; pull that account's auth activity ±24 h on the host (logins, su/sudo events) to establish whether the session that made the edit was itself ordinary.
3. Inspect the actual file on the host: compare the current key set against the known-good baseline or backup — the alert cannot tell you what changed, only that the file was touched.
4. False-positive check: legitimate key-management automation (Ansible/Puppet/Chef pushing SSH keys, a user rotating their own key via a logged sudo command) — expect routine hits in any environment that manages authorized_keys this way; correlate with change-management records before escalating.
**Escalation:** a key present in the file that no change record or owner accounts for → treat as confirmed persistence; open an incident and move to the identity-compromise flow for the key's account.

###### 5. Remediation & Evidence Preservation

- Collect and SHA-256 hash the affected `authorized_keys` file before editing it; record file mtime and owner.
- Remove the unauthorized key; force a credential review for the account (password reset, audit of the account's other keys and active sessions).
- Because same-UID direct writes are invisible to this rule, sweep authorized_keys files fleet-wide (content diff or mtime review) rather than trusting the absence of further alerts.
- Hunt logins that used the rogue key (subsequent SSH accepts for the account) and treat those sessions' activity as attacker activity.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_linux_ssh_root_login"></a>
##### Direct Root Login via SSH

**Rule file:** `rules/sigma/auth_linux_ssh_root_login.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Initial Access, Persistence |
| Technique(s) | T1078.003 — Valid Accounts: Local Accounts |
| Severity (`level`) | high |
| Data source | Filebeat (Linux auth.log) |
| Trigger condition | A Linux auth event with `user.name: root` and `event.outcome: success` — an accepted SSH login directly as root |

Detects a successful SSH login directly as root. Most security baselines disable direct root SSH access (`PermitRootLogin no`) and require login as an unprivileged user followed by sudo/su, so a direct root session is either a misconfigured host or a credential compromise bypassing that control entirely.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `event.module` | rule detection block | Scopes to the Linux auth pipeline (`system`) |
| `user.name` | rule detection block | Fixed at `root` — the identity at stake |
| `event.outcome` | rule detection block | `success` — an accepted login, not an attempt |
| `source.ip`, `source.port` | event source (parsed SSH auth lines) | Client address — the primary TI artifact and pivot key |
| `system.auth.method` | event source | Auth method (`password` vs `publickey`) — a password root login is a materially worse signal than a managed appliance's key |
| `source.geo.country_name` | event source (external client IPs) | Geographic context for the client address |
| `host.name` | event source | The host now holding a live root session |

###### 3. Enrichment Criteria

- `source.ip` → AbuseIPDB; escalate at **≥ 50% confidence score**.
- Internal-only checks: asset inventory for a documented appliance/legacy allowlist entry permitting root SSH on this host; change calendar for sanctioned emergency access; whether the source IP is a known admin workstation or jump host.
- An internal source IP is not exonerating on its own — cite the allowlist entry or change record, or keep the case open.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B (identity): on AbuseIPDB ≥ 50% for the SSH source IP, automated account-centric containment — terminate the active root session and disable further root SSH logins; page the IR lead.
**Analyst triage path** (no TI confirmation) — 15-minute SLA; Tier B (identity) on analyst confirm:
1. Verify with KQL (index `logstash-*`; Linux auth fields are already ECS):
   ```
   event.module : "system" and user.name : "root" and event.outcome : "success"
   ```
2. Identity sweep: pivot on `source.ip` — other logins (any account, any host) from the same client address ±24 h; then pull the host's auth.log around the event for what the root session did next (su/sudo lines, session close).
3. False-positive check: an intentionally configured host/appliance that permits direct root SSH login (uncommon, but occurs on some legacy or vendor-managed systems) — allowlist the specific host rather than excluding root logins broadly.
**Escalation:** source IP TI-confirmed, external, or unknown to the asset inventory, or root activity following the login that no change record explains → page the IR lead and treat the root credential (password or key) as compromised.

###### 5. Remediation & Evidence Preservation

- Capture the host's auth.log slice and root's shell history before any cleanup; record active sessions (`who`/`last`) and terminate the attacker session.
- Rotate the root credential used: password reset and/or removal of the SSH key that authenticated; audit `/root/.ssh/authorized_keys` for attacker-added keys.
- Set `PermitRootLogin no` (or the documented appliance-appropriate restriction) unless the host is explicitly allowlisted; verify the config change took effect.
- Hunt lateral movement: authentications from this host to others during and after the root session window.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_linux_su_session_opened"></a>
##### su Session Opened

**Rule file:** `rules/sigma/auth_linux_su_session_opened.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation |
| Technique(s) | T1078.003 — Valid Accounts: Local Accounts |
| Severity (`level`) | low |
| Data source | Filebeat (Linux auth.log) |
| Trigger condition | A Linux auth event (`event.module: system`) whose `message` contains all three tokens `su`, `session`, and `opened` — PAM's session-open line for an `su` identity switch (the `su` token separates these from sshd's identically worded session-open lines for ordinary SSH logins) |

Detects a `su` session being opened, per PAM's own logging ("session opened for user <target> by <source>"). A user switching identity via `su` (as opposed to running a single command via `sudo`) opens a persistent shell under the target account — worth the same visibility as sudo usage. This is a visibility-tier rule: the alert is a context question, not an incident.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `event.module` | rule detection block | Scopes to the Linux auth pipeline (`system`) |
| `message` | rule detection block | The PAM line — carries both the target account ("for user <target>") and the source account ("by <source>") |
| `host.name` | event source | Host where the identity switch happened |
| `@timestamp` | event source | Session-open time — anchor for correlating the source account's login |

###### 3. Enrichment Criteria

- Internal-only artifact class: no external TI artifact on this event.
- Internal-only checks: is su-to-<target> part of the source account's normal admin pattern on this host (baseline, prior case history)? Does a change-calendar entry cover the session window?
- The PAM line proves the switch happened, not why — do not record intent without corroborating session context.

###### 4. Containment Decision Flow

**Auto-containment:** none — severity low, Internal-only → Tier D: enrich and queue for analyst review; no automation.
**Analyst triage path** (context checks, not containment):
1. Verify with KQL (index `logstash-*`; Linux auth fields are already ECS):
   ```
   event.module : "system" and message : "su" and message : "session" and message : "opened"
   ```
2. Identity context: parse source and target accounts from `message`; find the source account's originating login (SSH accept line, its `source.ip`) — an su-to-root from a session that began as an anomalous remote login is a different event than a local admin's routine switch.
3. Baseline check: is this source→target pair seen regularly on this host? Baseline expected accounts before escalating every hit.
4. False-positive check: routine, legitimate use of `su` for administrative tasks — expect regular volume on any host where staff use `su` rather than `sudo -s`.
**Escalation:** su to root (or a service account) by an account outside the host's admin baseline, or a source session originating from an unexpected remote address → open a case and move to the identity-compromise flow for the source account.

###### 5. Remediation & Evidence Preservation

- For an escalated case: export the auth.log window covering the source account's login through session close, and capture the target account's shell history for the session.
- If the source account is judged compromised (cited evidence required): reset its credentials, review its authorized_keys, and audit everything the su-acquired shell touched.
- If benign but unbaselined: record the source→target pair in the host's admin baseline so future hits triage faster.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="auth_linux_sudo_privilege_escalation"></a>
##### Sudo Command Execution Logged

**Rule file:** `rules/sigma/auth_linux_sudo_privilege_escalation.yml` · **Status:** experimental · **Severity:** low

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Privilege Escalation |
| Technique(s) | T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| Severity (`level`) | low |
| Data source | Filebeat (Linux auth.log) |
| Trigger condition | A Linux auth event (`event.module: system`) whose `message` contains both the tokens `sudo` and `command` — sudo logs a literal `COMMAND=` field for every invocation |

Detects a sudo command invocation recorded in auth.log. Deliberately broad, not narrowed to specific commands: this flags every logged sudo invocation, not just suspicious ones — it is the visibility layer other, more targeted rules (like `auth_linux_ssh_authorized_keys_change.yml`) build on, not a standalone high-confidence alert. The rule's own promotion gate: it stays experimental until paired with a threshold companion or narrowed to commands of interest, because per-event alerting on all sudo usage is not operable at fleet scale.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `event.module` | rule detection block | Scopes to the Linux auth pipeline (`system`) |
| `message` | rule detection block | The full sudo line — invoking user, `TTY=`, `PWD=`, `USER=<target>`, and the exact `COMMAND=` string |
| `host.name` | event source | Host where the command ran |
| `@timestamp` | event source | Invocation time — anchor for baseline comparison |

###### 3. Enrichment Criteria

- Internal-only artifact class: no external TI artifact on this event.
- Internal-only checks: the invoking account against the host's expected-admin allowlist; the `COMMAND=` value against the account's routine pattern; change calendar for maintenance windows explaining unusual commands.
- A sudo line is evidence that a command ran with privilege — nothing more. Suspicion needs the command content plus context, cited in the case.

###### 4. Containment Decision Flow

**Auto-containment:** none — severity low, Internal-only → Tier D: enrich and queue for analyst review; no automation.
**Analyst triage path** (context checks, not containment):
1. Verify with KQL (index `logstash-*`; Linux auth fields are already ECS):
   ```
   event.module : "system" and message : "sudo" and message : "command"
   ```
2. Context check: parse the invoking account and `COMMAND=` from `message`; compare against that account's baseline on this host (expected accounts, routine commands, normal hours). Bucket by host/account over 24 h to see whether this is ordinary volume.
3. Content check: does the `COMMAND=` touch credential material, `authorized_keys`, shell spawns (`sudo su`, `sudo -s`, `sudo bash`), or config the account has no business editing? Correlate with any sibling `authorized_keys` alert in the same window.
4. False-positive check: routine, expected administrative sudo usage — the rule is deliberately broad; tune with an allowlist of expected accounts/commands per host rather than treating every hit as an incident.
**Escalation:** a privileged command from an account outside the admin baseline, or a `COMMAND=` that manipulates credentials/keys/persistence with no change record → open a case and move to the identity-compromise flow for the invoking account.

###### 5. Remediation & Evidence Preservation

- For an escalated case: export the auth.log window for the account (all sudo lines plus its originating login), preserving the exact `COMMAND=` strings verbatim.
- If the invoking account is judged compromised (cited evidence required): reset credentials, audit sudoers membership, and reverse the escalated command's effects (restore edited files from backup, remove added keys/users).
- Tune rather than mute: feed confirmed-benign account/command pairs into the per-host allowlist so the visibility layer stays reviewable.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### Sysmon Specialized Events (EID 8 CreateRemoteThread, EID 11 FileCreate) — 2 rules

*`proc_creation_win_startup_folder_file_drop.yml` lives in this family despite its filename prefix: its logsource is `file_event` (Sysmon EID 11) and its detection field is `TargetFilename`, not process-creation fields.*

<a id="create_remote_thread_win_susp_target"></a>
##### Suspicious CreateRemoteThread Target or Source (Sysmon EventID 8)

**Rule file:** `rules/sigma/create_remote_thread_win_susp_target.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Defense Evasion, Privilege Escalation |
| Technique(s) | T1055 — Process Injection |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (create_remote_thread) |
| Trigger condition | Sysmon EID 8 where either the target process image ends `\lsass.exe` (any source account) or `SourceUser` is anything other than `NT AUTHORITY\SYSTEM` |

Detects CreateRemoteThread where the target is lsass.exe (classic credential-dumping-via-injection precursor) or the thread was created by a non-SYSTEM account. The rule states its own scope limits: the non-SYSTEM branch is broad by design and will match routine non-malicious activity (EDR/AV agents, debuggers, JIT/.NET hosting, accessibility and remote-support tooling, some installers) — expect meaningful alert volume on a live fleet; a SYSTEM-context actor injecting into a non-lsass target is not covered; and the SYSTEM exclusion matches the literal display string `NT AUTHORITY\SYSTEM` (Sysmon exposes no SID for `SourceUser`), which is correct on English-locale hosts but needs a locale-specific value added on non-English builds.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Fixed at 8 (CreateRemoteThread) |
| `TargetImage` | rule detection block | Injection target — `\lsass.exe` marks the credential-access branch |
| `SourceUser` | rule detection block | Account that created the thread — the non-SYSTEM branch trigger |
| `SourceImage` | event source (Sysmon EID 8) | The injecting binary — primary artifact; hash it via its own EID 1 event |
| `SourceProcessGuid`, `TargetProcessGuid` | event source (Sysmon EID 8) | Process-tree pivot keys for source and target |
| `StartAddress`, `StartModule`, `StartFunction` | event source (Sysmon EID 8) | Thread start location — a start address backed by no module is an injection tell |
| `Computer`, `UtcTime` | event source (Sysmon EID 8) | Host and timeline anchor |

###### 3. Enrichment Criteria

- SHA-256 of the `SourceImage` binary (from that process's own Sysmon EID 1 event — EID 8 carries no hashes) → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- Internal-only checks: `SourceImage` against the deployed EDR/AV/debugging tooling inventory and the fleet allowlist; change calendar for a sanctioned debugging or support session.
- A non-SYSTEM CreateRemoteThread alone is not malicious — the branch is broad by design; label the source binary malicious only with the citing VT verdict or an internal case ID.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the `SourceImage` binary's VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; raw winlog fields — this channel is not ECS-renamed):
   ```
   winlog.event_id : 8 and (winlog.event_data.TargetImage : *\\lsass.exe or not winlog.event_data.SourceUser : "NT AUTHORITY\\SYSTEM")
   ```
2. Process-tree analysis: pivot `SourceProcessGuid` to the source process's EID 1 event for its command line, parent, and hash; sweep the host ±30 min for other EID 8 events from the same source image.
3. False-positive checks: legitimate security/monitoring agents (EDR, debuggers, backup software) that inject into or inspect LSASS for non-malicious purposes; on the non-SYSTEM branch, routine CreateRemoteThread by EDR/AV agents, debuggers, JIT/.NET runtimes, accessibility tooling, and remote-support software under a normal user account — expect tuning (allowlisting) to be required at this severity on a live fleet.
**Escalation:** the lsass-target branch with a non-allowlisted source is a credential-access red flag — mirror the LSASS-dump treatment: page the IR lead and treat every credential with a session on the host as exposed.

###### 5. Remediation & Evidence Preservation

- Acquire full host memory **before** any cleanup or reboot; collect and hash the `SourceImage` binary.
- For a confirmed lsass-target case: force password resets for every account with a session on the host; revoke Kerberos tickets and cached sessions for those accounts; hunt post-event authentications by those accounts from new source hosts.
- Remove the source binary's launcher (service, scheduled task, Run key — whatever the process tree shows) and verify the binary does not respawn.
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

<a id="proc_creation_win_startup_folder_file_drop"></a>
##### File Dropped into the Startup Folder

**Rule file:** `rules/sigma/proc_creation_win_startup_folder_file_drop.yml` · **Status:** experimental · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Severity (`level`) | high |
| Data source | Sysmon/Winlogbeat (file_event) |
| Trigger condition | Sysmon EID 11 (FileCreate) where `TargetFilename` contains a user or all-users `\Start Menu\Programs\Startup\` path and ends in one of `.exe`/`.dll`/`.lnk`/`.bat`/`.cmd`/`.vbs`/`.js`/`.ps1`/`.scr`/`.pif` |

Detects a file created inside a Startup folder — anything placed there runs automatically at the next logon, with no registry key or scheduled task needed. Scoped to executable-adjacent extensions because a data file dropped there has no persistence effect; `.scr` and `.pif` (both natively executable at logon and classic icon-disguise extensions) were added after security review #233 flagged their absence.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `TargetFilename` | rule detection block | Full dropped-file path — which user's Startup folder, and the payload extension |
| `Image` | event source (Sysmon EID 11) | The writer process — installer vs script host/Office/browser is the core triage split |
| `ProcessGuid`, `ProcessId` | event source (Sysmon EID 11) | Pivot to the writer's EID 1 event (command line, parent, hash) |
| `User` | event source (Sysmon EID 11) | Account context — whose logon will run the payload |
| `CreationUtcTime` | event source (Sysmon EID 11) | Differs from event time when an existing file was overwritten in place |
| `Computer`, `UtcTime` | event source (Sysmon EID 11) | Host and timeline anchor |

###### 3. Enrichment Criteria

- SHA-256 of the dropped file (collect it from disk — EID 11 carries no hash) → VirusTotal; escalate at **≥ 5 malicious verdicts**. For a `.lnk`, hash and enrich the target the shortcut points at as well.
- Internal-only checks: the writer `Image` against the change calendar and software-deployment records (sanctioned installer run?); the target user's role on the host.
- A Startup-folder write by an installer during a documented deployment is routine — cite the change record or the VT verdict before labeling either file malicious.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when the dropped file's VT verdict is ≥ 5 malicious; account actions on analyst confirm.
**Analyst triage path** (no TI confirmation yet) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; raw winlog fields — this channel is not ECS-renamed; the query is deliberately broader than the rule's full path match, so confirm the complete `\Start Menu\Programs\Startup\` path in the returned `TargetFilename`):
   ```
   winlog.event_id : 11 and winlog.event_data.TargetFilename : *\\Startup\\*
   ```
2. Process-tree analysis: pivot `ProcessGuid` to the writer's EID 1 event; a script host, Office process, or browser writing an executable into Startup is a strong compromise signal, an interactive MSI/installer much less so. Sweep the host ±30 min for other file drops by the same writer.
3. Logon-execution check: if a logon occurred after the drop, look for an EID 1 whose image or command line matches the dropped file — persistence that has already fired changes the case from "planted" to "active".
4. False-positive check: a legitimate application installer creating its own Startup-folder shortcut (`.lnk`) during setup — correlate the installing process against the change calendar.
**Escalation:** dropped file VT ≥ 5 malicious, a non-installer writer process, or evidence the payload already executed at logon → page the IR lead and isolate the host.

###### 5. Remediation & Evidence Preservation

- Collect and SHA-256 hash the dropped file (and a `.lnk`'s target) **before** deleting it from the Startup folder.
- Remove the file; then sweep the host's other autostart locations (both Startup folders, Run/RunOnce keys, scheduled tasks) for siblings planted by the same writer.
- If the payload already ran: treat the host per the payload's behavior — memory acquisition, credential resets for logged-on accounts, and eradication of whatever it launched.
- Remove or remediate the writer process's own foothold (the process tree shows how it got there).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

#### WMI Activity (EID 5861) — 1 rule

<a id="wmi_win_event_subscription_binding"></a>
##### Suspicious WMI Event Filter-to-Consumer Binding (WMI-Activity 5861)

**Rule file:** `rules/sigma/wmi_win_event_subscription_binding.yml` · **Status:** stable · **Severity:** high

###### 1. Rule Summary & MITRE Mapping

| Attribute | Value |
|---|---|
| Tactic(s) | Persistence |
| Technique(s) | T1546.003 — Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| Severity (`level`) | high |
| Data source | Winlogbeat (WMI-Activity/Operational) |
| Trigger condition | WMI-Activity/Operational EID 5861 whose `Operation` string contains both `PutInstance` and `FilterToConsumerBinding` — the operation that completes a permanent WMI event subscription |

Detects the PutInstance operation that binds an `__EventFilter` to a consumer (`__FilterToConsumerBinding`) — the step that makes WMI-based persistence durable across reboots. The channel is enabled by default on Windows 8 / Server 2012 and later; no additional audit policy is required.

###### 2. Automated Extraction Fields

| Field | Origin | Use in triage |
|---|---|---|
| `EventID` | rule detection block | Fixed at 5861 — a binding was completed, not merely attempted |
| `Operation` | rule detection block | The full PutInstance string — embeds the binding instance: filter name, consumer name/type, and for a CommandLineEventConsumer the command line that will run when the filter fires |
| `Computer` | event source (WMI-Activity/Operational) | The host now carrying the permanent subscription |
| `@timestamp` | event source | When the persistence was installed — anchor for the who-did-it pivot |

###### 3. Enrichment Criteria

- Internal-first artifact class: match the filter/consumer names and the consumer command line (parsed from `Operation`) against known management tooling (SCCM, AV/EDR agents), the software inventory, the change calendar, and prior case history.
- If the consumer command line references a payload on disk (executable, script, encoded command writing a file), collect that file and SHA-256 → VirusTotal; escalate at **≥ 5 malicious verdicts**.
- The binding event proves persistence was installed; whether it is malicious rests on the consumer's payload and the internal match — cite one or the other before labeling.

###### 4. Containment Decision Flow

**Auto-containment:** severity high → Tier B: auto EDR-isolate the host when a payload referenced by the consumer command line hashes to VT ≥ 5 malicious; the binding itself (internal-first artifact class) routes to analyst triage otherwise.
**Analyst triage path** (no TI confirmation) — 15-minute SLA:
1. Verify with KQL (index `logstash-*`; raw winlog fields — this channel is not ECS-renamed):
   ```
   winlog.event_id : 5861 and winlog.event_data.Operation : *PutInstance* and winlog.event_data.Operation : *FilterToConsumerBinding*
   ```
2. Parse `Operation`: extract the filter name, consumer name/type, and command line; then pivot to the host's Sysmon EID 1 events around `@timestamp` to find the process that created the subscription (wmic, PowerShell, an installer, or an unknown binary).
3. Enumerate the live subscription on the host (`root\subscription`: `__EventFilter`, `CommandLineEventConsumer`/other consumers, `__FilterToConsumerBinding`) to capture exactly what is now persistent.
4. False-positive check: legitimate WMI-based management or monitoring tooling (e.g. SCCM, some AV/EDR agents) that registers permanent event subscriptions — match the names and command line against the deployed-tooling inventory.
**Escalation:** a consumer command line launching a shell/script host or an unknown binary, or a subscription no management tool accounts for → page the IR lead and treat as active persistence; isolate on confirm.

###### 5. Remediation & Evidence Preservation

- Before removal, export the full subscription triple from `root\subscription` (e.g. `Get-CimInstance` of `__EventFilter`, the consumer class, and `__FilterToConsumerBinding`, saved to file) — the filter query and consumer command line are the core evidence.
- Collect and hash any payload the consumer references before deleting it.
- Remove all three objects — the `__FilterToConsumerBinding`, the `__EventFilter`, and the consumer (e.g. `CommandLineEventConsumer`) — removing only the binding leaves re-linkable parts behind; verify by re-enumerating `root\subscription`.
- Hunt sibling subscriptions: re-run the enumeration fleet-wide (or query this rule's history across hosts) for the same filter/consumer names or command-line pattern.
- Identify and eradicate the creating process's own foothold (from the Sysmon pivot in triage).
- Preserve evidence per SOP-147 (`docs/SOP-147-evidence-validation-runbook.md`): SHA-256 hash all collected files/screenshots, record the UTC window and source host before cleanup.

# References and Resources
- [`docs/detections/attack-coverage.md`](../detections/attack-coverage.md) — authoritative ATT&CK coverage matrix (auto-generated from `rules/sigma/`)
- `rules/sigma/` — the 108 deployed Sigma rules (single source of truth for endpoint/network detection logic)
- `rules/elastic/threshold/` — Elastic threshold companion rules carrying count-over-time logic for the 8 paired detections
- [`docs/SOP-147-evidence-validation-runbook.md`](../SOP-147-evidence-validation-runbook.md) — evidence validation runbook (SHA-256 hashing, UTC windows, tamper-evident capture)
- Threat intelligence sources: VirusTotal, AbuseIPDB, AlienVault OTX (thresholds defined in [Standard 4-Phase IR Workflow](#standard-4-phase-ir-workflow))
- MITRE ATT&CK: <https://attack.mitre.org/>
- Suburban-SOC Emulation Coverage Checklist

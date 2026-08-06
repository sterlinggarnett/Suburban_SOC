# Suburban-SOC — SIEM Detection Queries (KQL/Lucene)

> **Generated** by `scripts/setup/build_kql_docs.py` from `rules/sigma/*.yml`
> through the `configs/detections/suburban-soc-ecs.yml` field pipeline. Do not
> hand-edit — re-run the generator. Queries target **`process.args`** (this
> stack's field), NOT the ECS-standard `process.command_line`.

**52 rules.** Each query is the exact Lucene the Sigma rule compiles to.

## AS-REP Roasting — TGT Requested for an Account Without Pre-Authentication

- **Rule:** `auth_win_asreproast_no_preauth_tgt.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1558.004

```
(winlog.event_id:4768 AND winlog.event_data.PreAuthType:0) AND (NOT winlog.event_data.TargetUserName:*$)
```

## Repeated Failed Sign-Ins (Windows Security 4625)

- **Rule:** `auth_win_bruteforce_failed_logons.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1110

```
winlog.event_id:4625
```

## Password Spray Indicator via Failed Logons From a Single Source (Windows Security 4625)

- **Rule:** `auth_win_bruteforce_source_spray.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1110.003

```
winlog.event_id:4625
```

## DCSync — Directory Replication Rights Exercised by a Non-DC Account

- **Rule:** `auth_win_dcsync_replication_rights_used.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1003.006

```
(winlog.event_id:4662 AND winlog.event_data.AccessMask:0x100 AND (winlog.event_data.Properties:(*1131f6aa\-9c07\-11d1\-f79f\-00c04fc2dcd2* OR *1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2* OR *89e95b76\-444d\-4c62\-991a\-0facbeda640c*))) AND (NOT winlog.event_data.SubjectUserName:*$)
```

## Explicit-Credential Sign-In Recorded (Windows Security 4648)

- **Rule:** `auth_win_explicit_cred_account_sweep.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1110.003

```
winlog.event_id:4648
```

## Kerberoasting — RC4 Service Ticket Requested for a User SPN

- **Rule:** `auth_win_kerberoasting_rc4_spn_request.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1558.003

```
(winlog.event_id:4769 AND winlog.event_data.TicketEncryptionType:0x17 AND winlog.event_data.Status:0x0) AND (NOT winlog.event_data.ServiceName:*$) AND (NOT winlog.event_data.ServiceName:krbtgt*)
```

## Privileged Group Membership Change (Windows Security 4732/4728/4756)

- **Rule:** `auth_win_priv_group_membership_change.yml` · **level:** high · **status:** stable · **ATT&CK:** T1098, T1078

```
(winlog.event_id:(4732 OR 4728 OR 4756)) AND ((winlog.event_data.TargetUserName:(Administrators OR Domain\ Admins OR Enterprise\ Admins)) OR (winlog.event_data.TargetSid:(*\-544 OR *\-512 OR *\-519)))
```

## Security Audit Log Cleared (Windows Security 1102)

- **Rule:** `auth_win_security_log_cleared.yml` · **level:** high · **status:** stable · **ATT&CK:** T1070.001

```
winlog.event_id:1102
```

## Special-Privilege Logon Assigning SeDebugPrivilege (Windows Security 4672)

- **Rule:** `auth_win_sedebug_special_logon.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1078, T1134

```
(winlog.event_id:4672 AND winlog.event_data.PrivilegeList:*SeDebugPrivilege*) AND (NOT winlog.event_data.SubjectUserSid:S\-1\-5\-18)
```

## Suspicious CreateRemoteThread Target or Source (Sysmon EventID 8)

- **Rule:** `create_remote_thread_win_susp_target.yml` · **level:** high · **status:** stable · **ATT&CK:** T1055

```
winlog.event_id:8 AND (winlog.event_data.TargetImage:*\\lsass.exe OR (NOT winlog.event_data.SourceUser:NT\ AUTHORITY\\SYSTEM))
```

## Executable or Script Payload Downloaded Over HTTP (Zeek Files)

- **Rule:** `net_zeek_executable_download.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1105

```
zeek.source:HTTP AND (mime_type:(application\/x\-dosexec OR application\/x\-msdownload OR application\/vnd.microsoft.portable\-executable OR application\/x\-elf OR application\/x\-executable OR application\/x\-sharedlib OR application\/x\-sh OR application\/x\-shellscript))
```

## Network Port or Address Scan Detected (Zeek Notice)

- **Rule:** `net_zeek_port_scan.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1046

```
note:(Scan\:\:Port_Scan OR Scan\:\:Address_Scan OR Scan\:\:Random_Scan)
```

## SSH Password Guessing / Brute Force (Zeek Notice)

- **Rule:** `net_zeek_ssh_bruteforce.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1110

```
note:(SSH\:\:Password_Guessing OR SSH\:\:Login_By_Password_Guesser)
```

## Obfuscated or Encoded PowerShell Script Block

- **Rule:** `posh_ps_obfuscated_scriptblock.yml` · **level:** high · **status:** stable · **ATT&CK:** T1059.001, T1027

```
winlog.event_id:4104 AND (((winlog.event_data.ScriptBlockText:(*IEX\(* OR *IEX\ * OR *\|IEX* OR *\|\ IEX* OR *;IEX* OR *;\ IEX* OR *Invoke\-Expression* OR *\[scriptblock\]\:\:Create* OR *.Invoke\(\)*)) AND ((winlog.event_data.ScriptBlockText:(*DownloadString* OR *DownloadFile* OR *DownloadData* OR *Net.WebClient* OR *Invoke\-WebRequest* OR *Invoke\-RestMethod* OR *Start\-BitsTransfer* OR *\ iwr\ * OR *\|iwr\ * OR *;iwr\ * OR *\=iwr\ * OR *\ irm\ * OR *\|irm\ * OR *;irm\ * OR *\=irm\ *)) OR (winlog.event_data.ScriptBlockText:(iwr\ * OR irm\ *)))) OR ((winlog.event_data.ScriptBlockText:(*IEX\(* OR *IEX\ * OR *\|IEX* OR *\|\ IEX* OR *;IEX* OR *;\ IEX* OR *Invoke\-Expression* OR *\[scriptblock\]\:\:Create* OR *.Invoke\(\)*)) AND (winlog.event_data.ScriptBlockText:(*\-bxor* OR *\-bnot* OR *FromBase64String* OR *\-EncodedCommand* OR *\-enc\ *))) OR (((winlog.event_data.ScriptBlockText:(*DownloadString* OR *DownloadFile* OR *DownloadData* OR *Net.WebClient* OR *Invoke\-WebRequest* OR *Invoke\-RestMethod* OR *Start\-BitsTransfer* OR *\ iwr\ * OR *\|iwr\ * OR *;iwr\ * OR *\=iwr\ * OR *\ irm\ * OR *\|irm\ * OR *;irm\ * OR *\=irm\ *)) OR (winlog.event_data.ScriptBlockText:(iwr\ * OR irm\ *))) AND (winlog.event_data.ScriptBlockText:(*\-bxor* OR *\-bnot* OR *FromBase64String* OR *\-EncodedCommand* OR *\-enc\ *))))
```

## Malicious File Download via Bitsadmin

- **Rule:** `proc_creation_win_bitsadmin_download.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1105

```
process.executable:*\\bitsadmin.exe AND process.args:*\/transfer*
```

## Payload Decoding via Certutil

- **Rule:** `proc_creation_win_certutil_decode.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1140

```
process.executable:*\\certutil.exe AND (process.args:(*\-decode* OR *\/decode*))
```

## Ingress Tool Transfer via Certutil URL Cache

- **Rule:** `proc_creation_win_certutil_urlcache_download.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1105

```
(process.executable:*\\certutil.exe AND (process.args:(*urlcache* OR *verifyctl*))) AND process.args:*split*
```

## Clearing Windows Event Logs via Wevtutil

- **Rule:** `proc_creation_win_clear_event_logs.yml` · **level:** high · **status:** stable · **ATT&CK:** T1070.001

```
process.executable:*\\wevtutil.exe AND (process.args:(*\ cl\ * OR *\ clear\-log\ *))
```

## Saved Credential Enumeration via cmdkey or vaultcmd

- **Rule:** `proc_creation_win_cmdkey_saved_creds_enum.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1555.004

```
(process.executable:*\\cmdkey.exe OR process.pe.original_file_name:cmdkey.exe OR process.executable:*\\vaultcmd.exe OR process.pe.original_file_name:vaultcmd.exe) AND (process.args:(*\/list* OR *\-list*))
```

## CMSTP Execution via Malicious INF or Silent-Install Flags

- **Rule:** `proc_creation_win_cmstp_execution.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1218.003

```
process.executable:*\\cmstp.exe AND (process.args:(*\/s* OR *\/ns* OR *.inf* OR *\\appdata\\* OR *\\temp\\* OR *\\users\\public\\*))
```

## Cscript/Wscript Executing from a Non-Standard Location

- **Rule:** `proc_creation_win_cscript_wscript_remote.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1059.005, T1059.007

```
(process.executable:(*\\cscript.exe OR *\\wscript.exe)) AND (process.args:(*\/\/e\:* OR *\\appdata\\* OR *\\temp\\* OR *\\users\\public\\* OR *\\downloads\\* OR *http*))
```

## Windows Defender Real-Time Protection Disabled

- **Rule:** `proc_creation_win_defender_tamper.yml` · **level:** high · **status:** stable · **ATT&CK:** T1562.001

```
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.args:*Set\-MpPreference* AND process.args:*Disable*)
```

## Domain Group Discovery via Net.exe

- **Rule:** `proc_creation_win_domain_group_discovery.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1087.002

```
(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.args:*group* AND process.args:*\/domain*)
```

## Indirect Command Execution via Forfiles

- **Rule:** `proc_creation_win_forfiles_execution.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1202

```
(process.executable:*\\forfiles.exe AND process.args:*\/c*) AND (process.args:(*cmd\ \/c* OR *powershell* OR *pwsh* OR *rundll32* OR *regsvr32* OR *mshta* OR *wscript* OR *cscript* OR *certutil*))
```

## InstallUtil Execution Bypassing Uninstall Logging

- **Rule:** `proc_creation_win_installutil_bypass.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1218.004

```
process.executable:*\\installutil.exe AND (process.args:(*\/u* OR *\-u* OR *\/logfile\=* OR *\-logfile\=* OR *\/logtoconsole\=false*))
```

## Shell Spawned by PsExec Service or WMI Provider Host

- **Rule:** `proc_creation_win_lateral_tool_parent.yml` · **level:** high · **status:** stable · **ATT&CK:** T1021, T1569.002

```
(process.executable:(*\\cmd.exe OR *\\powershell.exe)) AND (process.parent.name:(*\\PSEXESVC.exe OR *\\WmiPrvSE.exe))
```

## LaZagne Credential Harvester Execution

- **Rule:** `proc_creation_win_lazagne_credential_harvest.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1555

```
((process.executable:*lazagne* OR process.pe.original_file_name:*lazagne* OR process.args:*lazagne*) AND ((process.args:(*\ all* OR *\ browsers* OR *\ windows*)) OR (process.args:(*\ \-oN* OR *\ \-oJ*)))) OR ((process.args:(*\ all* OR *\ browsers* OR *\ windows*)) AND (process.args:(*\ \-oN* OR *\ \-oJ*)))
```

## Local User Account Creation via Net.exe

- **Rule:** `proc_creation_win_local_acct_create.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1136.001

```
(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.args:*user* AND process.args:*\/add*)
```

## LSASS Memory Dump via Comsvcs.dll

- **Rule:** `proc_creation_win_lsass_dump.yml` · **level:** high · **status:** stable · **ATT&CK:** T1003.001

```
process.executable:*\\rundll32.exe AND (process.args:*comsvcs.dll* AND process.args:*MiniDump*)
```

## Mimikatz Module Syntax on the Command Line

- **Rule:** `proc_creation_win_mimikatz_module_syntax.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1003.001

```
process.args:(*sekurlsa\:\:* OR *lsadump\:\:* OR *privilege\:\:debug* OR *kerberos\:\:golden* OR *kerberos\:\:ptt* OR *crypto\:\:capi* OR *misc\:\:memssp*)
```

## Mshta Remote or Script Payload Execution

- **Rule:** `proc_creation_win_mshta_remote.yml` · **level:** high · **status:** stable · **ATT&CK:** T1218.005

```
process.executable:*\\mshta.exe AND (process.args:(*http* OR *javascript* OR *vbscript*))
```

## MSI Package Installed from a Remote URL

- **Rule:** `proc_creation_win_msiexec_remote.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1218.007

```
process.executable:*\\msiexec.exe AND (process.args:(*\/i\ http* OR *\/i\"http* OR *\-i\ http* OR *\/package\ http* OR *\/a\ http*))
```

## Domain Controller Discovery via Nltest

- **Rule:** `proc_creation_win_nltest_discovery.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1018

```
process.executable:*\\nltest.exe AND (process.args:(*\/dclist\:* OR *\/domain_trusts* OR *\/dsgetdc\:*))
```

## NTDS.dit Extraction via ntdsutil IFM Media Creation

- **Rule:** `proc_creation_win_ntdsutil_ifm_dump.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1003.003

```
(process.executable:*\\ntdsutil.exe OR process.pe.original_file_name:ntdsutil.exe) AND (process.args:(*ac\ i\ ntds* OR *activate\ instance\ ntds*)) AND (process.args:(*create\ full* OR *ifm*))
```

## Indirect Command Execution via Pcalua

- **Rule:** `proc_creation_win_pcalua_execution.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1202

```
(process.executable:*\\pcalua.exe AND process.args:*\-a*) AND (NOT process.parent.name:*\\explorer.exe)
```

## PowerShell Remote Download Cradle

- **Rule:** `proc_creation_win_powershell_downloadstring.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1059.001, T1105

```
(process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.args:(*downloadstring* OR *downloadfile* OR *downloaddata* OR *invoke\-webrequest* OR *invoke\-restmethod* OR *start\-bitstransfer* OR *webrequest\:\:create* OR *httpclient*))
```

## Suspicious PowerShell Encoded Command Execution

- **Rule:** `proc_creation_win_powershell_encoded.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1059.001

```
((process.executable:(*\\powershell.exe OR *\\pwsh.exe)) AND (process.args:(*\ \-e\ * OR *\ \-en\ * OR *\ \-enc\ * OR *\ \-enco* OR *\ \-encod* OR *\ \-EncodedCommand* OR *\ \-ec\ * OR *\ \/e\ * OR *\ \/en\ * OR *\ \/enc\ * OR *\ \/enco* OR *\ \/encod* OR *\ \/EncodedCommand* OR *\ \/ec\ *))) AND (NOT (process.args:(*\ \-encoding\ * OR *\ \-encoding\:*)))
```

## RDP Session Hijacking via Tscon

- **Rule:** `proc_creation_win_rdp_hijack_tscon.yml` · **level:** high · **status:** stable · **ATT&CK:** T1574

```
process.executable:*\\tscon.exe AND process.args:*\/dest\:*
```

## SAM Hive Dump via Reg.exe

- **Rule:** `proc_creation_win_reg_save_sam.yml` · **level:** high · **status:** stable · **ATT&CK:** T1003.002

```
process.executable:*\\reg.exe AND (process.args:*save* AND process.args:*hklm\\sam*)
```

## Regasm/Regsvcs Proxy Execution

- **Rule:** `proc_creation_win_regasm_regsvcs_bypass.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1218.009

```
(process.executable:(*\\regasm.exe OR *\\regsvcs.exe)) AND (process.args:(*\/u* OR *\\appdata\\* OR *\\temp\\* OR *\\users\\public\\* OR *\\programdata\\* OR *\\downloads\\*))
```

## Regsvr32 Execution from Remote Server

- **Rule:** `proc_creation_win_regsvr32_remote_sct.yml` · **level:** critical · **status:** stable · **ATT&CK:** T1218.010

```
process.executable:*\\regsvr32.exe AND (process.args:*\/i\:http* AND process.args:*scrobj.dll*)
```

## Registry Run Key Persistence via Reg.exe

- **Rule:** `proc_creation_win_run_key_persistence.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1547.001

```
process.executable:*\\reg.exe AND (process.args:*add* AND process.args:*CurrentVersion\\Run*)
```

## Rundll32 Executing Inline Script via mshtml

- **Rule:** `proc_creation_win_rundll32_inline_script.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1218.011

```
process.executable:*\\rundll32.exe AND (process.args:(*javascript\:* OR *vbscript\:* OR *runhtmlapplication* OR *mshtml*))
```

## Scheduled Task Creation via Schtasks

- **Rule:** `proc_creation_win_scheduled_task.yml` · **level:** low · **status:** stable · **ATT&CK:** T1053.005

```
process.executable:*\\schtasks.exe AND (process.args:*\/create* AND process.args:*\/tn*)
```

## Windows Service Creation via Sc.exe

- **Rule:** `proc_creation_win_service_creation_sc.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1543.003

```
process.executable:*\\sc.exe AND (process.args:*create* AND process.args:*binpath*)
```

## Suspicious System Owner/User Discovery

- **Rule:** `proc_creation_win_user_discovery.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1033

```
process.executable:*\\whoami.exe AND process.args:*\/all*
```

## Shadow Copy Deletion via Vssadmin

- **Rule:** `proc_creation_win_vss_delete_shadows.yml` · **level:** high · **status:** stable · **ATT&CK:** T1490

```
process.executable:*\\vssadmin.exe AND (process.args:*delete* AND process.args:*shadows*)
```

## WMI Process Call Create

- **Rule:** `proc_creation_win_wmi_process_create.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1047

```
process.executable:*\\wmic.exe AND (process.args:*process* AND process.args:*call* AND process.args:*create*)
```

## Event Log Cleared (Windows System 104)

- **Rule:** `system_win_eventlog_cleared.yml` · **level:** high · **status:** stable · **ATT&CK:** T1070.001

```
winlog.event_id:104
```

## Windows Event Log Service Reconfigured or Disabled (Windows System 7040)

- **Rule:** `system_win_eventlog_service_tamper.yml` · **level:** high · **status:** stable · **ATT&CK:** T1562.002

```
winlog.event_id:7040 AND winlog.event_data.param1:*Event\ Log*
```

## New Service Installed (Windows System 7045)

- **Rule:** `system_win_service_installed.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1543.003

```
winlog.event_id:7045 AND (NOT (winlog.event_data.ImagePath:(C\:\\Windows\\System32\\* OR \"C\:\\Windows\\System32\\* OR C\:\\Windows\\SysWOW64\\* OR \"C\:\\Windows\\SysWOW64\\* OR C\:\\Program\ Files\\* OR \"C\:\\Program\ Files\\* OR C\:\\Program\ Files\ \(x86\)\\* OR \"C\:\\Program\ Files\ \(x86\)\\* OR %SystemRoot%\\* OR \"%SystemRoot%\\* OR \\SystemRoot\\* OR \??\\C\:\\Windows\\* OR \"\??\\C\:\\Windows\\* OR \??\\C\:\\Program\ Files\\* OR \"\??\\C\:\\Program\ Files\\*)))
```

## Suspicious WMI Event Filter-to-Consumer Binding (WMI-Activity 5861)

- **Rule:** `wmi_win_event_subscription_binding.yml` · **level:** high · **status:** stable · **ATT&CK:** T1546.003

```
winlog.event_id:5861 AND (winlog.event_data.Operation:*PutInstance* AND winlog.event_data.Operation:*FilterToConsumerBinding*)
```

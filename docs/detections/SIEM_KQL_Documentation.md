# Suburban-SOC — SIEM Detection Queries (KQL/Lucene)

> **Generated** by `scripts/setup/build_kql_docs.py` from `rules/sigma/*.yml`
> through the `configs/detections/suburban-soc-ecs.yml` field pipeline. Do not
> hand-edit — re-run the generator. Queries target **`process.args`** (this
> stack's field), NOT the ECS-standard `process.command_line`.

**105 rules.** Each query is the exact Lucene the Sigma rule compiles to.

## SSH Login Attempt for a Nonexistent User

- **Rule:** `auth_linux_invalid_user_ssh_attempt.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1110.001

```
event.module:system AND message:invalid AND message:user
```

## Reference to authorized_keys in Linux Auth Log

- **Rule:** `auth_linux_ssh_authorized_keys_change.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1098.004

```
event.module:system AND message:authorized_keys
```

## Direct Root Login via SSH

- **Rule:** `auth_linux_ssh_root_login.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1078.003

```
event.module:system AND user.name:root AND event.outcome:success
```

## su Session Opened

- **Rule:** `auth_linux_su_session_opened.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1078.003

```
event.module:system AND message:su AND message:session AND message:opened
```

## Sudo Command Execution Logged

- **Rule:** `auth_linux_sudo_privilege_escalation.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1548.003

```
event.module:system AND message:sudo AND message:command
```

## AS-REP Roasting — TGT Requested for an Account Without Pre-Authentication

- **Rule:** `auth_win_asreproast_no_preauth_tgt.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1558.004

```
(winlog.event_id:4768 AND winlog.event_data.PreAuthType:0) AND (NOT winlog.event_data.TargetUserName:*$)
```

## Audit Policy Changed

- **Rule:** `auth_win_audit_policy_changed.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1562.002

```
winlog.event_id:4719
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

## Logon Attempt Against a Disabled Account

- **Rule:** `auth_win_disabled_account_logon_attempt.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1078.002

```
winlog.event_id:4625 AND ((winlog.event_data.SubStatus:(0xC0000072 OR 0xc0000072)) OR (winlog.event_data.Status:(0xC0000072 OR 0xc0000072)))
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

## Pass-the-Hash Logon Pattern (LogonType 9, Negotiate)

- **Rule:** `auth_win_pass_the_hash_logon.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1550.002

```
winlog.event_id:4624 AND winlog.event_data.LogonType:9 AND winlog.event_data.AuthenticationPackageName:Negotiate
```

## Privileged Group Membership Change (Windows Security 4732/4728/4756)

- **Rule:** `auth_win_priv_group_membership_change.yml` · **level:** high · **status:** stable · **ATT&CK:** T1098, T1078

```
(winlog.event_id:(4732 OR 4728 OR 4756)) AND ((winlog.event_data.TargetUserName:(Administrators OR Domain\ Admins OR Enterprise\ Admins)) OR (winlog.event_data.TargetSid:(*\-544 OR *\-512 OR *\-519)))
```

## Interactive Logon via RDP (LogonType 10)

- **Rule:** `auth_win_rdp_logon_type10.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1021.001

```
winlog.event_id:4624 AND winlog.event_data.LogonType:10
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

## Object Access Against a Privileged AD Group

- **Rule:** `auth_win_sensitive_group_recon.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1069.002

```
winlog.event_id:4661 AND ((winlog.event_data.ObjectName:(*Domain\ Admins* OR *Enterprise\ Admins* OR *Schema\ Admins* OR *Administrators*)) OR (winlog.event_data.ObjectName:(*\-512 OR *\-519 OR *\-518 OR *\-544)))
```

## User Account Created (Windows Security 4720)

- **Rule:** `auth_win_user_account_created.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1136.001

```
winlog.event_id:4720
```

## Suspicious CreateRemoteThread Target or Source (Sysmon EventID 8)

- **Rule:** `create_remote_thread_win_susp_target.yml` · **level:** high · **status:** stable · **ATT&CK:** T1055

```
winlog.event_id:8 AND (winlog.event_data.TargetImage:*\\lsass.exe OR (NOT winlog.event_data.SourceUser:NT\ AUTHORITY\\SYSTEM))
```

## RDP Connection Originating From Outside Private Address Space

- **Rule:** `net_zeek_conn_external_rdp_inbound.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1021.001

```
(destination.port:3389 AND network.transport:tcp) AND (NOT (source.ip:10.0.0.0\/8 OR source.ip:172.16.0.0\/12 OR source.ip:192.168.0.0\/16))
```

## Unusually Large ICMP Flow (Possible ICMP Tunnel)

- **Rule:** `net_zeek_conn_icmp_tunnel_large.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1095

```
network.transport:icmp AND source.bytes:>1000000
```

## SMB Connection Crossing Private/Public Address Boundary

- **Rule:** `net_zeek_conn_smb_lateral_admin.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1021.002

```
(destination.port:445 AND network.transport:tcp) AND (NOT ((source.ip:10.0.0.0\/8 OR source.ip:172.16.0.0\/12 OR source.ip:192.168.0.0\/16) AND (destination.ip:10.0.0.0\/8 OR destination.ip:172.16.0.0\/12 OR destination.ip:192.168.0.0\/16)))
```

## Connection to Tor's Default OR or Directory Port

- **Rule:** `net_zeek_conn_tor_exit_node.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1090.003

```
(destination.port:(9001 OR 9030)) AND network.transport:tcp
```

## DNS Query for a Known Cryptocurrency Mining Pool

- **Rule:** `net_zeek_dns_crypto_mining_pool.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1496

```
dns.question.name:(*nanopool.org OR *supportxmr.com OR *hashvault.pro OR *moneroocean.stream OR *minexmr.com OR *nicehash.com OR *f2pool.com OR *2miners.com OR *c3pool.com OR *herominers.com OR *unmineable.com)
```

## NXDOMAIN Response for a DGA-Characteristic Domain Name

- **Rule:** `net_zeek_dns_dga_nxdomain_burst.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1568.002

```
dns.response_code:NXDOMAIN AND dns.question.name:/.*[a-zA-Z0-9]{20,}\..*/
```

## DNS Lookup for a Known Public DNS-over-HTTPS Provider

- **Rule:** `net_zeek_dns_doh_non_standard.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1572

```
dns.question.name:(*cloudflare\-dns.com OR *dns.google OR *dns.google.com OR *doh.opendns.com OR *quad9.net OR *doh.cleanbrowsing.org OR *doh.libredns.gr OR *dns.nextdns.io OR *use\-application\-dns.net)
```

## DNS Query with High-Entropy Long Subdomain Label (Possible Tunneling)

- **Rule:** `net_zeek_dns_tunneling_high_entropy.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1071.004

```
dns.question.name:/.*[a-zA-Z0-9]{50,}\..*/
```

## TXT Record Query with Encoded-Looking Payload (Possible C2/Exfil Channel)

- **Rule:** `net_zeek_dns_txt_record_abuse.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1071.004

```
dns.question.type:TXT AND dns.question.name:/.*[a-zA-Z0-9]{40,}\..*/
```

## Executable or Script Payload Downloaded Over HTTP (Zeek Files)

- **Rule:** `net_zeek_executable_download.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1105

```
zeek.source:HTTP AND (mime_type:(application\/x\-dosexec OR application\/x\-msdownload OR application\/vnd.microsoft.portable\-executable OR application\/x\-elf OR application\/x\-executable OR application\/x\-pie\-executable OR application\/x\-sharedlib OR application\/x\-sh OR application\/x\-shellscript))
```

## HTTP Request to a Known Default C2 Beacon URI

- **Rule:** `net_zeek_http_cobalt_strike_beacon.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1071.001

```
http.request.method:GET AND (url.path:(*\/pixel.gif* OR *\/__utm.gif* OR *\/jquery\-3.3.1.min.js* OR *\/jquery\-3.3.2.min.js* OR *\/en_US\/all.js* OR *\/dpixel*))
```

## Large HTTP POST Request Body

- **Rule:** `net_zeek_http_exfil_large_post.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1048.003

```
http.request.method:POST AND http.request.body.bytes:>5000000
```

## Network Port or Address Scan Detected (Zeek Notice)

- **Rule:** `net_zeek_port_scan.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1046

```
note:(Scan\:\:Port_Scan OR Scan\:\:Address_Scan OR Scan\:\:Random_Scan)
```

## Executable Payload Sent as an Email Attachment (Zeek Files)

- **Rule:** `net_zeek_smtp_attachment_executable.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1566.001

```
zeek.source:SMTP AND (mime_type:(application\/x\-dosexec OR application\/x\-msdownload OR application\/vnd.microsoft.portable\-executable OR application\/x\-elf OR application\/x\-executable OR application\/x\-pie\-executable OR application\/x\-sharedlib OR application\/x\-sh OR application\/x\-shellscript))
```

## SMTP Session with an Anomalously Deep Transaction Count

- **Rule:** `net_zeek_smtp_mass_outbound.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1071.003

```
trans_depth:>20
```

## SSH Password Guessing / Brute Force (Zeek Notice)

- **Rule:** `net_zeek_ssh_bruteforce.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1110

```
note:(SSH\:\:Password_Guessing OR SSH\:\:Login_By_Password_Guesser)
```

## TLS Connection with Expired Certificate

- **Rule:** `net_zeek_ssl_expired_cert_connection.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1071.001

```
tls.validation_status:*certificate\ has\ expired*
```

## TLS Connection with Self-Signed Certificate (Possible C2)

- **Rule:** `net_zeek_ssl_self_signed_c2.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1573.002

```
tls.validation_status:(*self\ signed* OR *self\-signed*)
```

## PowerShell Credential-Harvesting Cmdlet Pattern

- **Rule:** `posh_credential_harvesting_scriptblock.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1056.002

```
winlog.event_id:4104 AND ((winlog.event_data.ScriptBlockText:(*Login\ Data* OR *\\Cookies* OR *Local\ State*)) OR (winlog.event_data.ScriptBlockText:(*DPAPI* OR *\[System.Security.Cryptography.ProtectedData\]*)))
```

## PowerShell-Native Data Compression Staging

- **Rule:** `posh_data_compression_staging.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1560

```
winlog.event_id:4104 AND (winlog.event_data.ScriptBlockText:*System.IO.Compression* OR (winlog.event_data.ScriptBlockText:*Compress\-Archive* AND (winlog.event_data.ScriptBlockText:(*\\Temp\\* OR *\\AppData\\Local\\Temp\\* OR *$env\:TEMP*))))
```

## Active Directory Query via Official ActiveDirectory Module

- **Rule:** `posh_ps_ad_recon_admodule.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1087.002

```
winlog.event_id:4104 AND (winlog.event_data.ScriptBlockText:(*Get\-ADUser* OR *Get\-ADGroup* OR *Get\-ADGroupMember* OR *Get\-ADDomainController*))
```

## Active Directory Reconnaissance via PowerView

- **Rule:** `posh_ps_ad_recon_powerview.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1087.002

```
winlog.event_id:4104 AND (winlog.event_data.ScriptBlockText:(*Get\-NetDomain* OR *Get\-NetUser* OR *Get\-NetGroup* OR *Get\-NetComputer* OR *Get\-DomainUser* OR *Get\-DomainController* OR *Get\-DomainTrust* OR *Invoke\-ShareFinder* OR *Find\-DomainShare*))
```

## PowerShell AMSI Bypass Attempt

- **Rule:** `posh_ps_amsi_bypass_attempt.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1562.001

```
winlog.event_id:4104 AND (winlog.event_data.ScriptBlockText:(*AmsiUtils* OR *amsiInitFailed* OR *AmsiScanBuffer* OR *AMSI_RESULT_NOT_DETECTED*))
```

## Obfuscated or Encoded PowerShell Script Block

- **Rule:** `posh_ps_obfuscated_scriptblock.yml` · **level:** high · **status:** stable · **ATT&CK:** T1059.001, T1027

```
winlog.event_id:4104 AND (((winlog.event_data.ScriptBlockText:(*IEX\(* OR *IEX\ * OR *\|IEX* OR *\|\ IEX* OR *;IEX* OR *;\ IEX* OR *Invoke\-Expression* OR *\[scriptblock\]\:\:Create* OR *.Invoke\(\)*)) AND ((winlog.event_data.ScriptBlockText:(*DownloadString* OR *DownloadFile* OR *DownloadData* OR *Net.WebClient* OR *Invoke\-WebRequest* OR *Invoke\-RestMethod* OR *Start\-BitsTransfer* OR *\ iwr\ * OR *\|iwr\ * OR *;iwr\ * OR *\=iwr\ * OR *\ irm\ * OR *\|irm\ * OR *;irm\ * OR *\=irm\ *)) OR (winlog.event_data.ScriptBlockText:(iwr\ * OR irm\ *)))) OR ((winlog.event_data.ScriptBlockText:(*IEX\(* OR *IEX\ * OR *\|IEX* OR *\|\ IEX* OR *;IEX* OR *;\ IEX* OR *Invoke\-Expression* OR *\[scriptblock\]\:\:Create* OR *.Invoke\(\)*)) AND (winlog.event_data.ScriptBlockText:(*\-bxor* OR *\-bnot* OR *FromBase64String* OR *\-EncodedCommand* OR *\-enc\ *))) OR (((winlog.event_data.ScriptBlockText:(*DownloadString* OR *DownloadFile* OR *DownloadData* OR *Net.WebClient* OR *Invoke\-WebRequest* OR *Invoke\-RestMethod* OR *Start\-BitsTransfer* OR *\ iwr\ * OR *\|iwr\ * OR *;iwr\ * OR *\=iwr\ * OR *\ irm\ * OR *\|irm\ * OR *;irm\ * OR *\=irm\ *)) OR (winlog.event_data.ScriptBlockText:(iwr\ * OR irm\ *))) AND (winlog.event_data.ScriptBlockText:(*\-bxor* OR *\-bnot* OR *FromBase64String* OR *\-EncodedCommand* OR *\-enc\ *))))
```

## PowerShell Reverse Shell via TCPClient

- **Rule:** `posh_ps_reverse_shell.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1059.001

```
winlog.event_id:4104 AND winlog.event_data.ScriptBlockText:*Net.Sockets.TCPClient* AND (winlog.event_data.ScriptBlockText:(*GetStream\(\)* OR *NetworkStream* OR *.Read\(* OR *.Write\(*))
```

## Accessibility Feature Backdoor via Image/OriginalFileName Mismatch

- **Rule:** `proc_creation_win_accessibility_binary_debugger_swap.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1546.008

```
(process.executable:*\\sethc.exe AND (NOT process.pe.original_file_name:sethc.exe)) OR (process.executable:*\\utilman.exe AND (NOT process.pe.original_file_name:utilman.exe)) OR (process.executable:*\\osk.exe AND (NOT process.pe.original_file_name:osk.exe)) OR (process.executable:*\\magnify.exe AND (NOT process.pe.original_file_name:Magnify.exe)) OR (process.executable:*\\narrator.exe AND (NOT process.pe.original_file_name:Narrator.exe)) OR (process.executable:*\\displayswitch.exe AND (NOT process.pe.original_file_name:DisplaySwitch.exe)) OR (process.parent.name:*\\winlogon.exe AND (process.executable:(*\\cmd.exe OR *\\powershell.exe)) AND (process.args:(*sethc.exe* OR *utilman.exe* OR *osk.exe* OR *magnify.exe* OR *narrator.exe* OR *displayswitch.exe*)))
```

## ARP Cache Enumeration via arp.exe

- **Rule:** `proc_creation_win_arp_cache_discovery.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1016

```
(process.executable:*\\arp.exe OR process.pe.original_file_name:arp.exe) AND process.args:*\-a*
```

## Windows Recovery Options Disabled via bcdedit

- **Rule:** `proc_creation_win_bcdedit_recovery_disabled.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1490

```
(process.executable:*\\bcdedit.exe OR process.pe.original_file_name:bcdedit.exe) AND (process.args:(*recoveryenabled\ no* OR *recoveryenabled	no* OR *ignoreallfailures*))
```

## Malicious File Download via Bitsadmin

- **Rule:** `proc_creation_win_bitsadmin_download.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1105

```
process.executable:*\\bitsadmin.exe AND process.args:*\/transfer*
```

## Payload Decoding via Certutil

- **Rule:** `proc_creation_win_certutil_decode.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1140

```
(process.executable:*\\certutil.exe OR process.pe.original_file_name:CertUtil.exe) AND (process.args:(*\ \-decode* OR *\ \/decode*))
```

## Data Encoded for Exfiltration via Certutil

- **Rule:** `proc_creation_win_certutil_encode_exfil_prep.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1132.001

```
(process.executable:*\\certutil.exe OR process.pe.original_file_name:CertUtil.exe) AND (process.args:(*\ \-encode* OR *\ \/encode*))
```

## Ingress Tool Transfer via Certutil URL Cache

- **Rule:** `proc_creation_win_certutil_urlcache_download.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1105

```
(process.executable:*\\certutil.exe AND (process.args:(*urlcache* OR *verifyctl*))) AND process.args:*split*
```

## Free Disk Space Wiped via cipher.exe

- **Rule:** `proc_creation_win_cipher_free_space_wipe.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1485

```
(process.executable:*\\cipher.exe OR process.pe.original_file_name:cipher.exe) AND process.args:*\ \/w*
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

## DNS Server Plugin DLL Side-Loading via dnscmd

- **Rule:** `proc_creation_win_dnscmd_serverlevelplugindll.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1574.002

```
(process.executable:*\\dnscmd.exe OR process.pe.original_file_name:dnscmd.exe) AND process.args:*serverlevelplugindll*
```

## Domain Group Discovery via Net.exe

- **Rule:** `proc_creation_win_domain_group_discovery.yml` · **level:** low · **status:** experimental · **ATT&CK:** T1087.002

```
(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.args:*group* AND process.args:*\/domain*)
```

## Locked File Copied via esentutl VSS Trick (Browser Credential Access)

- **Rule:** `proc_creation_win_esentutl_locked_file_copy.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1005

```
(process.executable:*\\esentutl.exe OR process.pe.original_file_name:esentutl.exe) AND process.args:*\ \/y\ * AND process.args:*\/vss*
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

## Network Share Enumeration via net.exe

- **Rule:** `proc_creation_win_net_share_recon.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1135

```
(process.executable:*\\net.exe OR process.executable:*\\net1.exe OR process.pe.original_file_name:net.exe OR process.pe.original_file_name:net1.exe) AND (process.args:(*\ view* OR *\ share*))
```

## Firewall Rule Added via netsh

- **Rule:** `proc_creation_win_netsh_firewall_rule_added.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1562.004

```
(process.executable:*\\netsh.exe OR process.pe.original_file_name:netsh.exe) AND (process.args:(*advfirewall\ firewall\ add* OR *firewall\ add*))
```

## Port-Proxy Relay Configured via netsh

- **Rule:** `proc_creation_win_netsh_portproxy_relay.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1090.001

```
(process.executable:*\\netsh.exe OR process.pe.original_file_name:netsh.exe) AND process.args:*portproxy\ add*
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

## PsExec Client-Side Remote Execution Launch

- **Rule:** `proc_creation_win_psexec_client_side_launch.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1569.002

```
(process.executable:*\\psexec.exe OR process.executable:*\\psexec64.exe OR process.pe.original_file_name:psexec.c) AND process.args:*\\\\*
```

## Password-Protected Archive Staging via RAR/WinRAR

- **Rule:** `proc_creation_win_rar_archive_staging.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1560.001

```
(process.executable:*\\rar.exe OR process.executable:*\\winrar.exe OR process.pe.original_file_name:rar.exe OR process.pe.original_file_name:WinRAR.exe) AND (process.args:(*.exe\ a\ * OR *.exe\"\ a\ *)) AND (process.args:(*\ \-p* OR *\ \-hp*))
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

## Existing Service Reconfigured to a New Binary Path

- **Rule:** `proc_creation_win_sc_config_binpath_change.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1543.003

```
(process.executable:*\\sc.exe OR process.pe.original_file_name:sc.exe) AND process.args:*\ config\ * AND process.args:*binpath\=*
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

## SharpHound / BloodHound AD Collection Execution

- **Rule:** `proc_creation_win_sharphound_bloodhound_collection.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1087.002

```
(process.executable:*sharphound* OR process.pe.original_file_name:*sharphound* OR process.args:*sharphound*) OR (process.args:(*\-\-collectionmethod* OR *\-CollectionMethod* OR *Invoke\-BloodHound*))
```

## Print Spooler Service Spawning a Suspicious Child Process

- **Rule:** `proc_creation_win_spooler_child_process_printnightmare.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1068

```
process.parent.name:*\\spoolsv.exe AND (process.executable:(*\\cmd.exe OR *\\powershell.exe OR *\\pwsh.exe OR *\\rundll32.exe OR *\\mshta.exe OR *\\regsvr32.exe))
```

## File Dropped into the Startup Folder

- **Rule:** `proc_creation_win_startup_folder_file_drop.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1547.001

```
(file.path:(*\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\* OR *\\AppData\\Roaming\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\*)) AND (file.path:(*.exe OR *.dll OR *.lnk OR *.bat OR *.cmd OR *.vbs OR *.js OR *.ps1 OR *.scr OR *.pif))
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

## Windows Backup Catalog or System State Backup Deleted via wbadmin

- **Rule:** `proc_creation_win_wbadmin_delete_catalog.yml` · **level:** critical · **status:** experimental · **ATT&CK:** T1490

```
(process.executable:*\\wbadmin.exe OR process.pe.original_file_name:wbadmin.exe) AND process.args:*delete* AND (process.args:(*catalog* OR *systemstatebackup*))
```

## WMI Process Call Create

- **Rule:** `proc_creation_win_wmi_process_create.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1047

```
process.executable:*\\wmic.exe AND (process.args:*process* AND process.args:*call* AND process.args:*create*)
```

## Shadow Copy Deletion via WMIC

- **Rule:** `proc_creation_win_wmic_shadowcopy_delete.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1490

```
(process.executable:*\\wmic.exe OR process.pe.original_file_name:wmic.exe) AND process.args:*shadowcopy* AND process.args:*delete*
```

## Kernel or File-System Driver Service Installed

- **Rule:** `system_win_driver_service_installed.yml` · **level:** medium · **status:** experimental · **ATT&CK:** T1068

```
winlog.event_id:7045 AND ((winlog.event_data.ServiceType:(0x1 OR 0x2)) OR (winlog.event_data.ServiceType:(*kernel* OR *file\ system\ driver*)))
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

## Remote-Style Service Creation (PsExec Pattern)

- **Rule:** `system_win_remote_service_creation_psexec_style.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1543.003

```
winlog.event_id:7045 AND winlog.event_data.ServiceName:PSEXESVC
```

## New Service Installed (Windows System 7045)

- **Rule:** `system_win_service_installed.yml` · **level:** medium · **status:** stable · **ATT&CK:** T1543.003

```
winlog.event_id:7045 AND (NOT (winlog.event_data.ImagePath:(C\:\\Windows\\System32\\* OR \"C\:\\Windows\\System32\\* OR C\:\\Windows\\SysWOW64\\* OR \"C\:\\Windows\\SysWOW64\\* OR C\:\\Program\ Files\\* OR \"C\:\\Program\ Files\\* OR C\:\\Program\ Files\ \(x86\)\\* OR \"C\:\\Program\ Files\ \(x86\)\\* OR %SystemRoot%\\* OR \"%SystemRoot%\\* OR \\SystemRoot\\* OR \\??\\C\:\\Windows\\* OR \"\\??\\C\:\\Windows\\* OR \\??\\C\:\\Program\ Files\\* OR \"\\??\\C\:\\Program\ Files\\*)))
```

## New Service Installed With a LOLBin as its Binary

- **Rule:** `system_win_suspicious_service_binpath_lolbin.yml` · **level:** high · **status:** experimental · **ATT&CK:** T1543.003

```
winlog.event_id:7045 AND (winlog.event_data.ImagePath:(*cmd.exe* OR *powershell.exe* OR *rundll32.exe* OR *mshta.exe* OR *regsvr32.exe* OR *wscript.exe* OR *cscript.exe*))
```

## Suspicious WMI Event Filter-to-Consumer Binding (WMI-Activity 5861)

- **Rule:** `wmi_win_event_subscription_binding.yml` · **level:** high · **status:** stable · **ATT&CK:** T1546.003

```
winlog.event_id:5861 AND (winlog.event_data.Operation:*PutInstance* AND winlog.event_data.Operation:*FilterToConsumerBinding*)
```

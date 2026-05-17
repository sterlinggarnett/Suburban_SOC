Rule Technique Name MITRE ID Tactic

1 Command & Scripting Interpreter:PowerShell T1059.001 Execution
2 OS Credential Dumping: LSASS Memory T1003.001 Credential Access
3 Indicator Removal on Host: Clear Windows Event Logs T1070.001 Defense Evasion
4 Scheduled Task/Job: Scheduled Task T1053.005 Execution / Persistence
5 System Owner/User Discovery T1033 Discovery
6 System Binary Proxy Execution: Regsvr32 T1218.010 Defense Evasion
7 Ingress Tool Transfer (Bitsadmin) T1105 Command and Control
8 Windows Management Instrumentation (WMI) T1047 Execution
9 Create Account: Local Account T1136.001 Persistence
10 Hijack Execution Flow (RDP Session Hijacking) T1574 Privilege Escalation / Lateral Movement

Incident Response Playbook


This playbook provides a structured methodology to respond to alerts triggered by the Sigma
rules documented above.
1. Preparation & Triage
• 
• 
• 
Validate the Alert: Verify if the activity aligns with known IT administrative tasks,
scheduled patching, or approved software deployments (e.g., admin scripts running 
powershell.exe -enc).
Identify Context: Identify the affected endpoint(s), the user account associated with
the process, and the exact timestamp.
Examine Process Lineage: Look at the parent and child processes. For example, a
web server process spawning cmd.exe which then spawns powershell.exe is
highly suspicious.
2. Investigation & Analysis
• 
• 
• 
• 
• 
Payload Decoding: For PowerShell alerts (Rule 1), extract and decode the Base64
payload to understand the script's intent.
Credential & Session Assessment: If LSASS dumping (Rule 2) or RDP hijacking (Rule
10) occurs, assume credentials are compromised. Monitor immediately for lateral
movement or unusual authentication events originating from the host.
Evaluate Persistence: Review parameters for newly created Scheduled Tasks (Rule 4)
or Local Accounts (Rule 9). Identify the schedule frequency and the exact binary/
script being executed.
Network Connections: If tools like Regsvr32 (Rule 6) or Bitsadmin (Rule 7) fired,
check network logs for the remote C2 IP addresses, domains, and the nature of the
downloaded payloads.
Log Auditing: If local event logs were cleared (Rule 3), pivot to central SIEM logs or
EDR telemetry to reconstruct the missing timeline.
3. Containment
• 
• 
• 
Endpoint Isolation: Quarantine the compromised host from the network using EDR
functionality or network NACs to prevent lateral movement.
Account Suspension: Disable the compromised Active Directory user accounts, as
well as any newly discovered local accounts (Rule 9).
Perimeter Blocking: Block malicious C2 IP addresses or domains identified during
the investigation at the perimeter firewalls and web proxies.
4. Eradication & Remediation
• 
• 
• 
• 
Terminate Processes: Kill active malicious RDP sessions, background PowerShell
tasks, or unauthorized WMI processes.
Remove Artifacts: Delete malicious scheduled tasks, unauthorized registry
modifications, and dropped payload files.
Credential Reset: Force an immediate password reset for all user accounts that were
exposed on the compromised host, especially if LSASS was accessed.
System Scans: Run deep anti-virus and EDR scans to ensure all residual malware
components are removed.
5. Recovery & Post-Incident Activity
• 
• 
• 
Restore & Reconnect: Reconnect the endpoint to the network only once it is verified
clean. Reimage the machine if deep persistence or rootkits are suspected.
Rule Tuning: Update the Sigma rule falsepositives or exclusions list if the alert
was triggered by a legitimate, newly deployed administrative tool to prevent future
alert fatigue.
Root Cause Analysis: Conduct a post-mortem to determine how the initial execution
was achieved (e.g., phishing, exposed RDP, exploitation) and close the vulnerability.

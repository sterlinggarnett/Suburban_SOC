# Suburban-SOC Detection Engineering: KQL Translation Matrix\n\nThis document contains automated KQL translations generated directly from platform-agnostic Sigma rules using the Elastic Common Schema (ECS) data model.\n\n### LSASS Memory Dump via Comsvcs.dll
id: 22222222-2222-2222-2222-222222222222
status: experimental
description: Detects the use of rundll32.exe to execute the MiniDump function of comsvcs.dll to dump LSASS memory.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs.dll'
            - 'MiniDump'
    condition: selection
falsepositives:
    - Rare legitimate debugging operations.
level: high
tags:
    - attack.credential_access
    - attack.t1003.001\n**Sigma File:** `proc_creation_win_lsass_dump.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\rundll32.exe AND (process.command_line:*comsvcs.dll* AND process.command_line:*MiniDump*)\n```\n---\n\n### Clearing Windows Event Logs via Wevtutil
id: 33333333-3333-3333-3333-333333333333
status: experimental
description: Detects the use of wevtutil.exe to clear event logs.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wevtutil.exe'
        CommandLine|contains:
            - ' cl '
            - ' clear-log '
    condition: selection
falsepositives:
    - IT admin cleanup scripts.
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.001\n**Sigma File:** `proc_creation_win_clear_event_logs.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\wevtutil.exe AND (process.command_line:(*\ cl\ * OR *\ clear\-log\ *))\n```\n---\n\n### Scheduled Task Creation via Schtasks
id: 44444444-4444-4444-4444-444444444444
status: experimental
description: Detects the creation of a new scheduled task using schtasks.exe.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/create'
            - '/tn'
    condition: selection
falsepositives:
    - Software installations and updates.
    - Legitimate administrative tasks.
level: low
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.005\n**Sigma File:** `proc_creation_win_scheduled_task.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\schtasks.exe AND (process.command_line:*\/create* AND process.command_line:*\/tn*)\n```\n---\n\n### Suspicious System Owner/User Discovery
id: 55555555-5555-5555-5555-555555555555
status: experimental
description: Detects the execution of whoami.exe with the /all flag, commonly used by attackers for reconnaissance.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
        CommandLine|contains: '/all'
    condition: selection
falsepositives:
    - Administrator troubleshooting.
level: medium
tags:
    - attack.discovery
    - attack.t1033\n**Sigma File:** `proc_creation_win_user_discovery.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\whoami.exe AND process.command_line:*\/all*\n```\n---\n\n### Regsvr32 Execution from Remote Server
id: 66666666-6666-6666-6666-666666666666
status: experimental
description: Detects regsvr32.exe attempting to execute a remote script, known as the Squiblydoo bypass.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all:
            - '/i:http'
            - 'scrobj.dll'
    condition: selection
falsepositives:
    - Highly unlikely.
level: critical
tags:
    - attack.defense_evasion
    - attack.t1218.010\n**Sigma File:** `proc_creation_win_regsvr32_remote_sct.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\regsvr32.exe AND (process.command_line:*\/i\:http* AND process.command_line:*scrobj.dll*)\n```\n---\n\n### Malicious File Download via Bitsadmin
id: 77777777-7777-7777-7777-777777777777
status: experimental
description: Detects the use of bitsadmin.exe to download files via the /transfer switch.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\bitsadmin.exe'
        CommandLine|contains: '/transfer'
    condition: selection
falsepositives:
    - Legitimate background update processes.
level: medium
tags:
    - attack.command_and_control
    - attack.t1105\n**Sigma File:** `proc_creation_win_bitsadmin_download.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\bitsadmin.exe AND process.command_line:*\/transfer*\n```\n---\n\n### WMI Process Call Create
id: 88888888-8888-8888-8888-888888888888
status: experimental
description: Detects the use of WMIC to create a new process, a common technique for local or remote execution.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'process'
            - 'call'
            - 'create'
    condition: selection
falsepositives:
    - Legitimate remote administration.
level: medium
tags:
    - attack.execution
    - attack.t1047\n**Sigma File:** `proc_creation_win_wmi_process_create.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\wmic.exe AND (process.command_line:*process* AND process.command_line:*call* AND process.command_line:*create*)\n```\n---\n\n### Local User Account Creation via Net.exe
id: 99999999-9999-9999-9999-999999999999
status: experimental
description: Detects the creation of a local user account using the net user command.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\n**Sigma File:** `proc_creation_win_local_acct_create.yml`  \n**Target Query (KQL):**\n```text\n(process.executable:(*\\net.exe OR *\\net1.exe)) AND (process.command_line:*user* AND process.command_line:*\/add*)\n```\n---\n\n### RDP Session Hijacking via Tscon
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
status: experimental
description: Detects the use of tscon.exe to hijack an RDP session by passing a destination session ID.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\tscon.exe'
        CommandLine|contains: '/dest:'
    condition: selection
falsepositives:
    - IT administrators forcefully connecting to specific sessions.
level: high
tags:
    - attack.privilege_escalation
    - attack.lateral_movement
    - attack.t1574\n**Sigma File:** `proc_creation_win_rdp_hijack_tscon.yml`  \n**Target Query (KQL):**\n```text\nprocess.executable:*\\tscon.exe AND process.command_line:*\/dest\:*\n```\n---\n\n
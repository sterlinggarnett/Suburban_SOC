# Windows Event Logging STIG Baseline (Issue #205)
# This script configures Advanced Audit Policy to generate the necessary Event IDs
# (e.g., EID 4624, 4625, 4688) for the Suburban-SOC ECS pipeline.

echo "Applying STIG Advanced Audit Policy Configuration..."

# Process Creation (4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Logon/Logoff (4624, 4625, 4634, 4647)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable

# Account Management (4720, 4722, etc.)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Object Access (File Shares, Registry)
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:disable

# Firewall rule additions (4946) — #283, closes the New-NetFirewallRule
# PowerShell-cmdlet blind spot proc_creation_win_netsh_firewall_rule_added.yml
# has. NOT on by default, unlike most subcategories above.
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:disable

echo "Enable Command Line Auditing for EID 4688..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

echo "Configuration complete. Ensure Winlogbeat is installed and configured to read the Security channel."

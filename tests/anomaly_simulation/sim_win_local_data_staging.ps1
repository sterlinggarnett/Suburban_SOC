<#
  Suburban-SOC :: Windows Emulation -- Recursive Document Copy Into a Staging Path
  ATT&CK : T1074.001 (Collection)
  Detects: rules/sigma/proc_creation_win_local_data_staging.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible -- it stages a handful of
  throwaway placeholder documents under the user's own profile, robocopies them
  into C:\Users\Public (matching the rule's own staging-path signal), then
  removes both the source and staged copies.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1074.001 -- Local Data Staging"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_local_data_staging.yml"

$src = Join-Path $env:TEMP "SuburbanSOCEmu\src"
$dst = "C:\Users\Public\SuburbanSOCEmuStaged"
New-Item -ItemType Directory -Path $src -Force | Out-Null
"placeholder" | Out-File (Join-Path $src "report.docx")
"placeholder" | Out-File (Join-Path $src "budget.xlsx")
"placeholder" | Out-File (Join-Path $src "notes.pdf")

Write-Host "[*] Staging documents via robocopy into $dst"
robocopy $src $dst *.docx *.xlsx *.pdf /E | Out-Null

Write-Host "[*] Cleaning up (reversible)."
Remove-Item -Path $src -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $dst -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[+] Emulation complete."

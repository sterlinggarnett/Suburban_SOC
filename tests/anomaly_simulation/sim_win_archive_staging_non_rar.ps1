<#
  Suburban-SOC :: Windows Emulation -- Password-Protected/Staged Archive via
  7-Zip, MakeCab, or Tar
  ATT&CK : T1560.001 (Collection)
  Detects: rules/sigma/proc_creation_win_archive_staging_non_rar.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with Sysmon + winlogbeat
  shipping process-creation telemetry (Sysmon EID 1 / Security 4688).
  All actions in this script are benign / reversible -- it archives one
  throwaway placeholder file and removes every artifact afterward.
  Exercises BOTH branches: 7-Zip with a password flag (if 7z.exe is present --
  skipped, not failed, otherwise, since it's a third-party install this repo
  cannot assume), and makecab.exe (bundled on every Windows host) staging into
  a public path.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1560.001 -- Archive Staging (non-RAR)"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: proc_creation_win_archive_staging_non_rar.yml"

$work = Join-Path $env:TEMP "SuburbanSOCEmuArchive"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$src = Join-Path $work "data.txt"
"placeholder" | Out-File $src

# --- selection_7z branch (password flag) ---
$sevenZip = Get-Command "7z.exe" -ErrorAction SilentlyContinue
if ($sevenZip) {
    $archive7z = Join-Path $work "archive.7z"
    & $sevenZip.Source a -pSuburbanSOCEmu123 $archive7z $src | Out-Null
    Write-Host "[*] 7z.exe password-protected archive created (selection_7z branch)."
    Remove-Item -Path $archive7z -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "[!] 7z.exe not found on PATH -- skipping the 7z branch (not a failure; it's a third-party install)."
}

# --- selection_makecab_tar branch (staging path, no password concept) ---
$dst = "C:\Users\Public\SuburbanSOCEmuCab"
New-Item -ItemType Directory -Path $dst -Force | Out-Null
$cab = Join-Path $dst "data.cab"
makecab.exe $src $cab | Out-Null
Write-Host "[*] makecab.exe staged a CAB into C:\Users\Public (selection_makecab_tar branch)."

Write-Host "[*] Cleaning up (reversible)."
Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $dst -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[+] Emulation complete."

<#
  Suburban-SOC :: Windows Emulation -- PowerShell Clipboard Access
  ATT&CK : T1115 (Collection)
  Detects: rules/sigma/posh_ps_clipboard_capture.yml
  -----------------------------------------------------------------------------
  LAB USE ONLY. Run on an isolated, disposable test host with the "Turn on
  PowerShell Script Block Logging" Group Policy enabled (EventID 4104) and
  winlogbeat shipping it. All actions in this script are benign / reversible --
  it reads whatever is already on the clipboard (or nothing, if empty) and
  never modifies it.
  Exercises BOTH detection branches: the native Get-Clipboard cmdlet, and the
  older Add-Type/user32/GetClipboardData P/Invoke pattern.
#>
[CmdletBinding()]
param([switch]$Armed)
$ErrorActionPreference = 'Continue'
Write-Host "[*] Suburban-SOC emulation: T1115 -- PowerShell Clipboard Access"
Write-Host ("[*] Mode: " + $(if ($Armed) {'ARMED'} else {'SAFE (default)'}))
Write-Host "[*] Maps to: posh_ps_clipboard_capture.yml"

# --- selection_cmdlet branch ---
$clip = Get-Clipboard -ErrorAction SilentlyContinue
Write-Host ("[*] Get-Clipboard returned " + $(if ($clip) {"$($clip.Length) line(s)"} else {'nothing (clipboard empty or inaccessible)'}))

# --- selection_winapi branch: reference user32/GetClipboardData without
# actually invoking it destructively -- the rule matches on the ScriptBlockText
# reference itself (P/Invoke declaration), not a successful clipboard read, so
# defining the signature is sufficient telemetry and needs no interactive
# desktop session (unlike Get-Clipboard, which can fail non-interactively).
Add-Type -MemberDefinition @'
[DllImport("user32.dll")]
public static extern IntPtr GetClipboardData(uint uFormat);
'@ -Name Win32ClipboardEmu -Namespace SuburbanSOCEmu -ErrorAction SilentlyContinue | Out-Null
Write-Host "[*] Declared user32.dll GetClipboardData P/Invoke signature (selection_winapi branch)."

Write-Host "[+] Emulation complete."

---
name: triage
description: Use whenever analyzing alert logs (Zeek, Sysmon, Suricata) to determine
  true vs false positive. Enforces verbatim evidence quoting before any assessment.
---
Triage the alert using the Zeek/Sysmon logs in: $ARGUMENTS

1. Extract the exact log lines (verbatim) relevant to this alert.
2. Based only on those quoted lines, assess true positive vs false positive.
3. Cite the supporting quoted line for every claim.
4. If evidence is insufficient either way, output "insufficient evidence" — do not guess.
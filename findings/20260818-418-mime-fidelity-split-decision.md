# #418 — mime_type base-rate flattening: documented decision

## Scope

`net_zeek_executable_download.yml` (`level: low`) and
`net_zeek_smtp_attachment_executable.yml` (`level: medium`) each carry a
single 10-entry `mime_type` OR-list spanning wildly different real-world
base rates — routine shell-script/binary downloads sit in the same flat
block as a bare `.lnk` (T1204.002) or Mach-O binary, both near-zero-base-rate
in most environments. #384's review flagged that a tuning pass aimed at the
high-base-rate entries risks suppressing the whole rule, high-fidelity
entries included, and #418 asked for either a severity-split sibling rule or
an explicit per-entry fidelity note.

## Decision

**Not split into a sibling rule** — a split would require
`tests/detections/test_sigma_detections.py`'s
`test_zeek_executable_and_smtp_rules_share_the_exact_same_mime_type_list`
sync-invariant to be rethought for a partial split (it currently asserts
the two rules' lists are identical, in order), and a new rule pair adds
maintenance surface for a tuning concern that a documentation fix already
resolves. Took the issue's own "at minimum" fallback instead: documented
per-entry fidelity directly in both rules' descriptions so a tuning
decision can be made per-entry.

- **High-fidelity** (near-zero legitimate base rate — do not suppress when
  tuning shell-script/routine-binary noise out of either rule):
  `application/x-ms-shortcut` (bare LNK, T1204.002 — bare-file delivery
  only, per the rule's own LNK-entry caveat), `application/x-mach-o-executable`
  (macOS-targeted payload).
- **Low-fidelity / high-base-rate** (the routine provisioning-script and
  ordinary-binary traffic each rule's `falsepositives` block already
  describes): `application/x-dosexec`, `application/x-executable`,
  `application/x-sharedlib`, `text/x-shellscript`, `text/x-python`,
  `text/x-perl`, `text/x-ruby`, `text/x-msdos-batch`.

## Fix

- `rules/sigma/net_zeek_executable_download.yml`: closed the open "filed as
  #418" thread with the decision and per-entry fidelity list above.
- `rules/sigma/net_zeek_smtp_attachment_executable.yml`: added the same
  fidelity breakdown (identical mime_type list, same base-rate finding),
  pointing to the HTTP sibling's description as the source of record.

No detection logic, `mime_type` list, tags, or `level` changed on either
rule — description-only. Confirmed via
`tests/detections/test_sigma_detections.py::...share_the_exact_same_mime_type_list`
(still passes; it only checks the `mime_type` array) and the full
`pytest tests/` run (955 passed, only the `sigma`-CLI-dependent
`test_live_fire.py` excluded — pre-existing, unrelated to this environment).

# #410 — SMTP rule titles now disclose plaintext-only scope

## Scope
Both `rules/sigma/net_zeek_smtp_attachment_executable.yml` and
`rules/sigma/net_zeek_smtp_mass_outbound.yml` carry a real, load-bearing
scope caveat buried in their `description:` block: Zeek's file-extraction/
protocol-analysis framework can only see SMTP session content in
PLAINTEXT. Any session using STARTTLS or implicit TLS (the default for
SMTP submission on 587/465 on essentially every modern mail client) is
completely opaque to these rules — despite both carrying ATT&CK tags
(T1566.001, T1071.003) that read as blanket technique coverage in every
downstream rendering that shows only title+tags (generated docs, a Kibana
rule list, the ATT&CK-coverage SLO count).

## Fix
Moved the scope caveat into the rule title itself — the one field every
downstream rendering keeps:
- `Executable Payload Sent as an Email Attachment (Zeek Files)` → `...
  (Zeek Files) — Plaintext SMTP Only`
- `SMTP Session with an Anomalously Deep Transaction Count` → `... —
  Plaintext SMTP Only`

Confirmed via repo-wide grep before starting: only the 2 rule files and 3
generated docs referenced the old exact title strings; no
emulation_telemetry.map/coverage_checklist.md/dashboard reference either
rule by title, filename, or UUID. Regenerated
`docs/detections/SIEM_KQL_Documentation.md` and
`attack-coverage.{md,json}` under the pinned `python:3.11.15` toolchain.

## Parallel review (security-auditor + code-reviewer)

**code-reviewer** — approve. Found one Should-Fix: the new title's segment
ordering (`— Plaintext SMTP Only (Zeek Files)`) put the new caveat before
the `(Zeek Files)` logsource-tag suffix, breaking the repo's own
convention of keeping that parenthetical trailing (confirmed against 3
other `(Zeek X)`-suffixed titles). Fixed — reordered to `(Zeek Files) —
Plaintext SMTP Only`. Also independently caught (matching a security-
auditor finding below) that `net_zeek_smtp_mass_outbound.yml`'s
description falsely attributes "outbound" to the rule's *title* when it's
only ever been in the *filename* — pre-existing, directly adjacent to the
lines this PR touches. Fixed. Flagged two out-of-scope sibling cases
(rules with a similar description-only scope caveat) — one
(`net_zeek_dns_doh_non_standard.yml`, blind to hardcoded-IP DoH clients)
filed as [#426](https://github.com/voltron-1/Suburban_SOC/issues/426),
milestoned M17; the other
(`net_zeek_executable_download.yml`, already partially self-disclosed via
"Over HTTP") judged not worth a separate issue.

**security-auditor** — approve as scoped, zero Must/High findings.
Exhaustively confirmed no consumer in the repo keys on rule title text
(all key by filename or Sigma `id:` — checked every script that touches
rule titles); title length (81/77 chars) is well inside an
already-shipped envelope (an existing title runs ~120 chars); the ATT&CK-
coverage SLO count is provably title-independent (counts array length,
confirmed by reading `slo_metrics.py`); the em dash character is already
safely round-tripping through the toolchain via 3 other shipped titles.
Independently found and fixed the same "title says outbound" bug
code-reviewer caught. Surfaced 3 out-of-scope pre-existing issues, all
filed and milestoned:
- [#424](https://github.com/voltron-1/Suburban_SOC/issues/424) (M20,
  MEDIUM) — hardcoded ntfy notification titles containing an em dash
  likely raise `UnicodeEncodeError` against `http.client`'s latin-1
  header encoding, silently dropping the "Response DRAFTED — approval
  required" push with no alert-on-alert-failure. Confirmed no Sigma rule
  title reaches this code path (both call sites are hardcoded literals),
  so out of scope for this PR.
- [#425](https://github.com/voltron-1/Suburban_SOC/issues/425) (M17,
  LOW) — `build_attack_coverage.py`'s `_merged_comment()` uses ` — ` as a
  title↔rule delimiter, which an em-dash-containing title can collide
  with in a multi-rule technique grouping. Already live on `main`
  (pre-existing, not worsened by this diff — both new titles are
  single-rule groups).
- Unpinned `sigma-cli`/`pysigma-backend-elasticsearch` in
  `.github/workflows/detections.yml` — already tracked as
  [#330](https://github.com/voltron-1/Suburban_SOC/issues/330) (M19), no
  duplicate filed.

## Verification
- `tests/detections`: 58 passed, 72 subtests passed.
- `tests/detections tests/dashboards tests/hunts tests/pipeline tests/rbac
  tests/validate_emulation_map.py`: 267 passed, 80 subtests passed — no
  regressions, before and after applying both reviews' findings.
- `docs/detections/SIEM_KQL_Documentation.md` /
  `attack-coverage.{md,json}` regenerated and confirmed to carry the
  final (post-reorder) title strings identically across all 3 artifacts.
- Repo-wide grep confirmed zero stale references to either old title
  string after the fix.

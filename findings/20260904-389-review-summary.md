# #389 — review summary and dispositions (2026-09-04)

Branch `389-zeek-log-field-string-cap`. Three parallel reviews per CLAUDE.md; the
tester-debugger wrote its own file (`20260904-389-tester-debugger.md`), the other two
returned inline and are summarized here with what was done about each item.

## security-auditor — 1 HIGH / 3 MEDIUM / 3 LOW / 1 INFO

| Sev | Finding | Disposition |
|---|---|---|
| HIGH | A Zeek cap above `dns.answers` `ignore_above:8191` leaves Zeek-logged answers in (8191, cap] stored but unindexed → `net_zeek_dns_txt_answer_abuse.yml` silent for that range; the old 4096 cut kept every answer indexable | **Accepted → redesign.** Cap pinned to exactly 8191 (= ceiling). Lockstep test asserts `cap == ignore_above`. Raising both together (needs an array-aware clamp) filed as #545 (M18) |
| MEDIUM | Guards grep an identifier that also appears in config.zeek comments — prove neither presence nor value | **Fixed.** All 4 guards grep `^redef Log::default_max_field_string_bytes = 8191;`; simulated fresh/stale/comment-only/wrong-value copies |
| MEDIUM | Only image evidence is a skip-able test in a non-required job | **Fixed.** `SOC_REQUIRE_LIVE_ZEEK=1` in the live-fire step turns an unusable environment into an error |
| MEDIUM | Global raise = per-field amplification bounded by an unpinned 256000 total | **Partly fixed.** Now 2x (not 4x); live test 4 pins field (4096) and total (256000) defaults on the image. Disk-usage SLO metric noted in #545, not built |
| LOW | `pipeline.dns_answer_truncated_by_zeek` had no consumer | **Fixed.** `metric_dns_answer_truncated_by_zeek_count`, target 0, wired + tested |
| LOW | Weird sampling is a deliberate-suppression lever | **Documented** in the weird metric's docstring; paired with the unsampled tag metric |
| LOW | Multibyte mid-character cut untested | **Added** live test 5 (weird must fire; parse/length recorded) |
| INFO | Verified negatives (no ruby exception path from dropping `valid_encoding?`; `terms` on `name` scoped by `event.dataset`; weird.log shipped; version guard correct; no secrets/PII). Nit: "characters" → "bytes" in the troubleshooting row | **Nit fixed** |

## code-reviewer — 0 must-fix, 2 should-fix (both applied)

1. Live test hardcoded the 8191 ceiling → now read from the template.
2. No direct assertion tying the mirror constant to config.zeek → added (mutation-checked).

Also confirmed: guard precedence, #288 regex budgets (367–388 chars < 400), packet
construction, and that all remaining "4096"/"DNS analyzer" mentions are historical.

## tester-debugger — 5/5 checks passed

See `20260904-389-tester-debugger.md`. One correction applied: config.zeek's comment quoted
the wrong 8.0.5 error text (a bare redef fails with `"redef" used but not previously defined`).

## security-auditor re-check of the redesign — all 7 dispositions hold, 1 new MEDIUM (fixed)

- Items 1–7 above verified against the current files (cap == `ignore_above`, an 8191-byte cut
  answer is indexed and cannot exceed 8191 UTF-16 units, guards anchored on the active line,
  env gate + CI env, image bounds pinned, metric wired with target 0, suppression documented,
  multibyte test asserts only the weird).
- **New MEDIUM:** the target-0 `dns_answer_truncated_by_zeek_count` used the shared 7-day
  `WINDOW`, so one forged exact-cap record via `:5514` would page for ~672 consecutive runs;
  its precedent `zeek_path_nomatch_count` deliberately uses its own 1-hour window. **Fixed:**
  own `SLO_DNS_ANSWER_TRUNCATED_WINDOW` (default `now-1h`) + a decoupling test.
- Stale-doc note: `20260904-389-tester-debugger.md` describes the pre-redesign 16384 value;
  annotated with a header note rather than rewritten.

> **Note (added after the fact):** this evidence was gathered against the FIRST draft of the
> fix, which set `Log::default_max_field_string_bytes = 16384`. The security-auditor review
> then had the cap redesigned to **8191** (= `dns.answers` `ignore_above`) — see
> `20260904-389-review-summary.md`. Every check below (version guard, pcap replays on the
> native 8.0.5, guard fixtures, suites, mutation test) was re-run by the main session after
> the redesign with the 8191 value and passed identically; the numbers quoted below are the
> pre-redesign ones and are kept verbatim as the record of what this agent observed.

# #389 tester-debugger validation — Zeek `Log::default_max_field_string_bytes` cap fix

Date: 2026-09-04
Branch under test: `389-zeek-log-field-string-cap` (uncommitted working tree)
Environment: native Zeek 8.0.5 at `/opt/zeek/bin/zeek` (pre-8.1, no
`Log::default_max_field_string_bytes` identifier), Python 3.12, no Docker
daemon, no scapy. All scratch work under
`/tmp/claude-1000/-home-tjlam-projects-Suburban-SOC/46e53f36-8edb-435a-b51a-76b4d8b94861/scratchpad/tester/`.
No repo files were modified by this validation.

Claimed behavior (one sentence): `configs/intel/config.zeek` raises Zeek's
per-string logging cap from the 4096-byte upstream default to 16384 bytes
(version-guarded to Zeek >=8.1.0 so it doesn't break the still-in-use 8.0.5
native binary), and `configs/logstash.conf` / the 4 real capture invocations'
staleness guards / the two new test files enforce that value stays in
lockstep everywhere it's referenced.

---

## Check 1 — version guard on native 8.0.5

**Command:**
```
/opt/zeek/bin/zeek -a configs/intel/config.zeek
```
(`-a`/`--parse-only`, confirmed via `zeek --help`: "exit immediately after
parsing scripts")

**Output:** (no stdout/stderr)
**Exit code:** 0

**Proving the guard is load-bearing:** copied `configs/intel/config.zeek` to
scratch (`check1/config_unguarded.zeek`), deleted only the two guard lines
(`@if ( Version::number >= 80100 )` and `@endif`) via
`sed -i '/^@if ( Version::number >= 80100 )$/d; /^@endif$/d'`, confirmed via
`diff` that only those 2 lines were removed and the bare `redef` line
remains, then:
```
cd .../scratchpad/tester/check1
/opt/zeek/bin/zeek -a config_unguarded.zeek
```
**Output:**
```
error in ./config_unguarded.zeek, line 87: "redef" used but not previously defined (Log::default_max_field_string_bytes)
```
**Exit code:** 1

**Surprise / discrepancy:** config.zeek's own comment (and this task's
step 1) both say the pre-8.1 failure mode is `"unknown identifier
Log::default_max_field_string_bytes"`. That exact string only reproduces for
a **`print`/read** use of the identifier — verified separately:
```
echo 'print Log::default_max_field_string_bytes;' > probe_identifier.zeek
/opt/zeek/bin/zeek -a probe_identifier.zeek
# error in ./probe_identifier.zeek, line 1: unknown identifier Log::default_max_field_string_bytes, at or near "Log::default_max_field_string_bytes"
```
For a **`redef`** of an unknown identifier (the actual construct used in
config.zeek), Zeek 8.0.5 instead emits `"redef" used but not previously
defined (Log::default_max_field_string_bytes)`. Both are genuine parse
FATALs (exit 1, whole file rejected) — the guard's protective effect is real
and confirmed — but the code comment's exact quoted error text does not
match what `redef` actually produces on 8.0.5. Not a functional bug, but the
comment in `configs/intel/config.zeek` (lines 82-83) should be corrected to
avoid misleading a future reader who greps logs for the wrong string.

**Verdict: PASS**, with one doc-accuracy note (wrong error string quoted in
the comment).

---

## Check 2 — pcap builder + native-8.0.5 replay (10k / 20k TXT answers)

Imported `write_txt_pcap`/`_txt_chunks` from
`tests/detections/test_zeek_log_field_string_cap_live.py` via
`importlib.util.spec_from_file_location` (no repo edits). Built:
- `txt_10k.pcap`: 40 chunks x 250 bytes = 10,000 content bytes
- `txt_20k.pcap`: 80 chunks x 250 bytes = 20,000 content bytes

Note: mid-session the live test file changed on disk by 2 characters (a
lint-only loop-variable rename `l`→`label` inside `_dns_name`, functionally
identical — confirmed via diff of the function body). No re-import was
needed; behavior unaffected.

**Commands (each in its own fresh scratch cwd, NATIVE zeek, no repo
config.zeek loaded — this reproduces upstream/pre-fix behavior since 8.0.5
has no cap at all):**
```
cd check2/out_10k && /opt/zeek/bin/zeek -C -r ../txt_10k.pcap LogAscii::use_json=T
cd check2/out_20k && /opt/zeek/bin/zeek -C -r ../txt_20k.pcap LogAscii::use_json=T
```
**Exit codes:** 0 / 0

**Results (parsed dns.log JSON, answers[0]):**

| pcap | answers[0] byte length | starts "TXT " | ends with last chunk's letter run | weird.log present |
|---|---|---|---|---|
| txt_10k.pcap | 10359 | True | `...NNNNNNNNNN` (last chunk = 'N') | **No** (file not created) |
| txt_20k.pcap | 20719 | True | `...BBBBBBBBBB` (last chunk = 'B') | **No** (file not created) |

Both answers came through **in full** (no truncation) — matches the
expectation stated in the task: on 8.0.5 there is no
`Log::default_max_field_string_bytes` cap at all, so no truncation and no
`log_string_field_truncated` weird occurs regardless of size. This is the
correct negative control: it confirms the truncation behavior the live test
(`test_zeek_log_field_string_cap_live.py`) exercises against the pinned
8.2.1 image is genuinely absent pre-8.1, not an artifact of test tooling.

**Verdict: PASS.**

---

## Check 3 — guard-logic extraction and substitution tests

### 3a. `configs/systemd/zeek-host-capture.service` ExecStartPre (line 303)

Extracted the exact `bash -c '...'` payload for the line containing
`capture-loss` via a small Python regex (`^ExecStartPre=/bin/bash -c '(.*)'$`),
saved verbatim to `check3/payload_orig.sh`. Rewrote only paths: `/storage/PCAP/intel`
→ a scratch dir, `${SOC_REPO}` → a scratch "repo" root (two variants below),
via `sed`.

Built two fake repo trees mirroring `configs/intel/{config.zeek,
data/intel.dat, intel.seed.dat}`:
- `repo_valid`: copy of the **current working-tree** `config.zeek` (has the
  #389 redef)
- `repo_stale`: `git show HEAD:configs/intel/config.zeek` (the pre-#389
  version — has `capture-loss` but no `Log::default_max_field_string_bytes`
  redef, confirmed via `grep -c`)

**Scenario A (fresh/valid repo → target dir A):**
```
bash -c "$(rewritten payload, SOC_REPO=.../repo_valid, target=.../storage_intel_A)"
```
Exit code: **0**. Deployed `config.zeek` contains the redef line
(`redef Log::default_max_field_string_bytes = 16384;`).

**Scenario B (stale repo → target dir B):**
```
bash -c "$(rewritten payload, SOC_REPO=.../repo_stale, target=.../storage_intel_B)"
```
Output:
```
FATAL: deployed config.zeek is missing an expected at-load line or the #389 Log redef - stale copy
```
Exit code: **1**. Deployed `config.zeek` has no redef line (`grep` finds
nothing).

### 3b. `scripts/setup/stream_capture.sh` if-block (lines 63-66)

Extracted the 4-line `if ! sudo grep ... || ! sudo grep ...; then ... fi`
block verbatim via `sed -n '63,66p'`. Rewrote: dropped `sudo` (`sed
's/sudo //g'`), and pointed `/storage/PCAP/intel` at the same
`storage_intel_A` / `storage_intel_B` dirs from 3a (already populated with
valid/stale `config.zeek`, so this doubles as a cross-check that both
guards agree on the same fixtures).

**Against valid config (dir A):** block does not fire, exit 0 (no output).
**Against stale config (dir B):**
```
[FATAL] .../storage_intel_B/config.zeek is missing an expected @load or the #389 Log redef -- the intel config copy above may have failed silently. Refusing to stream against a config that might not match the repo.
```
Exit code: **1**.

**Verdict: PASS.** Both guards (systemd unit's ExecStartPre and
stream_capture.sh) correctly pass a config carrying the #389 redef and
correctly hard-fail with the documented FATAL message + exit 1 on a stale
pre-#389 config, using the real git HEAD content as the "stale" fixture
(not a synthetic string).

---

## Check 4 — test suite runs

| Suite | Command | Result |
|---|---|---|
| pipeline | `python3 -m pytest tests/pipeline -q -p no:cacheprovider` | **308 passed, 24 subtests passed** |
| slo_metrics | `python3 -m pytest tests/ai_agent/test_slo_metrics.py -q -p no:cacheprovider` | **199 passed, 10 subtests passed, 1 failed** (see below) |
| sigma + rule hygiene | `python3 -m pytest tests/detections/test_sigma_detections.py tests/detections/test_rule_description_hygiene.py -q -p no:cacheprovider` | **57 passed, 40 subtests passed** |
| #389 live (Docker-gated) | `python3 -m pytest tests/detections/test_zeek_log_field_string_cap_live.py -rs -q -p no:cacheprovider` | **3 skipped**, reason: `Docker daemon not reachable (docker version failed)` — clean skip, not error |
| #389 static lockstep (for context, not explicitly requested but part of this changeset) | `python3 -m pytest tests/pipeline/test_zeek_log_field_string_cap.py -q -p no:cacheprovider` | **6 passed, 4 subtests passed** |

**The one slo_metrics failure — confirmed environmental, not a code bug:**
`PrivilegeSelfCheckMainIntegrationTests::test_precheck_success_does_not_affect_a_healthy_run`
fails with `AssertionError: 2 != 0` because `coverage_techniques` reads
`12.0` (mocked) against a target of `>=35.0` → BREACH.

Root-caused without stashing anything:
- `scripts/setup/ai_agent/slo_metrics.py:146`: `"coverage_techniques":
  float(os.environ.get("SLO_COVERAGE_MIN", "10"))`
- `scripts/setup/.env` (present, not gitignored-missing) sets
  `SLO_COVERAGE_MIN=35` — loaded into `os.environ` at import time via
  `env_loader.load_env_file(ENV)`, so the module-level `TARGETS` dict
  resolves to 35.0 in this environment.
- `tests/ai_agent/test_slo_metrics.py`'s `_mock_all_metrics(mttd=0.0,
  mttr=0.0, coverage=12.0, ...)` hardcodes a mock default of 12.0.
- `git diff tests/ai_agent/test_slo_metrics.py` confirms `coverage=12.0` is
  an **unchanged context line** in this branch's diff — this changeset does
  not touch that default, and it has nothing to do with #389. The 12.0
  default predates the local `.env`'s 35 floor (per an existing code
  comment in the same file: "default 12.0 — that default predates the
  corpus growing past M12").

**Verdict: PASS** (4 of 4 explicitly requested suite runs behave exactly as
predicted; the one pre-existing failure is confirmed environmental with a
concrete root cause, not caused by or related to the #389 changeset).

---

## Check 5 — mutation test (16384 → 16385) on a scratch copy

Built a scratch tree mirroring the exact relative layout
`test_zeek_log_field_string_cap.py`'s `ROOT = Path(__file__).resolve().parents[2]`
requires, containing copies of all files the module reads:
```
tree/tests/pipeline/test_zeek_log_field_string_cap.py
tree/configs/intel/config.zeek
tree/configs/logstash.conf
tree/configs/elasticsearch/logstash-security-template.json
tree/scripts/setup/{zeek_run_pcap.sh, stream_capture.sh, zeek_connect_host.sh}
tree/configs/systemd/zeek-host-capture.service
```
(All 8 files it actually reads — `CONFIG_ZEEK`, `LOGSTASH_CONF`, `TEMPLATE`,
and the 4 `REAL_CAPTURE_SOURCES` files — not just 3, so the whole module
runs cleanly rather than erroring on a missing file.)

**Baseline run (unmutated scratch copy):**
```
python3 -m pytest .../check5/tree/tests/pipeline/test_zeek_log_field_string_cap.py -q -p no:cacheprovider
# 6 passed, 4 subtests passed
```
Identical result to running the test against the real repo — confirms the
scratch tree is a faithful mirror.

**Mutation:** `sed -i 's/redef Log::default_max_field_string_bytes = 16384;/redef Log::default_max_field_string_bytes = 16385;/'`
applied **only** to `check5/tree/configs/intel/config.zeek` (scratch copy;
real repo file untouched).

**Mutated run:**
```
python3 -m pytest .../check5/tree/tests/pipeline/test_zeek_log_field_string_cap.py -v -p no:cacheprovider
```
**Result: 2 failed, 4 passed, 4 subtests passed**
```
FAILED ...::ConfigZeekCapTests::test_config_zeek_redefs_the_log_field_string_cap_to_the_expected_value
  AssertionError: 16385 != 16384
FAILED ...::LogstashLockstepTests::test_logstash_exact_length_literal_equals_config_zeeks_redef
  AssertionError: 16384 != 16385
```
Exactly the two lockstep assertions fail (config.zeek vs. the hardcoded
`EXPECTED_CAP=16384` module constant; and config.zeek vs. the unmutated
`logstash.conf` literal) — the other 4 tests (version-guard placement,
ignore_above comparison, "no longer 4096", and the 4 capture-invocation
staleness-guard regex checks) correctly remain green since they don't depend
on the numeric value matching.

**Verdict: PASS.** The lockstep tests genuinely catch a drifted cap value;
this is not a vacuously-passing test suite.

---

## Overall Summary

| # | Check | Verdict |
|---|---|---|
| 1 | Version guard parses on native 8.0.5; unguarded file fails | ✅ PASS (doc has wrong quoted error string — cosmetic) |
| 2 | 10k/20k pcap replay on native 8.0.5: full length, no truncation weird | ✅ PASS |
| 3 | ExecStartPre + stream_capture.sh staleness guards: pass valid, FATAL+exit1 on stale | ✅ PASS |
| 4 | Test suites: pipeline, slo_metrics (1 pre-existing env failure), sigma/hygiene, live (clean Docker skip) | ✅ PASS |
| 5 | Mutation (16384→16385) breaks exactly the 2 lockstep tests | ✅ PASS |

No repo files were modified. All scratch artifacts remain under
`/tmp/claude-1000/-home-tjlam-projects-Suburban-SOC/46e53f36-8edb-435a-b51a-76b4d8b94861/scratchpad/tester/`.

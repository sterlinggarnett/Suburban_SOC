# Code review — #550 / M26 — es_ca_cache.sh, slo-metrics.service, test_slo_metrics_docker_independence.py

Reviewer: code-reviewer agent (logic/reliability/maintainability lens only — security-auditor
covering vulnerabilities in parallel). Date: 2026-09-06.

Scope: uncommitted changeset (`git status --short`):
- `configs/systemd/slo-metrics.service` (M)
- `scripts/setup/es_ca_cache.sh` (new)
- `tests/pipeline/test_slo_metrics_docker_independence.py` (new)

Verification performed (not just read-through): ran the full new + sibling pytest file
(`python3 -m pytest tests/pipeline/test_slo_metrics_docker_independence.py
tests/pipeline/test_es_ca_fingerprint_pinning.py -q` → 36 passed, 8 subtests passed);
ran `shellcheck` on both shell scripts (clean, no warnings); hand-traced `set -euo pipefail`
interaction with `mktemp`/`install`/`mv`/pipelines using throwaway repros in the scratchpad
dir to confirm exemption/non-exemption behavior empirically rather than from memory of the
bash manual.

## BLOCKER

None. `es_ca_cache.sh`'s own branches are logically sound and I could not construct a
`set -e` path that skips its intended `exit 0`, nor an `install_atomically` failure mode
that isn't cleaned up. Unit ordering (`cp -> restore -> verify -> save`) is correct.

## MAJOR

1. **Vacuous "restore" subtest in `test_neither_mode_can_fail_the_unit`**
   (`tests/pipeline/test_slo_metrics_docker_independence.py:299-314`):
   ```python
   unwritable = str(Path(self.tmp) / "no-such-dir" / "ca.crt")
   self._make_cert(self.runtime_ca, "CA-A")
   Path(self.pin_path).write_text(self._pin(self.runtime_ca) + "\n")
   result = subprocess.run(
       ["bash", str(CACHE_SCRIPT), mode, self.runtime_ca, unwritable, self.pin_path], ...)
   self.assertEqual(0, result.returncode, ...)
   ```
   For `mode="restore"`, `self.runtime_ca` is pre-populated by `_make_cert` just above, so
   `es_ca_cache.sh`'s very first line of the `restore` branch fires before `unwritable`
   (which maps to `$3`/`CACHE_CA`, not `$2`/`RUNTIME_CA`, the actual write target for
   `restore`) is ever read:
   ```
   restore)
       if [ -s "$RUNTIME_CA" ]; then
         # A live extraction already succeeded this run; it always wins.
         exit 0
       fi
   ```
   (`scripts/setup/es_ca_cache.sh:79-82`). The subtest passes with `returncode == 0`
   regardless of whether the cache path is writable, unwritable, or nonexistent — it never
   exercises `install_atomically`'s failure-tolerance for `restore` at all. The `save`
   subtest of the same test *is* meaningful (RUNTIME_CA present + PIN present routes past
   both guards into `cmp`/`install_atomically` against the unwritable `CACHE_CA`). Fix: for
   the `restore` case, leave `self.runtime_ca` unpopulated and instead make `$2`
   (`self.runtime_ca`, the actual restore write-target) point at a nonexistent-parent-dir
   path, with a valid `CACHE_CA`+pin in place, so the test actually reaches
   `install_atomically("$CACHE_CA", "$RUNTIME_CA")` and its failure path.

2. **Stale, now-contradictory assertion message in the sibling test file**
   (`tests/pipeline/test_es_ca_fingerprint_pinning.py:97-105`):
   ```python
   self.assertFalse(
       verify_line.startswith("ExecStartPre=-"),
       "slo-metrics.service's verify step must NOT be '-'-prefixed — "
       "this unit's sole purpose is indexing into ES (its own docker cp "
       "extraction step is also not '-'-prefixed), so there is no "
       "degraded-but-useful mode to preserve if the CA can't be trusted",
   )
   ```
   "its own docker cp extraction step is also not '-'-prefixed" is no longer true —
   `configs/systemd/slo-metrics.service:118` now reads
   `ExecStartPre=-/usr/bin/docker cp elasticsearch:...` (the whole point of #550), and the
   new test file explicitly asserts the opposite in the same repo:
   `tests/pipeline/test_slo_metrics_docker_independence.py:97-103`
   (`test_no_unprefixed_docker_invocation_survives_in_slo_metrics`, "nothing Docker-shaped
   in its start path may be able to fail it"). The boolean assertion in the old test still
   *passes* (the verify step itself correctly remains un-prefixed), so this isn't a test
   failure, but the message is now factually wrong and directly contradicts a passing test
   two files over — exactly the "does it contradict `test_es_ca_fingerprint_pinning.py`"
   check this review was asked to make. This repo's own convention (`slo-metrics.service`'s
   header comments) treats comment/assertion-message accuracy as a correctness property;
   this should be updated in the same PR, not left for someone to trip over later.

## MINOR

3. **`restore`/`save` ExecStartPre lines carry no explicit "-"-prefix rationale, unlike
   every other line in this unit** (`configs/systemd/slo-metrics.service:159,161`):
   ```
   ExecStartPre=/usr/bin/bash .../es_ca_cache.sh restore /run/.../ca.crt /var/lib/.../ca.crt /var/lib/.../ca_fingerprint.sha256
   ...
   ExecStartPre=/usr/bin/bash .../es_ca_cache.sh save /run/.../ca.crt /var/lib/.../ca.crt /var/lib/.../ca_fingerprint.sha256
   ```
   Every *other* ExecStartPre in this file has an explicit comment justifying its "-"
   choice (the `docker cp` comment at line 101 says the prefix "is load-bearing"; the
   `verify_ca_fingerprint.sh` comment at line 132 says "Deliberately NOT '-'-prefixed...").
   These two new lines are un-prefixed with no equivalent sentence saying so is deliberate.
   I confirmed by trace (see Correctness section below) that `es_ca_cache.sh` genuinely
   can't exit non-zero here short of a usage error, so leaving them un-prefixed is *correct*
   — but the safety rests entirely on that script's own internal discipline with zero
   systemd-level backstop, which is exactly the failure class #550 patched. A one-line
   comment ("not '-'-prefixed because es_ca_cache.sh's own contract guarantees exit 0 for
   anything but a usage error — see its header") would close the same kind of "why is this
   the way it is" gap #550 itself was about.

4. **`install_atomically`'s cleanup path (`rm -f "$tmp"`) has no regression test**
   (`scripts/setup/es_ca_cache.sh:72-74`):
   ```
   install -m 0600 "$src" "$tmp" && mv -f "$tmp" "$dest" && return 0
   rm -f "$tmp"
   return 1
   ```
   I verified by direct repro (unreadable `$src`, chmod 000) that this line does correctly
   fire and leaves no stray temp file. But `test_neither_mode_can_fail_the_unit` — the only
   test that tries to break `install_atomically` — triggers failure via a nonexistent
   parent directory, which fails at the `mktemp` step (`tmp="$(mktemp ...)" || return 1`,
   line 70) and never creates `$tmp` at all, so `rm -f "$tmp"` is never exercised by any
   test in the suite. Consider adding a case with an unreadable `$src` (or read-only
   `$dest` dir with `$tmp` creatable) so the cleanup line has coverage.

5. **Pre-existing, out-of-diff hazard in `verify_ca_fingerprint.sh` that the new script's
   trust-model comment leans on** (`scripts/setup/verify_ca_fingerprint.sh:52-54`, file
   unmodified by this changeset):
   ```
   fingerprint="$(openssl x509 -in "$CA_PATH" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
   if [ -z "$fingerprint" ]; then
     echo "[FATAL] could not compute a SHA-256 fingerprint of $CA_PATH" >&2
     rm -f "$CA_PATH"
     exit 1
   fi
   ```
   Reproduced empirically: feeding a non-empty but non-X.509 `$CA_PATH` (e.g. plain text)
   makes `openssl` fail inside the pipeline; under `set -euo pipefail` this trips `-e`
   **at the assignment itself** — `bash -x` shows execution stop right after
   `+ fingerprint=`, before the `[ -z "$fingerprint" ]` check ever runs. The script does
   still exit 1 (matches `openssl`'s own exit code by coincidence), but the `[FATAL]`
   message never prints and, more importantly, `rm -f "$CA_PATH"` never runs — the
   malformed cert is left on disk. `es_ca_cache.sh`'s header explicitly relies on "a cert
   that failed the pin — which verify_ca_fingerprint.sh deletes — can never enter the
   cache" (`scripts/setup/es_ca_cache.sh:54-55`). In *this* unit the practical blast radius
   is nil: `verify_ca_fingerprint.sh`'s ExecStartPre is un-prefixed so the unit still fails
   correctly and `save` never runs regardless, and `RuntimeDirectory=` is torn down before
   the next run anyway, wiping the leftover file. But the header's documented contract
   ("fingerprint mismatch: DELETE the ca.crt... and exit 1") doesn't actually hold for the
   "couldn't parse a fingerprint at all" branch, and a future caller that persists `CA_PATH`
   outside a RuntimeDirectory= would inherit a live bug. Worth a follow-up fix
   (`fingerprint="$(openssl ... 2>/dev/null)" || fingerprint=""` pattern, or splitting the
   pipeline so `cut`'s exit status doesn't mask `openssl`'s), separate from #550.

## CONSIDER

6. `scripts/setup/es_ca_cache.sh` is mode `-rwxr-xr-x` while its sibling
   `scripts/setup/verify_ca_fingerprint.sh` is `-rw-r--r--`; both are invoked identically
   via `/usr/bin/bash <path>` in the unit, so the executable bit is functionally inert here
   — flagging only for consistency, not correctness.
7. No trap/cleanup for a `SIGKILL`-during-install leaving a stray `ca.crt.XXXXXX` under
   `StateDirectory=` (which, unlike `RuntimeDirectory=`, is not torn down between runs).
   Probability is very low given the script's runtime is milliseconds; not worth
   engineering around unless it's ever observed.

## Sibling-unit follow-up (M17/M26 scope, not a blocker for #550)

Per the review prompt's point 6: **`intel-refresh.service` does *not* need this cache as
urgently as the other two.** It already has both its `docker cp` (line 121) and its
`verify_ca_fingerprint.sh` step (line 122) "-"-prefixed, *and* `configs/intel/refresh_intel.sh`
has its own gate before ever sourcing `es_common.sh`:
`configs/intel/refresh_intel.sh:280`: `log "WARN: ES_CA (${ES_CA:-unset}) missing or
unreadable and ES_INSECURE not set -- skipped ES indexing (feed file still updated)"` — this
already reports the true reason without ever making an HTTP call, so it doesn't hit the
misleading generic TLS-bundle error #550 is about.

**`checkpoints-compact.service` and `threat-intel-compact.service` are the better follow-up
candidates and are arguably worse off than slo-metrics was.** Confirmed via grep: neither
unit has a `verify_ca_fingerprint.sh` ExecStartPre step, a `StateDirectory=`, or any TOFU
pin at all — only a "-"-prefixed `docker cp` and nothing else. Their `ExecStart` targets
(`scripts/setup/ai_agent/compact_agent_checkpoints.py:164-165` and
`scripts/setup/ai_agent/compact_threat_intel.py:102-103`) both do:
```python
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True
```
then pass `verify=ES_VERIFY` straight to `requests`. On a Docker-down run, `RuntimeDirectory=`
teardown means `ES_CA` points at a file that doesn't exist, and `requests` will raise the same
generic TLS CA-bundle error class that motivated `es_ca_cache.sh` for slo-metrics — with no
graceful script-level gate like `refresh_intel.sh`'s to catch it first. File a follow-up issue
(milestoned, per this repo's own convention) to extend TOFU pinning + `es_ca_cache.sh` to
these two units; do not fold it into #550 without a separate confirmation.

## Looks Good

- `install_atomically` (`scripts/setup/es_ca_cache.sh:68-75`) is genuinely atomic: `mktemp
  "${dest}.XXXXXX"` guarantees the temp file lives in the same directory as `dest`, so
  `mv -f` is a same-filesystem rename. Verified empirically that `mktemp` fails cleanly
  (rc=1, no partial file) when `dest`'s parent directory doesn't exist, and that both
  `install` and `mv` failures correctly fall through to the `rm -f "$tmp"` cleanup under
  `set -e` (the `&&`-chain exemption rule applies correctly here — confirmed by repro, not
  assumed).
- The restore-before-verify / save-after-verify ordering
  (`configs/systemd/slo-metrics.service:159-161`) is correct and directly enforces the
  stated trust model: a reinstated cert is still pin-checked, and a pin-failed cert can
  never reach the cache (systemd stops at the un-prefixed `verify` step before `save` runs).
- The TOFU re-arm hazard is both correctly implemented and explicitly tested: `restore`
  refuses to act when the pin file is absent (`scripts/setup/es_ca_cache.sh:87-90`), closing
  the "stale cache re-pinned as the new trusted value during a rotation window" hole, and
  `test_restore_refuses_while_tofu_is_re_armed_for_a_rotation` exercises exactly that.
- Steady-state idempotency: `cmp -s "$RUNTIME_CA" "$CACHE_CA"` (line 107) means a healthy
  run with an unchanged CA never rewrites the cache — only genuine first-use or rotation
  triggers a write.
- The new test file runs the script for real against real self-signed certs (not just
  regex/string checks against the unit file), and the cross-unit regression guard
  (`test_every_ca_extracting_unit_has_a_best_effort_docker_cp`) protects the whole
  four-unit family, not just slo-metrics.

## Verdict

⚠️ **Approve with conditions** — fix MAJOR #1 (vacuous restore subtest) and MAJOR #2 (stale
contradictory assertion message) before merge; they're test-suite integrity issues, not
functional breaks. The production logic in `es_ca_cache.sh` and the unit ordering/prefixing
are correct as written and hold up under empirical `set -e`/atomicity testing, not just
read-through. MINOR/CONSIDER items and the sibling-unit follow-up can be separate issues.

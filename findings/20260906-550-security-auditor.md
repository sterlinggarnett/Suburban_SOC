# Security audit — #550 / M26 CA-cache + Docker-independence changeset

Audited 2026-09-06 by the `security-auditor` agent (read-only role; report
persisted here by the main session, which also re-verified the claims marked
**[verified in main session]** below).

Scope: `scripts/setup/es_ca_cache.sh` (new), `configs/systemd/slo-metrics.service`
(modified), `tests/pipeline/test_slo_metrics_docker_independence.py` (new).
Read for context: `verify_ca_fingerprint.sh`, `intel-refresh.service`,
`slo-metrics.timer`, `configs/slo/slo-metrics.cron`,
`test_es_ca_fingerprint_pinning.py`, `slo_metrics.py`.

## Headline verdict

**No HIGH or CRITICAL. The core trust property holds.** Every path by which a
file can reach `/run/suburban-soc-slo/ca.crt` — the `docker cp` at
`slo-metrics.service:118` and `install_atomically` at `es_ca_cache.sh:91` — is
followed by `verify_ca_fingerprint.sh` before `ExecStart`. `restore` is
additionally gated on a non-empty pin (`es_ca_cache.sh:87`), so it cannot feed
verify's learn-branch (`verify_ca_fingerprint.sh:62`). **The cache cannot
launder an unpinned trust anchor.**

| Severity | Count |
|---|---|
| CRITICAL / HIGH | 0 |
| MEDIUM | 4 |
| LOW | 6 |
| INFO | 2 |

## MEDIUM 1 — A stale CA cache re-creates the #550 hard-fail loop, unalertably

T1562.001. `save`'s only gate is `if [ ! -s "$PIN_PATH" ]`
(`es_ca_cache.sh:103`) — it checks that *a* pin exists, never that the cert
matches it. If the cache goes stale relative to the pin, every later
Docker-down run does: `restore` installs it -> `verify_ca_fingerprint.sh:71`
`rm -f "$CA_PATH"` + `exit 1` -> ExecStartPre failure -> unit dead before
`ExecStart`. `verify_ca_fingerprint.sh` only deletes the `/run` copy; the
`/var/lib` cache is not in its argv, so the condition is permanent and
self-perpetuating.

Most likely trigger is not an attacker: an operator re-pins a rotated CA by
writing the new fingerprint into `ca_fingerprint.sha256` by hand instead of
deleting it. Pin = NEW, cache = OLD, unit fails every 15 minutes. The script's
own remediation message (`verify_ca_fingerprint.sh:70`) predates the cache and
does not mention it.

The header claim at `es_ca_cache.sh:53-55` — "a cert that failed the pin ...
can never reach the cache" — is true only by systemd ordering, not by any
check the script performs.

**Fix:** fingerprint-check the cache in *both* verbs. **ACCEPTED — implemented.**

## MEDIUM 2 — `SuccessExitStatus=0 2` swallows ExecStartPre failures

T1553.004. **[verified in main session]** A throwaway `--user` unit with
`SuccessExitStatus=0 2` and `ExecStartPre=/bin/sh -c 'echo PRE_RAN; exit 2'`
yields `Result=success` and reaches `ExecStart`. The directive is **not**
main-process-only.

Consequence: `verify_ca_fingerprint.sh` exiting 2 is treated as clean and the
unit proceeds with an **unverified** `ca.crt`. `bash` exits 2 on a script
syntax error, so truncation/corruption of the trust check fails **open**. The
new script made this concrete by using `exit 2` as its usage-error code.

Asymmetry also noted: the *other* usage error (missing argv via `${1:?}` under
`set -u`) exits 1 and *does* fail the unit, contradicting the header's
"always 0 for anything short of a usage error".

**Fix:** `exit 2` -> `exit 64` (sysexits `EX_USAGE`), and normalize the verify
step's status so no control process in this start path can return a forgiven
code. **ACCEPTED — implemented.**

## MEDIUM 3 — `-` protects against a non-zero exit, not against a hang

T1562.001. `-` suppresses a failed status; it does nothing for a `docker cp`
that blocks against a half-up daemon (socket present, daemon unresponsive) —
the state adjacent to the one #550 fixes. `slo-metrics.service` sets no
`TimeoutStartSec=`, so stock `DefaultTimeoutStartSec` (90s) applies to the
whole start job; a blocked cp consumes it and systemd kills the unit with the
same net effect as the `203/EXEC` it replaced. The sibling sets
`TimeoutStartSec=300` (`intel-refresh.service:144`); this one set nothing.

**Fix:** `timeout 15` around the cp (coreutils, cannot dangle the way the
Docker Desktop symlink does) plus `TimeoutStartSec=120`. **ACCEPTED — implemented.**

## MEDIUM 4 — The change improves the journal message but adds no delivery path

T1562.001. Reaching `ExecStart` does let `slo_metrics.py:1969` fire an ntfy
POST that depends on neither ES nor Docker — a real win. But every path where
the unit still dies at ExecStartPre bypasses it, and `configs/systemd/`
contains **no `OnFailure=` on any unit**. `NTFY_TOPIC` also reaches the process
only via `env_loader.load_env_file()`, so an unreadable `.env` silently
disables alerting with no warning.

Auditor calls this "the single highest-value item for M26".

**SCOPED OUT of #550** — merged with the main session's own finding that
`NTFY_TOPIC` is absent from this host's `.env` entirely. Follow-up issue.

## LOW 5 — Cached trust anchor has no max age and no expiry check

T1553.004. Credential harvest is **not** newly enabled — `ES_VERIFY` gates
transmission and forging the CA needs its private key, so a local process
squatting `localhost:9200` during the Docker-down window fails the handshake.
The genuine weakening is an unbounded-age anchor: `verify_ca_fingerprint.sh`
compares fingerprints only, never `notAfter`. The restore log names the path
but not the age.

**Fix:** `openssl x509 -checkend 0` refusal + cache age in the log message. Do
*not* add a hard max-age — that resurrects the misleading CA-bundle error #550
exists to eliminate. **ACCEPTED — implemented.**

## LOW 6 — `install_atomically` has no `trap`; temp files leak into StateDirectory

`rm -f "$tmp"` covers a failed `install`/`mv` but not a SIGTERM between
`mktemp` and `mv` — reachable given MEDIUM 3. `/run` leftovers self-clean via
`RuntimeDirectory=` teardown; `/var/lib` leftovers accumulate permanently and
make "which file is the real anchor?" ambiguous during triage.
**ACCEPTED — implemented** (`trap` + a sweep in `save`).

## LOW 7 — Permissions and mktemp: sound, with two inconsistencies

**No finding on the core model.** `mktemp "${dest}.XXXXXX"` in the destination
directory makes `mv -f` a same-filesystem `rename(2)` and therefore genuinely
atomic; `mktemp` creates `O_EXCL` at 0600; `install -m 0600` sets the mode
explicitly rather than relying on `UMask=0077`; both destination directories
are 0700. Six `X`s is not a predictability concern inside a 0700 same-UID
directory.

Inconsistencies: (i) `docker cp` does not normalize the extracted mode, so the
live-extraction path can be laxer (commonly 0644) than the restore path;
(ii) `install`/`mv` follow a symlinked `$src`.
**Symlink refusal ACCEPTED — implemented.** (i) left as-is: harmless inside a
0700 directory, and each additional `ExecStartPre` is another thing that can
fail in a unit whose whole defect was an over-fragile start path.

## LOW 8 — `RemoveIPC=true` on a 15-minute unit running as the interactive login account

**[verified in main session]** `slo-metrics.service:184` sets
`RemoveIPC=true` with `User=tjlam`. `intel-refresh.service:191-198` explicitly
*rejects* the same directive and names slo-metrics.service while doing so:
"User=tjlam is the interactive login account (same as slo-metrics.service),
and Type=oneshot means this unit stops after every single run". At a 15-minute
cadence that is 96 teardowns a day against the operator's own login UID,
eligible to destroy IPC belonging to desktop-session and Docker Desktop helper
processes. `slo_metrics.py` uses no IPC, so it protects nothing.

Pre-existing, but a documented in-repo decision that was never applied to this
unit. **ACCEPTED — implemented** (one-line removal, precedent comment carried
over).

## LOW 9 — Sandboxing parity gap versus the sibling unit

`intel-refresh.service` sets `RestrictAddressFamilies=`, `SystemCallFilter=`,
`SystemCallErrorNumber=`, `PrivateDevices=`, `ProtectProc=`, `ProcSubset=` and
`MemoryMax=`; `slo-metrics.service` sets none of them, despite that unit's own
comment saying its directive set was "verified against this exact directive set
working for slo-metrics.service in production" — the porting went one way only.

**SCOPED OUT of #550.** Pre-existing hardening gap, unrelated to the Docker
failure class. Follow-up issue.

## LOW 10 — `configs/slo/slo-metrics.cron` supplies an unpinned trust anchor

T1557. The documented cron fallback sets
`ES_CA="$HOME/.config/suburban-soc/ca.crt"` (`slo-metrics.cron:24`), populated
by a one-time manual `docker cp` with no fingerprint pin, no verification and
no 0700 directory. `verify_ca_fingerprint.sh` is not invoked on this path and
no test asserts it should be. #550 raises the relevance: an operator hitting a
prolonged Docker outage is exactly the person likely to reach for the
documented fallback.

**SCOPED OUT of #550, handled separately** — this is a live control gap on
existing config, so per this project's convention it gets fixed directly rather
than described in a public issue.

## INFO — Shell safety in `es_ca_cache.sh`: clean

Checked specifically for injection, quoting and `set -e` interaction. No
`eval`, no `sh -c`, no command substitution on untrusted input; every expansion
quoted at every use site. `install_atomically` is invoked from `if` conditions,
which suppresses `errexit` inside it — the desired behaviour, with explicit
`&&`/`rm -f`/`return 1` handling. Nits: `set -o pipefail` is inert (no
pipelines, until the fingerprint checks added in revision); `2>/dev/null` on
the `cmp` would mask `cmp: command not found`, whose effect is a harmless
redundant cache rewrite.

## INFO — Stale justification string in the pre-existing pinning test

`test_es_ca_fingerprint_pinning.py:111-112` justifies its assertion with "its
own docker cp extraction step is also not '-'-prefixed". That premise is now
false. The assertion still passes and is still correct, but the message will
mislead the next reader. **ACCEPTED — implemented** (the code-reviewer raised
the same point as MAJOR #2).

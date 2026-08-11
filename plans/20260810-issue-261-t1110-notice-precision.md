# Plan — Issue #261: Zeek T1046/T1110 pipeline classification

## Issue as filed
`configs/logstash.conf`'s T1110 branch tags `threat.technique.id=T1110` on
*every* `auth_success=false` event (every failed SSH login), not an
aggregated brute-force notice — unlike the T1046 branch, which correctly
matches only the aggregated `Scan::Port_Scan` notice. An unauthenticated
actor can inflate `raw_alert_volume`'s `zeek_notices` count at will with a
failed-login burst. Suggested fix: match `[note] in
["SSH::Password_Guessing", "SSH::Login_By_Password_Guesser"]`, mirroring the
T1046 pattern.

## Root-cause investigation finding (expands scope)
Applying the suggested fix in isolation would regress T1110 to **zero** real
detections: the Zeek policy that emits those exact notices,
`policy/protocols/ssh/detect-bruteforcing`, is not loaded by any real capture
invocation today.

- `configs/zeek/local.zeek` — which the Sigma rule's own docstring assumes
  loads it — is dead config, confirmed unused since #286 (own header comment).
- Checked every real entry point: `stream_capture.sh`,
  `configs/systemd/zeek-host-capture.service` (the always-on production
  sensor), `zeek_connect_host.sh`, `zeek_run_pcap.sh`. None load it.
- `coverage_checklist.md:14` already carries this as an unchecked `[ ]` item,
  never connected to #261 before now.

Same failure class as T1046/`Scan::Port_Scan` (modern Zeek dropped the
built-in Scan framework, requiring a custom reimplementation,
`scan-detection.zeek`, explicitly wired into the two real capture paths).
Difference: `detect-bruteforcing.zeek` **is** still shipped in the pinned
`zeek/zeek:latest` image — confirmed directly (`zeek --version` → 8.1.1,
`find` located
`/usr/local/zeek/share/zeek/policy/protocols/ssh/detect-bruteforcing.zeek`
inside the image). It needs wiring, not reimplementation.

Read the policy script directly:
- Emits `SSH::Password_Guessing` via a `SumStats` threshold
  (`password_guesses_limit: double = 30 &redef`, default 30 failed logins /
  30 min window from one source) on the `ssh_auth_failed` event.
- `Login_By_Password_Guesser` is declared but never raised anywhere in the
  script (comment: "This is not currently implemented") — expected to never
  fire from this stock policy; still worth keeping in the Sigma rule/pipeline
  match for forward-compat, matching this repo's existing honest-scoping
  pattern.
- `ssh_auth_failed`/`ssh_auth_successful` are analyzer-level SSH events,
  likely sourced from the same auth-outcome inference `verify_detections.py`
  already documents as unreliable over loopback ("large-MTU, unsegmented
  packets defeat its packet-size heuristic"). `sim_brute_ssh.sh` defaults to
  `TARGET_HOST=127.0.0.1` and only issues 5 attempts — nowhere near the
  30-attempt notice threshold, and loopback-sourced regardless. Live
  verification needs a non-loopback path (real NIC or a Docker bridge
  network, which uses normal Ethernet framing/MTU) to avoid retesting a
  known, already-documented limitation instead of the actual fix.

## Scope (confirmed with repo owner — full fix, not split)
1. Wire `@load policy/protocols/ssh/detect-bruteforcing` into
   `scripts/setup/stream_capture.sh` and
   `configs/systemd/zeek-host-capture.service`'s `ExecStart`, alongside the
   existing `scan-detection.zeek` load. Verified empirically that the
   combined script set (`config.zeek` + `scan-detection.zeek` +
   `policy/protocols/ssh/detect-bruteforcing`) loads clean, exit 0, no
   errors, against the pinned image.
2. Fix `configs/logstash.conf`'s T1110 branch: `[note] in
   ["SSH::Password_Guessing", "SSH::Login_By_Password_Guesser"]`, mirroring
   the T1046 branch's own pattern and comment style.
3. Add a regression test (mirrors the #263 CI-enforced-invariant pattern) —
   `tests/pipeline/test_framework_enrichment.py` — asserting the T1110
   branch is note-based, not `auth_success`-based, so this can't silently
   regress back to per-event tagging.
4. Live-verify against the real capture toolchain (not loopback) — delegate
   to `tester-debugger` with this investigation's findings as context so it
   doesn't need to rediscover the loopback issue or the 30-attempt
   threshold.
5. Re-evaluate `net_zeek_ssh_bruteforce.yml` / `net_zeek_port_scan.yml`
   promotion out of `experimental` per the issue's 3rd acceptance criterion.
   **Conclusion: stay `experimental`** — confirmed correct by both agent
   reviews. A precise pipeline tag and a live Detection Engine rule reading
   the identical notice would double-count by construction, exactly as each
   rule's own docstring already states. security-auditor's review sharpened
   this further: promoting the notice-based rule wouldn't have resolved
   anything, just made a guaranteed double-count predictable instead of
   murky. The better move for the acceptance criterion's actual goal (real
   coverage below the 30-attempt notice threshold) is a genuinely distinct
   signal — a session-cadence threshold rule reading `zeek.ssh` records
   directly, mutually exclusive with the notice-based tag by construction —
   filed as [#332](https://github.com/voltron-1/Suburban_SOC/issues/332)
   rather than built inline here (new rule authoring, its own review cycle).
   No rule-file change beyond the docstring corrections (item 7).
6. `security-auditor` + `code-reviewer` in parallel on the diff (project
   CLAUDE.md mandate: after any code change), plus `tester-debugger` for live
   verification, all three launched together per the "fix implemented ->
   review + test in parallel" pattern.
7. Fix stale docs the investigation surfaced, all pointing at the dead
   `local.zeek` or the old per-event T1110 behavior:
   `scripts/setup/ai_agent/slo_metrics.py`'s `metric_raw_alert_volume`
   docstring, both `net_zeek_*.yml` rule docstrings,
   `configs/detections/emulation_telemetry.map` (2 entries), and
   `coverage_checklist.md`'s two `local.zeek`-referencing to-dos (checked
   off, now accurately describing the real wiring location).

## Live verification results (tester-debugger, resumed once to finish)

**Check 1 — `configs/logstash.conf`'s T1110 filter: PASS.** Spliced the
exact T1046/T1110 block into a minimal pipeline, ran it through the real
`docker.elastic.co/logstash/logstash:9.3.2` image (matches this repo's own
pin), fed synthetic notice/non-notice JSON docs through stdin. A synthetic
`SSH::Password_Guessing`/`Login_By_Password_Guesser` notice gets tagged
T1110; a synthetic `auth_success:false` connection event with no `note`
field gets no `threat.*` fields at all. T1046 unaffected (sanity check).

**Check 2 — `detect-bruteforcing` live-fire: PASS.** Real two-container
Docker bridge network (not loopback — normal Ethernet framing), Alpine sshd
server + sshpass client, `tcpdump` on the bridge interface, captured pcap
fed through `zeek -C -r <pcap> ... policy/protocols/ssh/detect-bruteforcing
SSH::password_guesses_limit=5`. Real `SSH::Password_Guessing` notice fired
(`"suppress_for":3600.0` — confirms the stock policy relies on the
framework's 1h default suppression, unlike `scan-detection.zeek`'s explicit
1-minute override; a validation re-run inside an hour of a prior one won't
re-fire, expected behavior worth knowing about, not a bug).

First attempt (very recent Alpine-`edge` OpenSSH 10.2p1 client+server)
produced zero auth-outcome classification from Zeek's SSH analyzer at all —
a real, separate, unconfirmed-root-cause Zeek-analyzer limitation, not a
regression from this fix (a debian:bullseye-slim/OpenSSH-8.4p1 control using
the identical harness worked correctly and is what produced the PASS above).
Filed as [#333](https://github.com/voltron-1/Suburban_SOC/issues/333).

## Follow-ups filed from review (deliberately out of scope for this PR)
- [#331](https://github.com/voltron-1/Suburban_SOC/issues/331) —
  `scan-detection.zeek`'s `Scan::Port_Scan` is SYN-only and source-spoofable,
  a cheaper `raw_alert_volume` inflation vector than the SSH path this PR
  fixed. Pre-existing, not introduced by this diff, not touched by it.
- [#332](https://github.com/voltron-1/Suburban_SOC/issues/332) — add a
  session-cadence SSH brute-force threshold rule for coverage below
  `detect-bruteforcing`'s 30-attempt notice threshold (low-and-slow /
  distributed brute force). Also resolves acceptance criterion 3 more
  cleanly than promoting the existing notice-based rule would have.
- [#333](https://github.com/voltron-1/Suburban_SOC/issues/333) — Zeek's SSH
  auth-outcome inference may be blind to very recent OpenSSH clients
  (10.2p1 observed); root cause unconfirmed, low priority absent evidence
  it's operationally relevant.
- Commented on the already-open
  [#293](https://github.com/voltron-1/Suburban_SOC/issues/293) (pin
  `zeek/zeek`) noting this PR adds a new dependency on that image's internal
  script-path structure.

## Explicitly out of scope
- Tuning `password_guesses_limit` in production (keep Zeek's stock default,
  30/30min) — only overridden transiently for live-verification.
- Re-implementing `sim_brute_ssh.sh` to hit the 30-attempt threshold for a
  routine dev-loop test; the existing 5-attempt session-cadence check
  (`verify_detections.py`) stays the intended fast local signal. If
  live-verification needs more attempts, that happens in the
  tester-debugger's own throwaway harness, not a change to the checked-in
  simulation script, unless the review decides otherwise.

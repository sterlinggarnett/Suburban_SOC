#!/usr/bin/env bash
# =============================================================================
# zeek_capture_liveness.sh — #549: derive zeek-host-capture.service's liveness
# from sensor OUTPUT (conn.log's mtime), not unit state.
#
# Incident this closes: on 2026-09-05 a dead tcpdump leg left `docker run`
# attached to a container whose Zeek had already exited (a truncated pcap
# read failed inside the container, but the docker run CLIENT never returns),
# so systemd saw ExecStart still "running" and reported
# ActiveState=active/SubState=running for five days with zero packets
# captured. `set -o pipefail` cannot catch this — it only decides an exit
# status once the pipeline EXITS, and this one hangs forever.
# WatchdogSec= cannot either — ExecStart is a bash script, which has no way to
# sd_notify() a keepalive.
#
# The capture-interface preflight (capture_iface_preflight.sh, #549/#551)
# closes the TRIGGER seen in that incident (an unusable CAPTURE_IFACE now
# exits 78, parking the unit in `failed`). It runs once, before the
# pipeline — every OTHER route to "active with zero packets" (tcpdump dying
# mid-run: device removed, ENOBUFS, the CAP_SETUID EPERM this unit's own
# header documents) is still open. This script is the general-purpose
# closer: it doesn't care WHY the unit went quiet, only THAT it did.
#
# Deliberately narrow: restart + alert ONLY when the unit is `active` AND the
# output is stale. NEVER when it is `failed` — a genuine config error must
# stay parked (that's what makes it visible to `systemctl is-active` and an
# operator) rather than papered over by an automatic restart loop.
#
# Same observable, same fix: the outage this closes and a deliberate
# sensor-disable (T1562.001) look identical from here — unit reports
# `active`, the log file stops advancing. A control built for one covers
# both (see rules/sigma/system_lnx_self_health_unit_failed.yml, #556, for
# the companion detection on the unit actually reaching `failed`).
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./zeek_capture_liveness.sh
# Env: ZEEK_CONN_LOG (default /storage/PCAP/zeek_logs/conn.log),
#      ZEEK_CAPTURE_STALE_MAX_S (default 1800 — above the quietest legitimate
#      traffic gap expected on this link; retune per-deployment), NTFY_TOPIC.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }

CONN_LOG="${ZEEK_CONN_LOG:-/storage/PCAP/zeek_logs/conn.log}"
NTFY_TOPIC="${NTFY_TOPIC:-}"
UNIT="zeek-host-capture.service"

# security-auditor (#555's own finding, same bug class): bash recursively
# evaluates a variable's CONTENTS inside (( )), so an env-supplied threshold
# naming another variable (or a command substitution) would be silently
# always-false, or worse, executed. Validate as a plain non-negative integer
# before it ever reaches an arithmetic context.
STALE_MAX_S="${ZEEK_CAPTURE_STALE_MAX_S:-1800}"
if ! [[ "$STALE_MAX_S" =~ ^[0-9]+$ ]]; then
  echo "zeek_capture_liveness: ignoring non-numeric ZEEK_CAPTURE_STALE_MAX_S=$STALE_MAX_S, using default 1800" >&2
  STALE_MAX_S=1800
fi

state="$(systemctl is-active "$UNIT" 2>/dev/null || true)"
if [[ "$state" != "active" ]]; then
  echo "zeek_capture_liveness: $UNIT is '$state', not 'active' -- nothing to do (a failed unit must stay parked, not be papered over by a restart)"
  exit 0
fi

if [[ ! -e "$CONN_LOG" ]]; then
  # The unit is active but has never written its first log at all — treat as
  # maximally stale rather than skipping the check (a fresh install with a
  # genuinely broken capture path looks identical to this until conn.log
  # first appears).
  echo "zeek_capture_liveness: $CONN_LOG does not exist yet -- $UNIT is active with no output" >&2
  age=$((STALE_MAX_S + 1))
else
  now=$(date +%s)
  mtime=$(stat -c %Y "$CONN_LOG")
  age=$(( now - mtime ))
fi

if (( age <= STALE_MAX_S )); then
  echo "zeek_capture_liveness: OK -- $UNIT active, $CONN_LOG age ${age}s <= ${STALE_MAX_S}s"
  exit 0
fi

echo "zeek_capture_liveness: STALE -- $UNIT reports active but $CONN_LOG age ${age}s > ${STALE_MAX_S}s -- restarting" >&2
systemctl restart "$UNIT"

# Known limit, disclosed not hidden: no cooldown/backoff. If the restart
# doesn't actually fix the underlying cause, the NEXT run (one timer interval
# later) sees the same staleness and restarts + alerts again — repeated
# alerts for the SAME wedge, not silence, is the deliberate trade-off; see
# docs/SOP-005-reliability.md.
if [[ -n "$NTFY_TOPIC" ]]; then
  curl -s -m 10 -o /dev/null "https://ntfy.sh/${NTFY_TOPIC}" \
    -H "Title: Suburban-SOC sensor wedge" -H "Priority: urgent" -H "Tags: rotating_light,satellite" \
    -d "zeek-host-capture reported active with a stale conn.log (age ${age}s, threshold ${STALE_MAX_S}s) -- restarted automatically. Verify capture resumed: tail -f ${CONN_LOG}" 2>/dev/null || true
else
  echo "zeek_capture_liveness: NTFY_TOPIC unset -- restart performed but not reported (see #554/docs/SOP-005-reliability.md)" >&2
fi

# #549/#555 convention: a successful run that found and fixed a real problem
# is not a job failure. SuccessExitStatus=0 2 in the paired unit file treats
# this the same way slo-metrics.service/stack-health.service already do.
exit 2

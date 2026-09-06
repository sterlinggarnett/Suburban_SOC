#!/usr/bin/env bash
# =============================================================================
# stack_health.sh — WS2.5: the SOC monitors its own components.
#
# A SOC that can't see its own outages is blind. This checks every component
# (Elasticsearch, Kibana, Logstash, AI agent, Hive-Mind broker), indexes the result
# to soc-health, and raises an ntfy alert if anything is DOWN — so the SOC detects
# its own outages. Run on a schedule: configs/systemd/stack-health.{service,timer}
# every 5 minutes (#555 — preferred), or configs/monitoring/reliability.cron as the
# fallback on a host without systemd.
#
# Usage (env auto-loaded from scripts/setup/.env):
#   ./stack_health.sh
# Env: ES_URL, KIBANA_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, NTFY_TOPIC,
#      SOC_SLO_METRICS_STALE_MAX_S (default 2700 — see the freshness check below).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HERE/.env" ]] && { set -a; . "$HERE/.env"; set +a; }
KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
NTFY_TOPIC="${NTFY_TOPIC:-}"
# Shared ES creds + TLS + es helpers (issue #156). Soft mode: a health monitor must
# keep checking other components even when ES creds are absent, so don't fail-fast.
# shellcheck disable=SC2034  # read by the sourced es_common.sh, not directly in this file
ES_REQUIRE_CREDS=0
# #555: the same soft posture for the stack CA. Under stack-health.service the CA is
# extracted from the `elasticsearch` container on every run; when Docker Desktop is
# stopped that extraction cannot run, and on a host with no pin-verified cached copy
# yet it leaves no CA at all. es_common.sh's default there is `exit 1` — which would
# kill this script during exactly the outage it exists to report, taking the container
# checks and the ntfy push down with the ES ones. ES_REQUIRE_CA=0 moves that failure to
# each individual ES call instead (curl exit 77, raised during SSL setup before any
# connection is opened or any credential is sent), so those checks report DOWN and the
# rest of the run still happens. TLS verification is never relaxed — see es_common.sh.
# shellcheck disable=SC2034  # read by the sourced es_common.sh, not directly in this file
ES_REQUIRE_CA=0
# security-auditor (#555, LOW 1 — T1557): .env is sourced ABOVE, before es_common.sh,
# so an ES_INSECURE=true line in it beats anything systemd's Environment= sets and
# hands curl -k — sending this lane's credential over an unverified handshake every
# 5 minutes. That opt-out exists for a lab/first-run operator at a terminal, never for
# a scheduled monitor, so refuse it when systemd is the caller. INVOCATION_ID is set by
# systemd for every unit it starts and by nothing else; a manual run is unaffected.
if [[ -n "${INVOCATION_ID:-}" && "${ES_INSECURE:-false}" == "true" ]]; then
  echo "ERROR: ES_INSECURE=true is set (most likely in scripts/setup/.env) while running" >&2
  echo "       under systemd. A scheduled health monitor must not disable TLS verification;" >&2
  echo "       remove it, or run this script by hand if you really need the lab opt-out." >&2
  exit 1
fi
# shellcheck source=lib/es_common.sh
source "$HERE/lib/es_common.sh"

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }

declare -a DOWN=()
report() { printf '  %-16s %s\n' "$1" "$2"; }

# Container inventory, taken once per run. #555: "docker ps failed" and "docker ps
# returned an empty list" are different facts that used to collapse into the identical
# report line, "container down". On the WSL capture host /usr/bin/docker is a Docker
# Desktop symlink that dangles whenever the engine is stopped, and the Windows-side
# shim still on PATH answers "The command 'docker' could not be found in this WSL 2
# distro" — so every container read as DOWN whenever Docker Desktop was off, whatever
# the containers were actually doing. Snapshot the list once, record WHY it is empty,
# and report that reason instead of guessing. `timeout` bounds the half-up state
# (socket present, daemon not answering) the way #550 bounds the same call in systemd.
#
# security-auditor (#555, MEDIUM 5 — T1562.001): the snapshot carries {{.State}}, not
# just {{.Names}}. `docker ps` lists containers in the `restarting` state, so a
# crash-looping soc_ai_agent or hive_mind_broker used to read as UP and never reach the
# ntfy path — the SOC reporting itself healthy while a component flapped. Name presence
# is not liveness; only State=running is. This also raises the bar on a decoy container
# started by anyone with Docker socket access: it now has to actually stay running.
DOCKER_PS=""
DOCKER_REASON=""
if ! DOCKER_PS="$(timeout 10 docker ps --format '{{.Names}}|{{.State}}' 2>/dev/null)"; then
  DOCKER_PS=""
  DOCKER_REASON="docker unavailable"
fi
# Full-line match on "<name>|running" — grep -qx so a name cannot match by prefix.
container_up() { [[ -z "$DOCKER_REASON" ]] && grep -qx "$1|running" <<<"$DOCKER_PS"; }
# Why a container did not read as running: engine gone, a non-running state we can
# name, or genuinely absent.
container_detail() {
  [[ -n "$DOCKER_REASON" ]] && { printf '%s' "$DOCKER_REASON"; return; }
  local state
  state="$(grep -m1 "^$1|" <<<"$DOCKER_PS" | cut -d'|' -f2)"
  printf '%s' "${state:+container $state}"
  [[ -z "$state" ]] && printf 'container down'
  return 0
}

check() {  # $1=name  $2=ok(0/1)  $3=detail
  if [[ "$2" -eq 0 ]]; then report "$1" "UP   ($3)"; else report "$1" "DOWN ($3)"; DOWN+=("$1"); fi
}

echo "==> SOC stack health $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Elasticsearch — cluster health (red counts as down).
es_status="$(es -m 6 "$ES_URL/_cluster/health" | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)"
[[ "$es_status" == "green" || "$es_status" == "yellow" ]] && check elasticsearch 0 "$es_status" || check elasticsearch 1 "${es_status:-unreachable}"

# Kibana — overall status level. #177: Kibana is TLS-only now (same stack CA as ES),
# so es()'s ES_TLS flags (-k/--cacert) are load-bearing here too, not a no-op.
# #555: capture the HTTP status alongside the body. This lane now authenticates as the
# least-privilege `soc_health` user rather than `elastic`, and the exact Kibana privilege
# GET /api/status requires was NOT verified against a live Kibana here (no reachable
# stack while this was written). A 401/403 would otherwise be indistinguishable from
# "Kibana is down" and would page someone for a permissions problem, so name it.
kb_raw="$(es -m 6 -w '\n%{http_code}' "$KIBANA_URL/api/status")"
kb_code="$(printf '%s' "$kb_raw" | tail -n 1)"
kb_level="$(printf '%s' "$kb_raw" | grep -o '"level":"[a-z]*"' | head -1 | cut -d'"' -f4)"
if [[ "$kb_level" == "available" ]]; then
  check kibana 0 "$kb_level"
elif [[ "$kb_code" == "401" || "$kb_code" == "403" ]]; then
  check kibana 1 "HTTP $kb_code — this lane's credential lacks Kibana access, not an outage"
else
  check kibana 1 "${kb_level:-unreachable}"
fi

# Logstash — node stats (:9600) if reachable, else container state.
if curl -s -m 5 "http://localhost:9600/_node/stats/pipelines" 2>/dev/null | grep -q '"pipelines"'; then
  check logstash 0 "pipeline ok"
elif container_up logstash; then
  check logstash 0 "container up"
else
  check logstash 1 "no :9600 + $(container_detail logstash)"
fi

# AI agent + broker — container state (not LAN-exposed; HMAC-gated).
container_up soc_ai_agent && check ai_agent 0 "container up" || check ai_agent 1 "$(container_detail soc_ai_agent)"
container_up hive_mind_broker && check broker 0 "container up" || check broker 1 "$(container_detail hive_mind_broker)"

# soc-slo-metrics freshness (#555). This is the OTHER half of the mutual
# cross-monitoring pair: slo_metrics.py watches soc-health, and this watches
# soc-slo-metrics. Putting both staleness checks in one lane would be circular — a
# check on soc-slo-metrics that lives inside slo_metrics.py cannot fire when
# slo_metrics.py is the thing that stopped running, which is precisely the condition
# it exists to detect and precisely what happened here (the index sat frozen at
# 2026-08-17T01:31:42Z while slo-metrics.service failed every 15 minutes).
# Default 2700s = 3x the 15-minute slo-metrics.timer interval, so a single missed or
# slow run is tolerated and a stopped lane is not.
SOC_SLO_METRICS_STALE_MAX_S="${SOC_SLO_METRICS_STALE_MAX_S:-2700}"
# security-auditor (#555, LOW 2 — T1059.004): bash recursively evaluates a variable's
# CONTENTS inside (( )), so a value of x[$(cmd)] executes cmd, and a value naming
# another variable makes the comparison silently always-false. This is reachable from
# the plain process environment (a drop-in, a cron ENV= line), not only from .env.
# Validate before it ever reaches an arithmetic context.
if [[ ! "$SOC_SLO_METRICS_STALE_MAX_S" =~ ^[1-9][0-9]*$ ]]; then
  echo "WARNING: ignoring non-numeric SOC_SLO_METRICS_STALE_MAX_S=${SOC_SLO_METRICS_STALE_MAX_S} — using 2700" >&2
  SOC_SLO_METRICS_STALE_MAX_S=2700
fi
# How far ahead of this host a document may legitimately be dated (indexer clock skew)
# before the future-timestamp branch below treats it as an anomaly. Numeric-validated
# for the same (( )) reason as the threshold above.
SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S="${SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S:-120}"
if [[ ! "$SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S" =~ ^[0-9]+$ ]]; then
  echo "WARNING: ignoring non-numeric SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S — using 120" >&2
  SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S=120
fi
slo_newest="$(esj -m 6 -X POST "$ES_URL/soc-slo-metrics/_search" \
  -d '{"size":1,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp"]}' 2>/dev/null \
  | grep -o '"@timestamp":"[^"]*"' | head -1 | cut -d'"' -f4)"
if [[ -z "$slo_newest" ]]; then
  # No hit at all: index absent, ES unreachable, or the credential is rejected. All
  # three mean the same operational fact — nobody can currently prove the SLO lane is
  # alive — so none of them may read as healthy, and this check never suppresses itself
  # on the assumption that some other check already covers it.
  #
  # It does, however, name its cause. During an Elasticsearch outage this check fires
  # alongside the `elasticsearch` one above, so a single root cause reaches the ntfy
  # push as two DOWN entries (code-reviewer, MINOR: alert-fatigue surface). Reusing
  # es_status — already resolved above — lets the second entry say WHY it could not
  # read rather than presenting as an independent second failure. The entry still
  # counts as DOWN either way; only the detail string differs.
  if [[ "$es_status" == "green" || "$es_status" == "yellow" ]]; then
    check slo_metrics 1 "no soc-slo-metrics doc readable (index empty/absent, or credential rejected)"
  else
    check slo_metrics 1 "no soc-slo-metrics doc; elasticsearch is DOWN (${es_status:-unreachable})"
  fi
elif [[ ! "$slo_newest" =~ (Z|[+-][0-9]{2}:?[0-9]{2})$ ]]; then
  # security-auditor (#555, LOW 3): `date -u` sets OUTPUT format, it does not make a
  # naive input string UTC. Elasticsearch's strict_date_optional_time accepts a value
  # with no offset, and GNU date would read that as host-local — skewing the age by up
  # to the UTC offset, easily enough to make a dead lane read fresh against a 2700s
  # window. No current writer emits one, so refusing it costs nothing and closes the
  # latent case. TZ=UTC is also pinned in stack-health.service for belt and braces.
  check slo_metrics 1 "@timestamp carries no timezone: $slo_newest"
else
  slo_epoch="$(date -u -d "$slo_newest" +%s 2>/dev/null || true)"
  if [[ -z "$slo_epoch" ]]; then
    check slo_metrics 1 "unparseable @timestamp: $slo_newest"
  else
    slo_age=$(( $(date -u +%s) - slo_epoch ))
    if (( slo_age > SOC_SLO_METRICS_STALE_MAX_S )); then
      check slo_metrics 1 "stale ${slo_age}s > ${SOC_SLO_METRICS_STALE_MAX_S}s (newest $slo_newest)"
    elif (( slo_age < -SOC_SLO_METRICS_STALE_FUTURE_TOLERANCE_S )); then
      # security-auditor (#555, MEDIUM 1 — T1562.001): a negative age is trivially
      # <= any positive threshold, so a single future-dated document used to pin this
      # check to "fresh" forever — the exact "watchdog reads healthy while the thing
      # it watches is dead" failure the whole lane exists to prevent. Reachable from a
      # compromised slo_metrics credential (it holds `create` on soc-slo-metrics),
      # from a soc_admin write, or from plain host clock skew. A small tolerance
      # absorbs benign skew between this host and the indexer; beyond it, a future
      # timestamp is itself the anomaly and is reported as one.
      check slo_metrics 1 "@timestamp is $(( -slo_age ))s in the FUTURE (newest $slo_newest) — clock skew or a forged document"
    else
      check slo_metrics 0 "fresh ${slo_age}s"
    fi
  fi
fi

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status="$([[ ${#DOWN[@]} -eq 0 ]] && echo healthy || echo degraded)"
# Record to soc-health for the dashboard (best-effort; needs ES up).
# security-auditor (#555, LOW 4): `printf '"%s",' "${DOWN[@]}"` on an EMPTY array still
# applies the format once with an empty argument, so every healthy document used to
# record "down":[""] — one element, not zero. A panel or rule written as "alert when
# `down` is non-empty" would then match every healthy run: 288 false positives a day,
# which is the practical route to the alert fatigue this lane exists to prevent. There
# is no index template for soc-health, so the first document's dynamic mapping is
# authoritative — worth getting right before the timer starts writing.
down_json="[]"
(( ${#DOWN[@]} )) && down_json="[$(printf '"%s",' "${DOWN[@]}" | sed 's/,$//')]"
esj -m 6 -o /dev/null -X POST "$ES_URL/soc-health/_doc" \
  -d "{\"@timestamp\":\"$now\",\"status\":\"$status\",\"down_count\":${#DOWN[@]},\"down\":$down_json}" 2>/dev/null

echo
if [[ ${#DOWN[@]} -eq 0 ]]; then
  green "=== All components healthy. ==="
  exit 0
else
  red "=== DOWN: ${DOWN[*]} ==="
  if [[ -n "$NTFY_TOPIC" ]]; then
    curl -s -m 6 -o /dev/null "https://ntfy.sh/${NTFY_TOPIC}" \
      -H "Title: Suburban-SOC component DOWN" -H "Priority: urgent" -H "Tags: rotating_light,skull" \
      -d "SOC components DOWN: ${DOWN[*]}" 2>/dev/null
  fi
  exit 2
fi

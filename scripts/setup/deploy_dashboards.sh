#!/usr/bin/env bash
# =============================================================================
# Suburban-SOC — Four-Dashboard Deployment Script
#
# Imports the executive / network / endpoint / data-quality dashboards plus the
# SOC navigation hub into Kibana, provisions the logstash-* data view, installs
# the Elastic Watchers, and restarts Logstash to reload the bind-mounted
# configs/logstash.conf (the single source of truth — no copy/sync step).
#
# Usage:
#   ./scripts/setup/deploy_dashboards.sh
#
# Env overrides:
#   ES_URL       (default https://localhost:9200 — security is always on)
#   KIBANA_URL   (default https://localhost:5601 — #177: Kibana is TLS-only now)
#   ES_USER      (default elastic)
#   ES_PASS      (default $ELASTIC_PASSWORD from scripts/setup/.env)
#   ES_CA        (path to ca.crt; fails closed without it unless ES_INSECURE=true)
# =============================================================================
set -euo pipefail

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

# Resolve repo root from this script's location (scripts/setup/ -> repo root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_DIR="$REPO_ROOT/configs/server"
WATCHER_DIR="$REPO_ROOT/rules/elastic_watcher"
LOGSTASH_SRC="$REPO_ROOT/configs/logstash.conf"

# Load stack secrets from scripts/setup/.env if present (so ES_PASS need not be
# exported by hand). Never commit .env.
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  set -a; . "$SCRIPT_DIR/.env"; set +a
fi

# Security is always on (WS0.1): ES is HTTPS + authenticated. #177: Kibana is now
# TLS-only too (same stack CA), so KIBANA_URL defaults to https.
KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
# Shared ES creds + TLS + helpers (issue #156).
source "$SCRIPT_DIR/lib/es_common.sh"
# Basic-auth + TLS (ES + Kibana share both — same creds, same CA). Used for every
# ES and Kibana call below (#177: TLS is now load-bearing for Kibana calls too).
AUTH=("${ES_AUTH[@]}" "${ES_TLS[@]}")

DASHBOARDS=(
  "executive_dashboard.ndjson"
  "network_dashboard_v3.ndjson"
  "endpoint_dashboard.ndjson"
  "dataquality_dashboard.ndjson"
  "soc_navigation_hub.ndjson"
  "intel_feed_health.ndjson"
  "asset_inventory.ndjson"
  "slo_dashboard.ndjson"
  "hunts_dashboard.ndjson"
  "control_status_dashboard.ndjson"  # WS3.7 SOC 2 continuous control monitoring
)

# -----------------------------------------------------------------------------
# 1. Pre-flight — Elasticsearch + Kibana reachable
# -----------------------------------------------------------------------------
blue "==> [1/7] Validating Elasticsearch at ${ES_URL}"
if ! curl -fsS "${AUTH[@]}" "${ES_URL}" >/dev/null 2>&1; then
  red "ERROR: Elasticsearch not reachable/authenticated at ${ES_URL}. Is the stack up (docker compose up -d) and ES_PASS correct?"
  exit 1
fi
green "    Elasticsearch is up (authenticated)."

blue "==> [2/7] Validating Kibana at ${KIBANA_URL}"
if ! curl -fsS "${AUTH[@]}" "${KIBANA_URL}/api/status" >/dev/null 2>&1; then
  red "ERROR: Kibana not reachable at ${KIBANA_URL}/api/status. Give it a minute to start (and check ES_PASS)."
  exit 1
fi
green "    Kibana is up."

# -----------------------------------------------------------------------------
# 2. Provision the logstash-* data view (id: logstash-pattern)
# -----------------------------------------------------------------------------
blue "==> [3/7] Ensuring data views exist (logstash-pattern, soar-actions-pattern)"
# Use the Data Views API (NOT the low-level saved-objects API) so the data view
# is created complete — with field caps. A field-less index-pattern object makes
# aggregation-based visualizations throw "cannot read properties of undefined"
# and one throwing panel trips Kibana's error boundary, blanking the whole board.
create_data_view() {  # $1=id  $2=title  $3=allowNoIndex(true/false)
  curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
    -X POST "${KIBANA_URL}/api/data_views/data_view" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -d "{\"override\":true,\"data_view\":{\"id\":\"$1\",\"name\":\"$2\",\"title\":\"$2\",\"timeFieldName\":\"@timestamp\",\"allowNoIndex\":$3}}" || true
}
code=$(create_data_view "logstash-pattern" "logstash-*" "false")
[[ "$code" =~ ^20 ]] && green "    logstash-pattern ready (HTTP ${code})." || red "    WARN: logstash-pattern -> HTTP ${code}"
code=$(create_data_view "soar-actions-pattern" "soar-actions-*" "true")
[[ "$code" =~ ^20 ]] && green "    soar-actions-pattern ready (HTTP ${code})." || red "    WARN: soar-actions-pattern -> HTTP ${code}"
# WS1.3: data view for the threat-intel feed-health panel (intel_feed_health.ndjson).
code=$(create_data_view "threat-intel-meta-pattern" "threat-intel-meta*" "true")
[[ "$code" =~ ^20 ]] && green "    threat-intel-meta-pattern ready (HTTP ${code})." || red "    WARN: threat-intel-meta-pattern -> HTTP ${code}"
# WS1.4: the asset inventory dashboard is conn-derived — it reuses logstash-pattern,
# so no extra data view is needed.
# WS2.4: data view for the SLO dashboard (slo_dashboard.ndjson).
code=$(create_data_view "soc-slo-pattern" "soc-slo-metrics*" "true")
[[ "$code" =~ ^20 ]] && green "    soc-slo-pattern ready (HTTP ${code})." || red "    WARN: soc-slo-pattern -> HTTP ${code}"
# WS2.2: data view for the threat-hunt findings dashboard (hunts_dashboard.ndjson).
code=$(create_data_view "soc-hunts-pattern" "soc-hunts*" "true")
[[ "$code" =~ ^20 ]] && green "    soc-hunts-pattern ready (HTTP ${code})." || red "    WARN: soc-hunts-pattern -> HTTP ${code}"

# -----------------------------------------------------------------------------
# 3. Import all dashboard bundles
# -----------------------------------------------------------------------------
blue "==> [4/7] Importing dashboard bundles"
imported=0
for f in "${DASHBOARDS[@]}"; do
  path="${SERVER_DIR}/${f}"
  if [[ ! -f "$path" ]]; then
    red "    SKIP (missing): ${f}"
    continue
  fi
  resp=$(curl -s "${AUTH[@]}" -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H 'kbn-xsrf: true' --form file=@"${path}" || true)
  if echo "$resp" | grep -q '"success":true'; then
    green "    Imported ${f}"
    imported=$((imported+1))
  else
    red   "    FAILED ${f}: ${resp}"
  fi
done

# -----------------------------------------------------------------------------
# 4. Install / update Elastic Watchers (best-effort; needs Watcher feature)
# -----------------------------------------------------------------------------
blue "==> [5/7] Installing Elastic Watchers"
watchers=0
if [[ -d "$WATCHER_DIR" ]]; then
  for w in "$WATCHER_DIR"/*.json; do
    [[ -e "$w" ]] || continue
    wid="$(basename "$w" .json)"
    code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
      -X PUT "${ES_URL}/_watcher/watch/${wid}" \
      -H 'Content-Type: application/json' --data-binary @"$w" || true)
    if [[ "$code" =~ ^20 ]]; then
      green "    Installed watcher ${wid} (HTTP ${code})"
      watchers=$((watchers+1))
    else
      red   "    WARN: watcher ${wid} -> HTTP ${code} (Watcher may require a trial/Gold license)"
    fi
  done
else
  red "    No watcher directory at ${WATCHER_DIR}"
fi

# #267: soar_quarantine_alert was retired (moved out of $WATCHER_DIR so the
# loop above stops installing it) but a cluster this script already ran
# against still has it ACTIVE on a 1-minute schedule - retirement only
# stops future installs, it does not un-install what is already there.
# Idempotent: 404 (already gone / never installed) counts as success.
del_code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
  -X DELETE "${ES_URL}/_watcher/watch/soar_quarantine_alert" || true)
if [[ "$del_code" =~ ^(20|404) ]]; then
  green "    Removed retired watcher soar_quarantine_alert (HTTP ${del_code})"
else
  red   "    WARN: could not remove retired watcher soar_quarantine_alert -> HTTP ${del_code}"
fi

# -----------------------------------------------------------------------------
# 5b. Install the data lifecycle (WS0.5): ILM + snapshots + data-stream templates
# -----------------------------------------------------------------------------
# Must run BEFORE the Logstash restart so the data_stream templates exist when the
# pipeline reloads and starts writing `create` ops to logstash-security-<tenant>.
blue "==> [6/7] Installing data lifecycle (ILM + snapshots + data-stream templates)"
LIFECYCLE_SCRIPT="$REPO_ROOT/configs/elasticsearch/apply-lifecycle.sh"
if [[ -f "$LIFECYCLE_SCRIPT" ]]; then
  # Pass creds explicitly: apply-lifecycle.sh runs as a child (and in-container,
  # un-migrated) so it can't rely on this shell's lib-set, non-exported vars.
  if ES_URL="$ES_URL" ES_USER="$ES_USER" ES_PASS="$ES_PASS" bash "$LIFECYCLE_SCRIPT"; then
    green "    Data lifecycle installed."
  else
    red "    WARN: apply-lifecycle.sh reported an error (is path.repo + the snapshots volume deployed? re-run docker compose up -d)."
  fi
else
  red "    WARN: ${LIFECYCLE_SCRIPT} not found — ILM/snapshots not installed."
fi

# -----------------------------------------------------------------------------
# 6. Restart Logstash to apply the pipeline config
# -----------------------------------------------------------------------------
# configs/logstash.conf is the single source of truth and is bind-mounted into
# the container directly by docker-compose.yml (../../configs/logstash.conf), so
# there is no copy/sync step — we only need to restart Logstash to reload it.
blue "==> [7/7] Restarting Logstash to apply configs/logstash.conf"
if [[ -f "$LOGSTASH_SRC" ]]; then
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^logstash$'; then
    docker restart logstash >/dev/null && green "    Restarted Logstash container."
  else
    red "    NOTE: Logstash container not running — restart it manually to apply config."
  fi
else
  red "    WARN: ${LOGSTASH_SRC} not found — pipeline config is missing."
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo
green "=================== DEPLOYMENT SUMMARY ==================="
printf '  Dashboards imported : %s / %s\n' "$imported" "${#DASHBOARDS[@]}"
printf '  Watchers installed  : %s\n' "$watchers"
printf '  Kibana              : %s/app/dashboards\n' "$KIBANA_URL"
echo  "  Dashboard IDs       : executive-dashboard, network-dashboard-v3,"
echo  "                        endpoint-dashboard, dataquality-dashboard,"
echo  "                        soc-navigation-hub"
green "========================================================="
# WS3.5: record the change (deploy changelog evidence).
bash "$SCRIPT_DIR/deploy_changelog.sh" "dashboards" "imported ${imported}/${#DASHBOARDS[@]} dashboards + data views/watchers" 2>/dev/null || true

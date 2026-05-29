#!/usr/bin/env bash
# =============================================================================
# Suburban-SOC — Four-Dashboard Deployment Script
#
# Imports the executive / network / endpoint / data-quality dashboards plus the
# SOC navigation hub into Kibana, provisions the logstash-* data view, installs
# the Elastic Watchers, and syncs the enriched logstash.conf into the Docker
# mount before restarting Logstash.
#
# Usage:
#   ./scripts/setup/deploy_dashboards.sh
#
# Env overrides:
#   ES_URL       (default http://localhost:9200)
#   KIBANA_URL   (default http://localhost:5601)
#   ES_USER / ES_PASS   (only if xpack.security is enabled)
# =============================================================================
set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"

# Resolve repo root from this script's location (scripts/setup/ -> repo root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_DIR="$REPO_ROOT/configs/server"
WATCHER_DIR="$REPO_ROOT/rules/elastic_watcher"
LOGSTASH_SRC="$REPO_ROOT/configs/logstash.conf"
LOGSTASH_MOUNT="$REPO_ROOT/scripts/setup/configs/logstash/logstash.conf"

# Optional basic-auth (only used if ES_USER is set)
CURL_AUTH=()
if [[ -n "${ES_USER:-}" ]]; then
  CURL_AUTH=(-u "${ES_USER}:${ES_PASS:-}")
fi

DASHBOARDS=(
  "executive_dashboard.ndjson"
  "network_dashboard_v3.ndjson"
  "endpoint_dashboard.ndjson"
  "dataquality_dashboard.ndjson"
  "soc_navigation_hub.ndjson"
)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

# -----------------------------------------------------------------------------
# 1. Pre-flight — Elasticsearch + Kibana reachable
# -----------------------------------------------------------------------------
blue "==> [1/6] Validating Elasticsearch at ${ES_URL}"
if ! curl -fsS "${CURL_AUTH[@]}" "${ES_URL}" >/dev/null 2>&1; then
  red "ERROR: Elasticsearch not reachable at ${ES_URL}. Is the stack up (docker compose up -d)?"
  exit 1
fi
green "    Elasticsearch is up."

blue "==> [2/6] Validating Kibana at ${KIBANA_URL}"
if ! curl -fsS "${KIBANA_URL}/api/status" >/dev/null 2>&1; then
  red "ERROR: Kibana not reachable at ${KIBANA_URL}/api/status. Give it a minute to start."
  exit 1
fi
green "    Kibana is up."

# -----------------------------------------------------------------------------
# 2. Provision the logstash-* data view (id: logstash-pattern)
# -----------------------------------------------------------------------------
blue "==> [3/6] Ensuring 'logstash-pattern' data view exists"
http_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/logstash-pattern?overwrite=true" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{"attributes":{"title":"logstash-*","timeFieldName":"@timestamp"}}' || true)
if [[ "$http_code" =~ ^20 ]]; then
  green "    logstash-pattern ready (HTTP ${http_code})."
else
  red "    WARN: data view create returned HTTP ${http_code} (may already exist / differ)."
fi

# -----------------------------------------------------------------------------
# 3. Import all dashboard bundles
# -----------------------------------------------------------------------------
blue "==> [4/6] Importing dashboard bundles"
imported=0
for f in "${DASHBOARDS[@]}"; do
  path="${SERVER_DIR}/${f}"
  if [[ ! -f "$path" ]]; then
    red "    SKIP (missing): ${f}"
    continue
  fi
  resp=$(curl -s -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
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
blue "==> [5/6] Installing Elastic Watchers"
watchers=0
if [[ -d "$WATCHER_DIR" ]]; then
  for w in "$WATCHER_DIR"/*.json; do
    [[ -e "$w" ]] || continue
    wid="$(basename "$w" .json)"
    code=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_AUTH[@]}" \
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

# -----------------------------------------------------------------------------
# 5. Sync enriched logstash.conf to the Docker mount + restart Logstash
# -----------------------------------------------------------------------------
blue "==> [6/6] Syncing logstash.conf to Docker mount + restarting Logstash"
if [[ -f "$LOGSTASH_SRC" ]]; then
  # Best-effort dir create; the mount dir normally already exists. Guarded so a
  # read-only/UNC parent (e.g. running from a \\wsl.localhost share) can't abort.
  mount_dir="$(dirname "$LOGSTASH_MOUNT")"
  [[ -d "$mount_dir" ]] || mkdir -p "$mount_dir" 2>/dev/null || true
  cp "$LOGSTASH_SRC" "$LOGSTASH_MOUNT"
  green "    Synced configs/logstash.conf -> scripts/setup/configs/logstash/logstash.conf"
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^logstash$'; then
    docker restart logstash >/dev/null && green "    Restarted Logstash container."
  else
    red "    NOTE: Logstash container not running — restart it manually to apply config."
  fi
else
  red "    WARN: ${LOGSTASH_SRC} not found — skipped sync."
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

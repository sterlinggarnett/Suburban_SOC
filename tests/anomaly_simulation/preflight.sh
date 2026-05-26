#!/usr/bin/env bash
# =============================================================================
# preflight.sh — gate every prereq for the SOP-022 live-lab session
#
# Runs through the prereq table from docs/SOP-022-anomaly-validation.md and
# prints a single-line PASS / FAIL per check. Exits non-zero on the first
# failure so the operator can fix one thing at a time.
#
# Run from anywhere; the script resolves its own dir to load .env.
# =============================================================================

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

[[ -f .env ]] && set -a && source .env && set +a

# --- Defaults (mirror .env.example) ---
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
ES_URL="${ES_URL:-http://localhost:9200}"
ES_INDEX="${ES_INDEX:-logstash-security-*}"
AGENT_URL="${AGENT_URL:-http://localhost:5000}"
OPENWRT_HOST="${OPENWRT_HOST:-192.168.1.1}"
OPENWRT_USER="${OPENWRT_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hivemind}"
WATCHER_NAME="${WATCHER_NAME:-soar_quarantine_alert}"

FAILS=0
WARNS=0

# Only emit ANSI colors when stdout is a TTY (and not a dumb terminal).
if [[ -t 1 && "${TERM:-}" != "dumb" ]]; then
  C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
  C_GREEN=''; C_RED=''; C_YELLOW=''; C_RESET=''
fi

green()  { printf '  [%sPASS%s] %s\n' "$C_GREEN" "$C_RESET" "$1"; }
red()    { printf '  [%sFAIL%s] %s\n' "$C_RED"   "$C_RESET" "$1" >&2; FAILS=$((FAILS+1)); }
yellow() { printf '  [%sWARN%s] %s\n' "$C_YELLOW" "$C_RESET" "$1"; WARNS=$((WARNS+1)); }

section() { echo; echo "=== $1 ==="; }

# --- Host binaries ---
section "Host binaries"
for bin in nmap sshpass curl ssh python3; do
  if command -v "$bin" >/dev/null 2>&1; then
    green "$bin available ($(command -v "$bin"))"
  else
    red "$bin missing — sudo apt install $bin"
  fi
done

# --- Python deps ---
section "Python dependencies"
if python3 -c "import elasticsearch" 2>/dev/null; then
  ver=$(python3 -c "import elasticsearch; print(elasticsearch.__version__)")
  green "elasticsearch python client installed (${ver})"
else
  red "elasticsearch python client missing — pip install -r requirements.txt"
fi

# --- Config file ---
section "Configuration"
if [[ -f .env ]]; then
  green ".env present"
else
  yellow ".env not found — using defaults from .env.example (recommended: cp .env.example .env first)"
fi

# --- Elasticsearch ---
section "Elasticsearch (${ES_URL})"
if curl -fsS --max-time 5 "${ES_URL}" >/dev/null 2>&1; then
  green "ES cluster reachable"
  if curl -fsS --max-time 5 "${ES_URL}/${ES_INDEX//\*/}_search?size=0" 2>/dev/null \
       | grep -q '"hits"'; then
    green "index pattern ${ES_INDEX} returns hits"
  else
    yellow "index ${ES_INDEX} returns no hits — run a Zeek capture first per SOP-001"
  fi
else
  red "ES not reachable at ${ES_URL} — start with: docker compose up -d"
fi

# --- AI Agent ---
section "AI Agent (${AGENT_URL})"
if curl -fsS --max-time 5 "${AGENT_URL}/weekly-report/status" >/dev/null 2>&1; then
  green "AI agent responding on ${AGENT_URL}"
else
  red "AI agent not responding — start with: (cd scripts/setup/ai_agent && flask --app agent_app run --host 0.0.0.0 --port 5000)"
fi

# --- Kibana Watcher ---
section "Kibana Watcher (${WATCHER_NAME})"
watcher_resp=$(curl -fsS --max-time 5 "${ES_URL}/_watcher/watch/${WATCHER_NAME}" 2>/dev/null || true)
if echo "$watcher_resp" | grep -q '"found":true'; then
  green "Watcher ${WATCHER_NAME} installed"
elif echo "$watcher_resp" | grep -q '"_id"'; then
  green "Watcher ${WATCHER_NAME} installed"
elif [[ -z "$watcher_resp" ]]; then
  red "Watcher API unreachable or auth required — confirm ES_USER/ES_PASS in .env if x-pack security is on"
else
  red "Watcher ${WATCHER_NAME} not installed — see Step 5 of SOP-022"
fi

# --- OpenWrt SSH ---
section "OpenWrt SSH (${OPENWRT_USER}@${OPENWRT_HOST})"
if [[ ! -r "$SSH_KEY" ]]; then
  red "SSH key not readable: ${SSH_KEY}"
else
  green "SSH key readable: ${SSH_KEY}"
  set +e
  ssh -i "$SSH_KEY" \
      -o StrictHostKeyChecking=no \
      -o BatchMode=yes \
      -o ConnectTimeout=5 \
      "${OPENWRT_USER}@${OPENWRT_HOST}" \
      "uci show firewall >/dev/null 2>&1 && echo ok" 2>/dev/null | grep -q ok
  ssh_rc=$?
  set -e
  if [[ $ssh_rc -eq 0 ]]; then
    green "OpenWrt SSH + uci access working"
  else
    red "OpenWrt SSH failed (rc=${ssh_rc}) — verify key is authorized on router"
  fi
fi

# --- Optional: Discord webhook ---
section "Optional integrations"
if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
  green "DISCORD_WEBHOOK_URL set (embeds will be delivered)"
else
  yellow "DISCORD_WEBHOOK_URL not set — Discord embeds will be skipped (graceful no-op)"
fi

# --- Summary ---
section "Summary"
if [[ $FAILS -gt 0 ]]; then
  echo "  $FAILS prereq(s) failed, $WARNS warning(s). Resolve failures before running run_all.sh." >&2
  exit 1
fi
if [[ $WARNS -gt 0 ]]; then
  echo "  All hard prereqs satisfied. $WARNS warning(s) — review before live run."
else
  echo "  All checks passed. Ready for SOP-022 live-lab session."
fi

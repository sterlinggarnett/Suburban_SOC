#!/usr/bin/env bash
# =============================================================================
# sim_outbound_volume_asymmetry.sh — #441 Part B scenario: Asymmetric Outbound
# Connection Volume (Possible Exfiltration)
#
# Pushes a locally-generated ~6 MB dummy file one-way over a plain TCP
# connection to TARGET_HOST:TARGET_PORT — a real, wire-visible flow with
# orig_bytes well above the rule's 5MB threshold and resp_bytes near zero
# (well below its 200KB threshold), since nothing is expected to echo data
# back. No third-party service, cloud provider, or external network contact —
# entirely local-network traffic, matching sim_portscan.sh's own
# LOCAL-TARGET-ONLY convention (unlike sim_malware_download.sh's deliberate,
# purpose-built eicar.org exception).
#
# REQUIRES a listener already running on TARGET_HOST, the same "assume a real
# service is there" convention sim_brute_ssh.sh uses for SSH — this script
# does not stand one up itself. On the target:
#   nc -l -p "${TARGET_PORT:-9797}" > /dev/null &
# (or any TCP listener that discards input; the payload content is a
# throwaway placeholder, not something Zeek or this rule inspects).
#
# Expected Zeek detection: conn.log record with orig_bytes>=5000000 and
# resp_bytes<=200000 — net_zeek_conn_outbound_volume_asymmetry.yml's
# single-flow logic-of-record. Run this script 3+ times within a 30-minute
# window from the same source to also exercise the paired threshold rule
# (rules/elastic/threshold/net-zeek-conn-outbound-volume-asymmetry.ndjson),
# which is the actual deployed enforcement — see that file's own description.
# =============================================================================

set -euo pipefail

ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
  while IFS='=' read -r _k _v; do
    [[ "$_k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -n "${!_k+x}" ]] && continue
    _v="${_v%\"}"; _v="${_v#\"}"
    export "$_k=$_v"
  done < "$ENV_FILE"
fi

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-9797}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-6000000}"
PAYLOAD="$(mktemp)"
trap 'rm -f "$PAYLOAD"' EXIT

if ! command -v nc >/dev/null 2>&1; then
  echo "[ERROR] nc (netcat) not installed. sudo apt install netcat-openbsd" >&2
  exit 2
fi

echo "[*] Outbound volume asymmetry sim: generating a ${PAYLOAD_BYTES}-byte dummy payload"
head -c "$PAYLOAD_BYTES" /dev/urandom > "$PAYLOAD"

echo "[*] Pushing to ${TARGET_HOST}:${TARGET_PORT} (requires a listener already running there — see this script's own header)"
echo "[*] Expected Zeek detection: conn.log -> orig_bytes>=5000000, resp_bytes<=200000"
nc -w 5 "$TARGET_HOST" "$TARGET_PORT" < "$PAYLOAD" || {
  echo "[ERROR] Could not connect to ${TARGET_HOST}:${TARGET_PORT} — is a listener running there? See this script's header for the nc -l command to start one." >&2
  exit 1
}

echo "[+] Push complete. Allow ~30s for Zeek + Logstash to index."

#!/usr/bin/env bash
# =============================================================================
# sim_lnx_ingress_tool_transfer.sh — #441 Part A scenario: Linux Ingress Tool
# Transfer via curl/wget to a Temp Path or Piped to a Shell
#
# Pulls the same EICAR test file sim_malware_download.sh already uses
# (universally-recognized AV/IDS test signature — safe, purpose-built for
# exactly this kind of automated testing) into /tmp — matching the rule's
# temp-path branch. No pipe-to-shell variant here (that would actually
# execute the fetched content); the temp-path branch alone is a real,
# reversible signal.
#
# REQUIRES #442's auditd execve telemetry actually deployed and working on
# this host — not live-verified against a real auditd stream in the
# environment this was written in (see #442's own disclosed caveat).
#
# Expected detection: rules/sigma/proc_creation_lnx_ingress_tool_transfer.yml
# (selection_temp_dest branch).
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

URL="${MALWARE_SAMPLE_URL:-https://secure.eicar.org/eicar_com.zip}"
DEST="/tmp/sim_lnx_ingress_sample.zip"

echo "[*] Ingress-tool-transfer sim: curl pulling $URL into $DEST"
echo "[*] Expected detection: proc_creation_lnx_ingress_tool_transfer.yml"
curl -fsSL -o "$DEST" "$URL"

echo "[*] Cleaning up (reversible)."
rm -f "$DEST"

echo "[+] Sim complete. Allow ~30s for auditd + Filebeat + Logstash to index."

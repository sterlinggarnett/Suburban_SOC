#!/usr/bin/env bash
# =============================================================================
# sim_portscan.sh — Issue #22 scenario 1: Network Reconnaissance
#
# Runs a SYN scan that Zeek's Scan::Port_Scan policy should flag as a notice.
# Output appears in zeek.notice with note=Scan::Port_Scan.
# =============================================================================

set -euo pipefail

# Load .env for defaults, but let variables already set in the environment
# (e.g. `TARGET_HOST=10.18.81.59 ./sim_portscan.sh`) take precedence — sourcing
# the file directly would clobber CLI/env overrides.
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
  while IFS='=' read -r _k _v; do
    [[ "$_k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue   # skip comments / blank lines
    [[ -n "${!_k+x}" ]] && continue                       # keep an existing env/CLI override
    _v="${_v%\"}"; _v="${_v#\"}"                           # strip surrounding double-quotes
    export "$_k=$_v"
  done < "$ENV_FILE"
fi

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[ERROR] nmap not installed. sudo apt install nmap" >&2
  exit 2
fi

echo "[*] Port scan sim: TCP SYN scan of $TARGET_HOST, ports 1-1024"
echo "[*] Expected Zeek detection: notice.log → Scan::Port_Scan"

# -sT TCP connect scan (no root needed; a half-open -sS scan requires
# CAP_NET_RAW). Zeek's new_connection fires per probed port either way, so
# the scan-detection policy still flags it. #331 investigated and rejected
# two sensor-side fixes for a spoofed-source metric-gaming concern (neither
# actually defended against spoofing at this deployment's capture vantage
# point without losing real detection recall for scan types like this one)
# - scan-detection.zeek itself is unchanged; #331's actual fix is a
# distinct-source signal added to slo_metrics.py's raw_alert_volume metric
# instead. -T4 aggressive timing, -Pn skip host-discovery (so the full
# sweep runs even against unresponsive hosts), -n no DNS resolution.
nmap -sT -T4 -Pn -n -p 1-1024 "$TARGET_HOST" >/dev/null

echo "[+] Scan complete. Allow ~30s for Zeek + Logstash to index."

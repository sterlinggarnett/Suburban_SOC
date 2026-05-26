#!/usr/bin/env bash
# =============================================================================
# sim_portscan.sh — Issue #22 scenario 1: Network Reconnaissance
#
# Runs a SYN scan that Zeek's Scan::Port_Scan policy should flag as a notice.
# Output appears in zeek.notice with note=Scan::Port_Scan.
# =============================================================================

set -euo pipefail

# Load .env if present
[[ -f "$(dirname "$0")/.env" ]] && set -a && source "$(dirname "$0")/.env" && set +a

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[ERROR] nmap not installed. sudo apt install nmap" >&2
  exit 2
fi

echo "[*] Port scan sim: TCP SYN scan of $TARGET_HOST, ports 1-1024"
echo "[*] Expected Zeek detection: notice.log → Scan::Port_Scan"

# -sS SYN scan, -T4 aggressive timing, -Pn skip host-discovery (so Zeek sees the
# full attack pattern even against unresponsive hosts), -n no DNS resolution.
nmap -sS -T4 -Pn -n -p 1-1024 "$TARGET_HOST" >/dev/null

echo "[+] Scan complete. Allow ~30s for Zeek + Logstash to index."

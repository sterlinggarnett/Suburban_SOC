#!/bin/bash
# =============================================================================
# isolate.sh — Suburban-SOC SOAR Quarantine Script
# Phase C: OpenWrt uci MAC-based device isolation
#
# Usage:
#   ./isolate.sh <MAC_ADDRESS>
#   Example: ./isolate.sh AA:BB:CC:DD:EE:FF
#
# This script connects to the OpenWrt router via SSH and injects a
# permanent firewall DROP rule targeting the specified MAC address.
# The rule persists across reboots via uci commit.
#
# Prerequisites:
#   - SSH key ~/.ssh/id_ed25519_hivemind must be authorized on the router
#   - OPENWRT_HOST env var set to router IP (default: 192.168.1.1)
#   - OPENWRT_USER env var set (default: root)
# =============================================================================

set -euo pipefail

TARGET_MAC="${1:-}"
OPENWRT_HOST="${OPENWRT_HOST:-192.168.1.1}"
OPENWRT_USER="${OPENWRT_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_hivemind}"

# --- Validate input ---
if [[ -z "$TARGET_MAC" ]]; then
  echo "[ERROR] No MAC address provided." >&2
  echo "Usage: $0 <MAC_ADDRESS>" >&2
  exit 1
fi

# Basic MAC format validation (accepts both XX:XX:XX:XX:XX:XX and XX-XX-XX-XX-XX-XX)
if ! echo "$TARGET_MAC" | grep -qE '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'; then
  echo "[ERROR] Invalid MAC address format: $TARGET_MAC" >&2
  exit 1
fi

echo "[*] Initiating quarantine for device: $TARGET_MAC"
echo "[*] Connecting to OpenWrt router at $OPENWRT_HOST..."

# --- Execute uci firewall rule injection via SSH ---
ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    "${OPENWRT_USER}@${OPENWRT_HOST}" \
    "uci add firewall rule && \
     uci set firewall.@rule[-1].name='SOAR_QUARANTINE_${TARGET_MAC//:/}' && \
     uci set firewall.@rule[-1].src='lan' && \
     uci set firewall.@rule[-1].src_mac='${TARGET_MAC}' && \
     uci set firewall.@rule[-1].target='DROP' && \
     uci set firewall.@rule[-1].enabled='1' && \
     uci commit firewall && \
     /etc/init.d/firewall restart"

EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
  echo "[+] SUCCESS: Device $TARGET_MAC has been quarantined on $OPENWRT_HOST"
else
  echo "[-] FAILURE: Could not quarantine $TARGET_MAC on $OPENWRT_HOST (exit code: $EXIT_CODE)" >&2
  exit $EXIT_CODE
fi

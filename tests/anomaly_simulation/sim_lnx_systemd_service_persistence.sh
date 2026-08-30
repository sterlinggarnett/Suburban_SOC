#!/usr/bin/env bash
# =============================================================================
# sim_lnx_systemd_service_persistence.sh — #441 Part A scenario: Linux
# systemd Service Persistence
#
# Writes a throwaway, inert systemd unit (ExecStart is /bin/true — never
# started) into /etc/systemd/system/, runs `systemctl enable` and
# `systemctl daemon-reload` against it, then disables and removes it. Needs
# root (via sudo) — skipped, not failed, if passwordless sudo isn't
# available, matching this repo's other root-requiring sims' convention.
#
# REQUIRES #442's auditd execve telemetry actually deployed and working on
# this host — not live-verified against a real auditd stream in the
# environment this was written in (see #442's own disclosed caveat).
#
# Expected detection: rules/sigma/proc_creation_lnx_systemd_service_persistence.yml
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

if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
  echo "[!] No passwordless sudo — skipping this sim (not a failure; systemd unit persistence needs root)."
  exit 0
fi

UNIT="/etc/systemd/system/suburban-soc-sim-throwaway.service"
echo "[*] systemd-service-persistence sim: writing a throwaway inert unit to $UNIT"
echo "[*] Expected detection: proc_creation_lnx_systemd_service_persistence.yml"
printf '[Unit]\nDescription=Suburban-SOC emulation sim (throwaway)\n\n[Service]\nType=oneshot\nExecStart=/bin/true\n' \
  | sudo tee "$UNIT" > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable suburban-soc-sim-throwaway.service

echo "[*] Cleaning up (reversible)."
sudo systemctl disable suburban-soc-sim-throwaway.service 2>/dev/null || true
sudo rm -f "$UNIT"
sudo systemctl daemon-reload

echo "[+] Sim complete. Allow ~30s for auditd + Filebeat + Logstash to index."

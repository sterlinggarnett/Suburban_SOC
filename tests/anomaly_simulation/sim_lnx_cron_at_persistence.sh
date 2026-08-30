#!/usr/bin/env bash
# =============================================================================
# sim_lnx_cron_at_persistence.sh — #441 Part A scenario: Linux Cron/At Job
# Persistence
#
# Exercises all three of the rule's branches, each reversible:
#   1. crontab -e (a real interactive edit isn't scriptable — installs the
#      CURRENT user crontab unchanged via `crontab -l | crontab -`, the
#      standard non-interactive equivalent that still invokes crontab with
#      no -l/-r flag, matching the rule's own write-shaped condition).
#   2. A throwaway file written into /etc/cron.d/ (needs root — skipped,
#      not failed, if sudo isn't available) then immediately removed.
#   3. `at` scheduling a no-op job one minute out, then removed via atrm
#      before it would ever run (skipped, not failed, if `at` isn't
#      installed — not every distro ships it by default).
#
# REQUIRES #442's auditd execve telemetry actually deployed and working on
# this host — not live-verified against a real auditd stream in the
# environment this was written in (see #442's own disclosed caveat).
#
# Expected detection: rules/sigma/proc_creation_lnx_cron_at_persistence.yml
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

echo "[*] Cron/at-persistence sim: re-installing the current user crontab (crontab branch)"
echo "[*] Expected detection: proc_creation_lnx_cron_at_persistence.yml"
if command -v crontab >/dev/null 2>&1; then
  CRON_BACKUP="$(mktemp)"
  trap 'rm -f "$CRON_BACKUP"' EXIT
  crontab -l > "$CRON_BACKUP" 2>/dev/null || true  # empty file if no crontab exists yet
  crontab "$CRON_BACKUP"
  echo "[*] crontab re-installed (unchanged content)."
else
  echo "[!] crontab not installed — skipping the crontab branch (not a failure)."
fi

if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  CRON_D_FILE="/etc/cron.d/suburban-soc-sim-throwaway"
  echo "[*] Writing a throwaway cron.d entry (cron-directory-write branch)."
  echo "# Suburban-SOC emulation sim — throwaway, removed immediately" | sudo tee "$CRON_D_FILE" > /dev/null
  sudo rm -f "$CRON_D_FILE"
else
  echo "[!] No passwordless sudo — skipping the /etc/cron.d/ write branch (not a failure)."
fi

if command -v at >/dev/null 2>&1; then
  echo "[*] Scheduling a no-op via at (at branch), then removing it before it runs."
  JOB_ID="$(echo "true" | at now + 1 minute 2>&1 | grep -oE 'job [0-9]+' | awk '{print $2}' || true)"
  [[ -n "$JOB_ID" ]] && atrm "$JOB_ID" 2>/dev/null || true
else
  echo "[!] at not installed — skipping the at branch (not a failure)."
fi

echo "[+] Sim complete. Allow ~30s for auditd + Filebeat + Logstash to index."

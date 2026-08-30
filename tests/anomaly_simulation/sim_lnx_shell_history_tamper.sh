#!/usr/bin/env bash
# =============================================================================
# sim_lnx_shell_history_tamper.sh — #441 Part A scenario: Linux Shell History
# Tampering
#
# Runs `history -c` in a disposable subshell (does NOT clear the real
# interactive session's history — a child bash process has its own,
# separate in-memory history, discarded when it exits) and separately
# demonstrates the symlink-to-/dev/null branch against a THROWAWAY history
# file, never the real ~/.bash_history.
#
# REQUIRES #442's auditd execve telemetry actually deployed and working on
# this host — not live-verified against a real auditd stream in the
# environment this was written in (see #442's own disclosed caveat).
#
# Expected detection: rules/sigma/proc_creation_lnx_shell_history_tamper.yml
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

echo "[*] Shell-history-tamper sim: 'history -c' in a disposable subshell"
echo "[*] Expected detection: proc_creation_lnx_shell_history_tamper.yml"
bash -c "history -c" || true

THROWAWAY="$(mktemp -u).bash_history"
touch "$THROWAWAY"
echo "[*] Symlinking a throwaway .bash_history-named file to /dev/null (symlink branch, never the real history file)."
bash -c "ln -sf /dev/null ${THROWAWAY}"
rm -f "$THROWAWAY"

echo "[+] Sim complete. Allow ~30s for auditd + Filebeat + Logstash to index."

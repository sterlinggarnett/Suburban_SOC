#!/usr/bin/env bash
# =============================================================================
# sim_lnx_reverse_shell.sh — #441 Part A scenario: Linux Reverse Shell via
# Interpreter Redirect or Exec Flag
#
# Runs bash's /dev/tcp/ idiom against a LOCAL loopback listener this script
# starts itself — no real backdoor, no external contact. Connects, sends one
# benign line, and closes immediately.
#
# REQUIRES #442's auditd execve telemetry actually deployed and working on
# this host (audit.rules loaded, Filebeat shipping /var/log/audit/audit.log)
# — not live-verified against a real auditd stream in the environment this
# was written in (see #442's own disclosed caveat).
#
# Expected detection: rules/sigma/proc_creation_lnx_reverse_shell_interpreter.yml
# (selection_bash_dev_tcp branch — process.args contains "/dev/tcp/").
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

PORT="${SIM_LNX_REVSHELL_PORT:-4444}"

if ! command -v nc >/dev/null 2>&1; then
  echo "[ERROR] nc (netcat) not installed. sudo apt install netcat-openbsd" >&2
  exit 2
fi

echo "[*] Reverse-shell interpreter sim: starting a local loopback listener on 127.0.0.1:${PORT}"
# Local, self-contained listener (discards input) — no external contact.
nc -l -p "$PORT" > /dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

echo "[*] Connecting via bash's /dev/tcp/ idiom (the rule's own matched pattern)"
echo "[*] Expected detection: proc_creation_lnx_reverse_shell_interpreter.yml"
bash -c "exec 3<>/dev/tcp/127.0.0.1/${PORT}; echo 'sim' >&3; exec 3>&-" || true

kill "$LISTENER_PID" 2>/dev/null || true

echo "[+] Sim complete. Allow ~30s for auditd + Filebeat + Logstash to index."

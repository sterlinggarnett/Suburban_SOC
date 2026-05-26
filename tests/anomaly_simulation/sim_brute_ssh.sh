#!/usr/bin/env bash
# =============================================================================
# sim_brute_ssh.sh — Issue #22 scenario 2: SSH Brute Force
#
# Issues 5+ failed SSH auth attempts so Zeek's ssh analyzer records the
# auth_success=F cascade in ssh.log.
# =============================================================================

set -euo pipefail

[[ -f "$(dirname "$0")/.env" ]] && set -a && source "$(dirname "$0")/.env" && set +a

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
BRUTE_USER="${BRUTE_USER:-bogususer}"
BRUTE_PASSWORDS="${BRUTE_PASSWORDS:-wrong1 wrong2 wrong3 wrong4 wrong5}"

if ! command -v sshpass >/dev/null 2>&1; then
  echo "[ERROR] sshpass not installed. sudo apt install sshpass" >&2
  exit 2
fi

echo "[*] Brute-force sim: 5 failed SSH attempts → ${BRUTE_USER}@${TARGET_HOST}"
echo "[*] Expected Zeek detection: ssh.log → 5+ rows with auth_success=F"

attempt=0
for pw in $BRUTE_PASSWORDS; do
  attempt=$((attempt + 1))
  echo "[*] Attempt $attempt with password: $pw"
  # Allow non-zero exit; we *want* auth to fail.
  sshpass -p "$pw" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=5 \
    -o NumberOfPasswordPrompts=1 \
    "${BRUTE_USER}@${TARGET_HOST}" \
    "exit" 2>/dev/null || true
done

echo "[+] Brute-force sim complete ($attempt attempts). Allow ~30s for indexing."

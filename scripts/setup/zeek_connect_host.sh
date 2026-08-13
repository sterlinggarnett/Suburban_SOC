#!/usr/bin/env bash
# SOP-001-E: Interactive Zeek Host Monitor
# Runs Zeek directly on the host's eth0 interface with threat intel loaded.
# Requires NET_ADMIN and NET_RAW capabilities (sudo).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# security-auditor review (2nd pass): directory-level symlink check, same
# reasoning as zeek_run_pcap.sh's identical check — must run before mkdir
# -p, which silently follows a directory symlink instead of failing on one.
if [ -L /storage/PCAP/intel ] || [ -L /storage/PCAP/zeek_logs ]; then
  echo "[FATAL] /storage/PCAP/intel or zeek_logs is a symlink, refusing to follow it" >&2
  exit 1
fi

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
# security-auditor review: --remove-destination + a symlink guard, same
# reasoning as zeek_run_pcap.sh's identical check.
if [ -L /storage/PCAP/intel/config.zeek ]; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is a symlink, refusing to follow it" >&2
  exit 1
fi
sudo cp -r --remove-destination "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

# #288: verify the copy above actually landed a current config.zeek before
# monitoring any traffic — same reasoning as zeek_run_pcap.sh's identical
# check. sudo (not a suppressed, unprivileged grep) so a real permission
# problem surfaces distinctly from "file is genuinely stale" (security-
# auditor review).
if ! sudo grep -q "policy/misc/capture-loss" /storage/PCAP/intel/config.zeek; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is missing an expected @load -- the intel config copy above may have failed silently. Refusing to monitor against a config that might not match the repo." >&2
  exit 1
fi

sudo mkdir -p "$LOG_DIR"

echo "[INFO] Starting interactive Zeek on eth0 -> ${LOG_DIR}"
echo "[INFO] Press Ctrl+C to stop."

sudo docker run --rm \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v "${LOG_DIR}:/data/zeek_logs" \
  -v /storage/PCAP/intel:/data/intel \
  -w /data/zeek_logs \
  zeek/zeek \
  zeek -C -i eth0 LogAscii::use_json=T /data/intel/config.zeek

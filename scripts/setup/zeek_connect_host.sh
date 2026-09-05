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
# Shared root-owner + sticky-bit permission fix, see lib/intel_dir_perms.sh
# (#321).
source "${SCRIPT_DIR}/lib/intel_dir_perms.sh"
harden_intel_dir_perms /storage/PCAP/intel "${SOC_USER:-tjlam}"
# security-auditor review: --remove-destination + a symlink guard, same
# reasoning as zeek_run_pcap.sh's identical check.
if [ -L /storage/PCAP/intel/config.zeek ]; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is a symlink, refusing to follow it" >&2
  exit 1
fi
# #270: two explicit, single-file copies instead of one blanket `cp -r
# configs/intel/*` — intel.dat now lives in its own configs/intel/data/
# subdirectory (see configs/systemd/intel-refresh.service's ReadWritePaths
# comment for why), so the old wildcard copy would silently stop picking it
# up at all. Matches zeek-host-capture.service's own equivalent split.
sudo cp --remove-destination "${SCRIPT_DIR}/../../configs/intel/config.zeek" /storage/PCAP/intel/config.zeek 2>/dev/null || true
sudo cp --remove-destination "${SCRIPT_DIR}/../../configs/intel/data/intel.dat" /storage/PCAP/intel/intel.dat 2>/dev/null || true

# #288: verify the copy above actually landed a current config.zeek before
# monitoring any traffic — same reasoning as zeek_run_pcap.sh's identical
# check. sudo (not a suppressed, unprivileged grep) so a real permission
# problem surfaces distinctly from "file is genuinely stale" (security-
# auditor review).
if ! sudo grep -q "policy/misc/capture-loss" /storage/PCAP/intel/config.zeek || ! sudo grep -q "^redef Log::default_max_field_string_bytes = 8191;" /storage/PCAP/intel/config.zeek; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is missing an expected @load or the #389 Log redef -- the intel config copy above may have failed silently. Refusing to monitor against a config that might not match the repo." >&2
  exit 1
fi

sudo mkdir -p "$LOG_DIR"

echo "[INFO] Starting interactive Zeek on eth0 -> ${LOG_DIR}"
echo "[INFO] Press Ctrl+C to stop."

# #293: the Zeek image below is pinned to a specific version, not :latest — see
# configs/systemd/zeek-host-capture.service's header comment for why (an
# unpinned image already broke a Sigma rule's string match once, #228) and
# the bump process. tests/pipeline/test_zeek_image_pin.py enforces this
# stays in lockstep with the other 3 real capture paths.
sudo docker run --rm \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v "${LOG_DIR}:/data/zeek_logs" \
  -v /storage/PCAP/intel:/data/intel \
  -w /data/zeek_logs \
  zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
  zeek -C -i eth0 LogAscii::use_json=T /data/intel/config.zeek

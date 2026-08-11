#!/usr/bin/env bash
# SOP-001: Stream live traffic from a capture source through the Zeek container.
# Replaces the formerly-separate stream_bat0_data.sh / stream_br_lan_data.sh /
# stream_raw_data.sh (#173) — same behavior per source, parameterized by mode
# instead of duplicated across three near-identical files.
#
# Usage: stream_capture.sh <bat0|br-lan|raw>
#   bat0    SOP-001-A — SSH to the mesh router (ROUTER_IP, default 10.18.81.1),
#           capture the bat0 (B.A.T.M.A.N. advanced mesh) interface.
#   br-lan  SOP-001-B — SSH to the LAN router (ROUTER_IP, default 192.168.1.233),
#           capture the br-lan (standard bridged LAN) interface.
#   raw     SOP-001-C — local host eth0 capture via sudo tcpdump (no SSH).
#           Must be run with sudo.
#
# ROUTER_USER/ROUTER_IP/LOG_DIR are read from the environment (set by
# soc_pipeline.sh); sensible per-mode defaults are used when run standalone.

set -euo pipefail

MODE="${1:?Usage: $0 <bat0|br-lan|raw>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# Sync Intel configurations so threat intel rules are applied to live captures.
# The two mkdirs are deliberately NOT best-effort (unlike the intel cp below) —
# under set -e a failure here hard-exits before any capture starts, rather than
# silently limping on without a writable log/intel destination.
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true
sudo mkdir -p "$LOG_DIR"

# Pipes a tcpdump byte stream (stdin) into the Zeek container for live analysis.
run_zeek() {
  "$@" docker run -i --rm \
    -v "${LOG_DIR}:/data/zeek_logs" \
    -v /storage/PCAP/intel:/data/intel \
    -v "${SCRIPT_DIR}/configs/zeek:/data/policy:ro" \
    -w /data/zeek_logs \
    zeek/zeek \
    zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek /data/policy/scan-detection.zeek \
      policy/protocols/ssh/detect-bruteforcing
}

case "$MODE" in
  bat0|br-lan)
    ROUTER_USER="${ROUTER_USER:-root}"
    if [ "$MODE" = "bat0" ]; then
      ROUTER_IP="${ROUTER_IP:-10.18.81.1}"
    else
      ROUTER_IP="${ROUTER_IP:-192.168.1.233}"
    fi
    echo "[INFO] Streaming ${MODE} from ${ROUTER_USER}@${ROUTER_IP} -> Zeek -> ${LOG_DIR}"
    echo "[INFO] Press Ctrl+C to stop."
    ssh "${ROUTER_USER}@${ROUTER_IP}" "tcpdump -i ${MODE} -s 0 -U -w -" | run_zeek
    ;;
  raw)
    echo "[INFO] Capturing eth0 -> Zeek -> ${LOG_DIR}"
    echo "[INFO] Press Ctrl+C to stop."
    sudo tcpdump -i eth0 -s 0 -U -w - | run_zeek sudo
    ;;
  *)
    echo "Unknown mode '${MODE}' (expected bat0, br-lan, or raw)" >&2
    exit 1
    ;;
esac

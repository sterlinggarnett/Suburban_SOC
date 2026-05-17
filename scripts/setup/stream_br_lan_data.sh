#!/bin/bash
# SOP-001-B: Stream br-lan (LAN bridge) traffic from remote router through Zeek
# Reads ROUTER_USER and ROUTER_IP from environment (set by soc_pipeline.sh).
# Fallback defaults used when run standalone.

ROUTER_USER="${ROUTER_USER:-root}"
ROUTER_IP="${ROUTER_IP:-10.18.81.1}"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sync Intel configurations so threat intel rules are applied to live captures
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

sudo mkdir -p "$LOG_DIR"

echo "[INFO] Streaming br-lan from ${ROUTER_USER}@${ROUTER_IP} -> Zeek -> ${LOG_DIR}"
echo "[INFO] Press Ctrl+C to stop."

ssh "${ROUTER_USER}@${ROUTER_IP}" "tcpdump -i br-lan -s 0 -U -w -" | \
  docker run -i --rm \
    -v "${LOG_DIR}:/data/zeek_logs" \
    -v /storage/PCAP/intel:/data/intel \
    -w /data/zeek_logs \
    zeek/zeek \
    zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek

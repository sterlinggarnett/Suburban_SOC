#!/bin/bash
# SOP-001-C: Live capture on local eth0 interface through Zeek
# Requires tcpdump installed: sudo apt install tcpdump
# Must be run with sudo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# Sync Intel configurations so threat intel rules are applied to live captures
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

sudo mkdir -p "$LOG_DIR"

echo "[INFO] Capturing eth0 -> Zeek -> ${LOG_DIR}"
echo "[INFO] Press Ctrl+C to stop."

sudo tcpdump -i eth0 -s 0 -U -w - | \
  sudo docker run -i --rm \
    -v "${LOG_DIR}:/data/zeek_logs" \
    -v /storage/PCAP/intel:/data/intel \
    -w /data/zeek_logs \
    zeek/zeek \
    zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek

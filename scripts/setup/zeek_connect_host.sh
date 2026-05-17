#!/bin/bash
# SOP-001-E: Interactive Zeek Host Monitor
# Runs Zeek directly on the host's eth0 interface with threat intel loaded.
# Requires NET_ADMIN and NET_RAW capabilities (sudo).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

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

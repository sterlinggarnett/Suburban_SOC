#!/bin/bash
# Zeek RUN command — Offline PCAP Analysis
# Processes all *.pcap files in /storage/PCAP/ through Zeek and outputs
# JSON logs to /storage/PCAP/zeek_logs/ for Filebeat ingestion.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"
PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

# Clean previous logs to prevent duplicate processing
sudo rm -rf "${LOG_DIR:?}"/*

# Loop through all available PCAP files to ensure full dataset generation
for pcap in /storage/PCAP/*.pcap; do
  if [ -s "$pcap" ]; then
    echo "[INFO] Processing $pcap..."
    pcap_name=$(basename "$pcap" .pcap)

    # Process into a temporary directory
    sudo mkdir -p /storage/PCAP/temp_zeek
    docker run --rm \
      -v /storage/PCAP:/data \
      -v /storage/PCAP/intel:/data/intel \
      -w /data/temp_zeek \
      zeek/zeek \
      zeek -r "/data/$(basename "$pcap")" LogAscii::use_json=T /data/intel/config.zeek

    # Move and rename logs into the main zeek_logs directory so Filebeat catches them all
    for log in /storage/PCAP/temp_zeek/*.log; do
      if [ -f "$log" ]; then
        base=$(basename "$log" .log)
        sudo mv "$log" "${LOG_DIR}/${base}_${pcap_name}.log"
      fi
    done
    sudo rm -rf /storage/PCAP/temp_zeek
    echo "[INFO] Done: $pcap_name"
  fi
done

echo "[INFO] All PCAPs processed. Logs in ${LOG_DIR}"

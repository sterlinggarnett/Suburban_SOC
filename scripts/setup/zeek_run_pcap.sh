#!/bin/bash
# Zeek RUN command
# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r configs/intel/* /storage/PCAP/intel/

# Clean previous logs to prevent duplicate processing
sudo rm -rf /storage/PCAP/zeek_logs/*

# Loop through all available PCAP files to ensure full dataset generation
for pcap in /storage/PCAP/*.pcap; do
  if [ -s "$pcap" ]; then
    echo "Processing $pcap..."
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
        sudo mv "$log" "/storage/PCAP/zeek_logs/${base}_${pcap_name}.log"
      fi
    done
    sudo rm -rf /storage/PCAP/temp_zeek
  fi
done

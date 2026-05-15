#!/bin/bash
# CONNECTING TO HOST INTERFACE
# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r configs/intel/* /storage/PCAP/intel/

sudo docker run --rm \
--network host \
--cap-add=NET_ADMIN \
--cap-add=NET_RAW \
-v /storage/PCAP/zeek_logs:/data/zeek_logs \
-v /storage/PCAP/intel:/data/intel \
-w /data/zeek_logs \
zeek/zeek \
zeek -C -i eth0 LogAscii::use_json=T /data/intel/config.zeek

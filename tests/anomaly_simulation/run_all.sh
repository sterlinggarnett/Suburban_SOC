#!/usr/bin/env bash
# =============================================================================
# run_all.sh — Issue #22 orchestrator
#
# Runs all three simulation scenarios, waits for the Zeek→Logstash→ES
# pipeline to index the events, then runs the Python verifier.
# Does NOT run verify_quarantine.sh (needs the MAC argument and a live router).
# =============================================================================

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

[[ -f .env ]] && set -a && source .env && set +a

INDEX_WAIT="${INDEX_WAIT:-45}"

echo "============================================================"
echo " Anomaly Simulation Suite — Issue #22"
echo "============================================================"

echo
echo "--- [1/3] Network reconnaissance ---"
./sim_portscan.sh

echo
echo "--- [2/3] SSH brute force ---"
./sim_brute_ssh.sh

echo
echo "--- [3/3] Suspicious download ---"
./sim_malware_download.sh

echo
echo "[*] Waiting ${INDEX_WAIT}s for Zeek + Logstash + Elasticsearch indexing..."
sleep "$INDEX_WAIT"

echo
echo "--- Verifying detections in Elasticsearch ---"
python3 verify_detections.py

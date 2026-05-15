#!/bin/bash
# Dynamically resolve the scripts/setup directory relative to this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scripts/setup"

echo "--- Referenced Script Check ---"
for s in stream_bat0_data.sh stream_br_lan_data.sh stream_raw_data.sh zeek_run_pcap.sh zeek_connect_host.sh install_filebeat.sh clear_logs.sh; do
  if [ -f "$SCRIPT_DIR/$s" ]; then
    echo "  [FOUND]   $s"
  else
    echo "  [MISSING] $s"
  fi
done

echo ""
echo "--- Function Definitions in soc_pipeline.sh ---"
grep -E "^\w+\(\)" "$SCRIPT_DIR/soc_pipeline.sh"

echo ""
echo "--- Variable Assignments ---"
grep -E "^(SCRIPT_DIR|LOG_DIR|ROUTER_IP|ROUTER_USER)" "$SCRIPT_DIR/soc_pipeline.sh"

echo ""
echo "--- Heredoc markers ---"
grep -E "<<|EOF|FBEOF" "$SCRIPT_DIR/soc_pipeline.sh"

echo ""
echo "--- Line ending check ---"
if file "$SCRIPT_DIR/soc_pipeline.sh" | grep -q CRLF; then
  echo "  [WARN] CRLF line endings detected"
else
  echo "  [PASS] LF line endings only"
fi

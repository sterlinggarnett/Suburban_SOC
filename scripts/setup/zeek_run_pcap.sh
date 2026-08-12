#!/usr/bin/env bash
# Zeek RUN command — Offline PCAP Analysis
# When PCAP_FILE points to a real file, analyzes ONLY that file (the path the
# menu passes). Otherwise falls back to processing every *.pcap in
# /storage/PCAP/. Outputs JSON logs to /storage/PCAP/zeek_logs/ for Filebeat.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"
PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
sudo cp -r "${SCRIPT_DIR}/../../configs/intel/"* /storage/PCAP/intel/ 2>/dev/null || true

sudo mkdir -p "$LOG_DIR"

# Processes one PCAP file through Zeek and moves its JSON logs into a
# per-pcap subdirectory of LOG_DIR, with bare stream filenames (#291 —
# was suffixed flat filenames; see the per-file comment below for why that
# broke). Re-running a given pcap overwrites only its own logs (no
# cross-pcap duplication), so there is no need to wipe LOG_DIR.
# The pcap is bind-mounted read-only at a fixed path, so it can live anywhere
# on disk -- not just under /storage/PCAP.
process_pcap() {
  local pcap="$1"
  if [ ! -s "$pcap" ]; then
    echo "[WARN] Skipping empty or missing file: $pcap"
    return
  fi

  local pcap_name
  pcap_name=$(basename "$pcap" .pcap)
  echo "[INFO] Processing $pcap..."

  sudo mkdir -p /storage/PCAP/temp_zeek
  docker run --rm \
    -v /storage/PCAP:/data \
    -v /storage/PCAP/intel:/data/intel \
    -v "$pcap":/input.pcap:ro \
    -w /data/temp_zeek \
    zeek/zeek \
    zeek -C -r /input.pcap LogAscii::use_json=T /data/intel/config.zeek

  # Move logs into a per-pcap subdirectory under the main zeek_logs directory
  # (bare filenames, e.g. conn.log — NOT ${base}_${pcap_name}.log). #291
  # security-auditor review: configs/logstash.conf's Category 0 grok
  # (`[a-z0-9_]+` before ".log") captures the ENTIRE stem as zeek_stream,
  # underscore included — the old "${base}_${pcap_name}.log" naming made
  # event.dataset = "zeek.conn_${pcap_name}" instead of "zeek.conn". That
  # was harmless before #291 (no Sigma rule checked event.dataset at all),
  # but #291's new event.dataset:zeek.<service> scoping condition means
  # every zeek-sourced rule would now silently never fire against offline
  # PCAP-replay data — a real detection blackout for this SOP, not just a
  # naming cosmetic. The per-pcap subdirectory preserves this function's
  # own documented purpose (re-running a pcap only overwrites its own logs,
  # no cross-pcap collision in a flat directory) while keeping bare
  # filenames so the grok capture still resolves to the real stream name.
  for log in /storage/PCAP/temp_zeek/*.log; do
    if [ -f "$log" ]; then
      local base
      base=$(basename "$log" .log)
      sudo mkdir -p "${LOG_DIR}/${pcap_name}"
      sudo mv "$log" "${LOG_DIR}/${pcap_name}/${base}.log"
    fi
  done
  sudo rm -rf /storage/PCAP/temp_zeek
  echo "[INFO] Done: $pcap_name"
}

# Single-file mode: a specific, existing PCAP_FILE was provided (e.g. from the menu).
if [ -n "$PCAP_FILE" ] && [ -f "$PCAP_FILE" ]; then
  echo "[INFO] Single-file mode: $PCAP_FILE"
  process_pcap "$PCAP_FILE"
else
  # Batch mode: no specific file -- process every PCAP in /storage/PCAP.
  echo "[INFO] Batch mode: processing all PCAPs in /storage/PCAP"
  for pcap in /storage/PCAP/*.pcap; do
    process_pcap "$pcap"
  done
fi

echo "[INFO] Analysis complete. Logs in ${LOG_DIR}"

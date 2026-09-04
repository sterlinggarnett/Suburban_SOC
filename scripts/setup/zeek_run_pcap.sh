#!/usr/bin/env bash
# Zeek RUN command — Offline PCAP Analysis
# When PCAP_FILE points to a real file, analyzes ONLY that file (the path the
# menu passes). Otherwise falls back to processing every *.pcap in
# /storage/PCAP/. Outputs JSON logs to /storage/PCAP/zeek_logs/ for Filebeat.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"
PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

# security-auditor review (2nd pass): checking config.zeek alone (below)
# is not enough — if /storage/PCAP/intel ITSELF is a symlink (e.g. to
# /etc/sudoers.d), `sudo mkdir -p` and `cp -r` both follow it silently, and
# config.zeek's own `-L` check then resolves THROUGH the directory symlink
# to whatever sits at the real target, never seeing the swap. Same CWE-59
# class configs/systemd/zeek-host-capture.service:72-84 already rates HIGH
# for the identical vector; check the directory before creating/using it,
# not after.
if [ -L /storage/PCAP/intel ] || [ -L /storage/PCAP/zeek_logs ]; then
  echo "[FATAL] /storage/PCAP/intel or zeek_logs is a symlink, refusing to follow it" >&2
  exit 1
fi

# Sync Intel configurations to the host volume
sudo mkdir -p /storage/PCAP/intel
# Shared root-owner + sticky-bit permission fix, see lib/intel_dir_perms.sh
# (#321).
source "${SCRIPT_DIR}/lib/intel_dir_perms.sh"
harden_intel_dir_perms /storage/PCAP/intel "${SOC_USER:-tjlam}"
# security-auditor review: --remove-destination + a symlink guard, same
# reasoning as configs/systemd/zeek-host-capture.service's own
# ExecStartPre steps. --remove-destination is the one that actually
# prevents cp from writing THROUGH an existing symlink at this path
# instead of replacing it (verified directly: cp --remove-destination
# alone already unlinks a symlinked destination before writing); the
# explicit guard here is defense-in-depth matching the systemd unit's own
# belt-and-suspenders design (a symlink sweep alongside its own
# --remove-destination), not load-bearing on its own (code-reviewer
# follow-up).
if [ -L /storage/PCAP/intel/config.zeek ]; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is a symlink, refusing to follow it" >&2
  exit 1
fi
# #270: two explicit, single-file copies instead of one blanket `cp -r
# configs/intel/*` — intel.dat now lives in its own configs/intel/data/
# subdirectory (see configs/systemd/intel-refresh.service's ReadWritePaths
# comment for why), so the old wildcard copy would silently stop picking it
# up at all. Matches zeek-host-capture.service's own equivalent split.
sudo cp --remove-destination "${SCRIPT_DIR}/../../configs/intel/config.zeek" /storage/PCAP/intel/config.zeek 2>/dev/null || true
sudo cp --remove-destination "${SCRIPT_DIR}/../../configs/intel/data/intel.dat" /storage/PCAP/intel/intel.dat 2>/dev/null || true

# #288: the cp above is deliberately best-effort (a transient permissions/
# stale-mount failure should not block analysis outright when the deployed
# config might already be current from a prior run), but a SILENT failure
# left every real capture invocation running whatever stale config.zeek was
# already on disk with no verification the repo's own @load list actually
# made it across. Check for the newest @load line (capture-loss, #288)
# rather than an older one like validate-certs, which could already exist
# in a stale copy from before this fix. sudo (not a suppressed, unprivileged
# grep) so a real permission problem surfaces distinctly from "file is
# genuinely stale" instead of both collapsing into the same FATAL message
# (security-auditor review).
if ! sudo grep -q "policy/misc/capture-loss" /storage/PCAP/intel/config.zeek || ! sudo grep -q "^redef Log::default_max_field_string_bytes = 8191;" /storage/PCAP/intel/config.zeek; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is missing an expected @load or the #389 Log redef -- the intel config copy above may have failed silently. Refusing to analyze against a config that might not match the repo." >&2
  exit 1
fi

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
  # #293: the Zeek image below is pinned to a specific version, not :latest — see
  # configs/systemd/zeek-host-capture.service's header comment for why (an
  # unpinned image already broke a Sigma rule's string match once, #228) and
  # the bump process. tests/pipeline/test_zeek_image_pin.py enforces this
  # stays in lockstep with the other 3 real capture paths.
  docker run --rm \
    -v /storage/PCAP:/data \
    -v /storage/PCAP/intel:/data/intel \
    -v "$pcap":/input.pcap:ro \
    -w /data/temp_zeek \
    zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
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

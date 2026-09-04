#!/usr/bin/env bash
# SOP-001: Stream live traffic from a capture source through the Zeek container.
# Replaces the formerly-separate stream_bat0_data.sh / stream_br_lan_data.sh /
# stream_raw_data.sh (#173) — same behavior per source, parameterized by mode
# instead of duplicated across three near-identical files.
#
# Usage: stream_capture.sh <bat0|br-lan|raw>
#   bat0    SOP-001-A — SSH to the mesh router (ROUTER_IP, default 10.18.81.1),
#           capture the bat0 (B.A.T.M.A.N. advanced mesh) interface.
#   br-lan  SOP-001-B — SSH to the LAN router (ROUTER_IP, default 192.168.1.233),
#           capture the br-lan (standard bridged LAN) interface.
#   raw     SOP-001-C — local host eth0 capture via sudo tcpdump (no SSH).
#           Must be run with sudo.
#
# ROUTER_USER/ROUTER_IP/LOG_DIR are read from the environment (set by
# soc_pipeline.sh); sensible per-mode defaults are used when run standalone.

set -euo pipefail

MODE="${1:?Usage: $0 <bat0|br-lan|raw>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/storage/PCAP/zeek_logs}"

# security-auditor review (2nd pass): directory-level symlink check, same
# reasoning as zeek_run_pcap.sh's identical check — must run before mkdir
# -p, which silently follows a directory symlink instead of failing on one.
if [ -L /storage/PCAP/intel ] || [ -L /storage/PCAP/zeek_logs ]; then
  echo "[FATAL] /storage/PCAP/intel or zeek_logs is a symlink, refusing to follow it" >&2
  exit 1
fi

# Sync Intel configurations so threat intel rules are applied to live captures.
# The two mkdirs are deliberately NOT best-effort (unlike the intel cp below) —
# under set -e a failure here hard-exits before any capture starts, rather than
# silently limping on without a writable log/intel destination.
sudo mkdir -p /storage/PCAP/intel
# Shared root-owner + sticky-bit permission fix, see lib/intel_dir_perms.sh
# (#321). `|| true`: same "capture availability outranks intel freshness"
# priority the systemd unit's own equivalent step applies (its `-`-prefixed
# ExecStartPre) — unlike the mkdirs above, a failure here must not block
# capture from starting under this script's own `set -e`.
source "${SCRIPT_DIR}/lib/intel_dir_perms.sh"
harden_intel_dir_perms /storage/PCAP/intel "${SOC_USER:-tjlam}" || true
# security-auditor review: --remove-destination + a symlink guard, same
# reasoning as zeek_run_pcap.sh's identical check.
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

# #288: verify the copy above actually landed a current config.zeek before
# streaming any traffic — same reasoning as zeek_run_pcap.sh's identical
# check. set -e alone does not catch this, since the cp is `|| true`. sudo
# (not a suppressed, unprivileged grep) so a real permission problem
# surfaces distinctly from "file is genuinely stale" (security-auditor review).
if ! sudo grep -q "policy/misc/capture-loss" /storage/PCAP/intel/config.zeek || ! sudo grep -q "^redef Log::default_max_field_string_bytes = 8191;" /storage/PCAP/intel/config.zeek; then
  echo "[FATAL] /storage/PCAP/intel/config.zeek is missing an expected @load or the #389 Log redef -- the intel config copy above may have failed silently. Refusing to stream against a config that might not match the repo." >&2
  exit 1
fi

sudo mkdir -p "$LOG_DIR"

# Pipes a tcpdump byte stream (stdin) into the Zeek container for live analysis.
# #293: the Zeek image below is pinned to a specific version, not :latest — see
# configs/systemd/zeek-host-capture.service's header comment for why (an
# unpinned image already broke a Sigma rule's string match once, #228) and
# the bump process. tests/pipeline/test_zeek_image_pin.py enforces this
# stays in lockstep with the other 3 real capture paths.
run_zeek() {
  # --name zeek-stream (security-auditor review, #364): SOP-147's evidence-
  # validation commands need a way to find "the running Zeek container"
  # that survives a version bump — the `ancestor=zeek/zeek:<tag>` filter
  # they used to use is live-confirmed unreliable (a container run via
  # `repo:tag@digest` does not always get the tag applied to the local
  # image store, so the tagged filter can silently match nothing even
  # though the exact right container is running). A name is deterministic
  # regardless of Docker's tag-caching behavior; matches
  # zeek-host-capture.service's own --name zeek-host-capture, and both are
  # covered by the same `--filter name=zeek-` prefix.
  "$@" docker run -i --rm --name zeek-stream \
    -v "${LOG_DIR}:/data/zeek_logs" \
    -v /storage/PCAP/intel:/data/intel \
    -v "${SCRIPT_DIR}/configs/zeek:/data/policy:ro" \
    -w /data/zeek_logs \
    zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
    zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek /data/policy/scan-detection.zeek \
      policy/protocols/ssh/detect-bruteforcing
}

case "$MODE" in
  bat0|br-lan)
    ROUTER_USER="${ROUTER_USER:-root}"
    if [ "$MODE" = "bat0" ]; then
      ROUTER_IP="${ROUTER_IP:-10.18.81.1}"
    else
      ROUTER_IP="${ROUTER_IP:-192.168.1.233}"
    fi
    echo "[INFO] Streaming ${MODE} from ${ROUTER_USER}@${ROUTER_IP} -> Zeek -> ${LOG_DIR}"
    echo "[INFO] Press Ctrl+C to stop."
    ssh "${ROUTER_USER}@${ROUTER_IP}" "tcpdump -i ${MODE} -s 0 -U -w -" | run_zeek
    ;;
  raw)
    echo "[INFO] Capturing eth0 -> Zeek -> ${LOG_DIR}"
    echo "[INFO] Press Ctrl+C to stop."
    sudo tcpdump -i eth0 -s 0 -U -w - | run_zeek sudo
    ;;
  *)
    echo "Unknown mode '${MODE}' (expected bat0, br-lan, or raw)" >&2
    exit 1
    ;;
esac

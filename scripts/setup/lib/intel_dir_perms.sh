# shellcheck shell=bash
# =============================================================================
# intel_dir_perms.sh — shared root-owner + tjlam-group-sticky-bit permission
# fix for /storage/PCAP/intel (#321).
#
# configs/systemd/zeek-host-capture.service's own crash-loop fix (#209/#222)
# makes root the PERMANENT owner of this directory, with tjlam getting
# group-write + sticky-bit access (chown -h root:tjlam ... && chmod 1775 ...)
# so intel-refresh.service's live sync keeps working across every restart,
# not just the first — see that unit's own comments for the full history.
# Three sibling manual-capture helpers (stream_capture.sh, zeek_connect_host.sh,
# zeek_run_pcap.sh) each independently `sudo mkdir -p /storage/PCAP/intel`
# with no chown/chmod of their own — running any of them on a host where the
# directory doesn't exist yet silently reintroduces the exact root:root 0755
# state the systemd unit's fix corrects, since they run under full root
# (sudo, real DAC_OVERRIDE) and would happily leave it there.
#
# Usage — source AFTER the caller has already mkdir'd the directory and
# guarded against it being a symlink (this helper does neither):
#   source "<repo>/scripts/setup/lib/intel_dir_perms.sh"
#   harden_intel_dir_perms /storage/PCAP/intel tjlam
# =============================================================================

# Idempotent: if already sourced in this shell, skip redefining the function.
[[ -n "${_INTEL_DIR_PERMS_LOADED:-}" ]] && return 0
_INTEL_DIR_PERMS_LOADED=1

# "-h" on chown: GNU chown dereferences a symlink argument by default — run
# against a symlinked path, it would retarget whatever the symlink points at
# instead. "-h" operates on the link itself, a no-op on a real directory but
# a real guard if this path were ever replaced by a symlink. chmod has NO
# "-h"/no-dereference equivalent on Linux (symlinks carry no permission bits
# of their own) — the same residual limitation configs/systemd/
# zeek-host-capture.service's own #321 fix documents and narrows (a hard
# not-a-symlink guard immediately before its own equivalent chown+chmod
# step); callers of this function that can enforce that same precondition
# should still do so themselves before calling it. Chained via && (not run
# as two independent commands) so a failed chown never leaves a root:root
# directory silently chmod'd to 1775 anyway.
harden_intel_dir_perms() {
  local dir="$1" group_user="$2"
  sudo chown -h "root:${group_user}" "$dir" && sudo chmod 1775 "$dir"
}

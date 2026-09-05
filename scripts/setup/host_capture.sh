#!/usr/bin/env bash
# Suburban-SOC — pipes host tcpdump into the Zeek capture container (#320).
#
# Factored out of configs/systemd/zeek-host-capture.service's ExecStart to
# close a shell-interpolation gap (security-auditor review): systemd
# substitutes ${CAPTURE_IFACE} into the ExecStart= command STRING before
# bash ever parses it, so a value like "eth0; curl ... | sh" written to
# /etc/default/zeek-host-capture would execute as root on the next restart.
# Passing the interface as a POSITIONAL ARGUMENT here instead closes that:
# systemd passes ${VAR} to ExecStart as a single, unsplit argv word, and
# "$IFACE" below is quoted, so bash's own parser never gets a chance to
# re-interpret its contents as shell syntax — this file isn't tracked by
# the repo diff at all (/etc/default/zeek-host-capture), but a value
# written there can now only ever be an interface name, never a command.
#
# Usage: host_capture.sh <interface>

set -euo pipefail

IFACE="${1:?Usage: $0 <interface>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pin PATH before running anything. The unit loads
# EnvironmentFile=-/etc/default/zeek-host-capture, which injects ARBITRARY
# variables into the service environment — PATH included, and systemd
# honours it. Without this, the bare `ip`/`sed`/`awk`/`head`/`sleep` the
# preflight uses would resolve through an operator-supplied PATH while
# running as root with CAP_NET_RAW/CAP_NET_ADMIN/CAP_SETUID in the bounding
# set (T1574.007). That is root->root rather than a privilege escalation,
# since the env file is root-owned 644 — but it regresses this file's own
# convention of absolute paths (/usr/bin/tcpdump, /usr/bin/docker below).
# Pinning here covers every command downstream, including the preflight.
# Note `ip` lives in /sbin on some distros and /usr/sbin on others, so a
# pinned PATH is the portable form of the same hardening.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Refuse to start on an interface that is not up, and report that as a
# CONFIGURATION error (exit 78) rather than an ordinary failure — see
# capture_iface_preflight.sh's header for the five-day outage that motivated
# this, and the unit's RestartPreventExitStatus=78 for what consumes it.
# Runs BEFORE the capture pipeline so a bad pin never leaves a half-built
# container behind on every restart.
# Invoked through an explicit interpreter, NOT as an executable: this repo
# sets core.fileMode=false and tracks every script in scripts/setup/ as mode
# 100644, so the executable bit exists only on whatever host happened to
# chmod it. A fresh clone would get "Permission denied" here and the capture
# lane would refuse to start. Same reason the unit's own ExecStart= says
# `/bin/bash ${SOC_REPO}/scripts/setup/host_capture.sh`.
/bin/bash "${SCRIPT_DIR}/capture_iface_preflight.sh" "$IFACE"

# tcpdump captures in the host net namespace; Zeek parses the live pcap from
# stdin. "set -o pipefail" (via set -euo pipefail above): without it, this
# script's own exit status would be docker run's alone — a dead/EPERM'd
# tcpdump leg would leave systemd reporting the unit healthy while no
# packets are actually being captured (the exact failure class a prior
# security-auditor emergency review found and fixed at the ExecStart level
# — preserved here now that the pipeline lives in this script instead).
#
# The Zeek image below is pinned to a specific version — see
# configs/systemd/zeek-host-capture.service's #293 header comment for why
# and the bump process. tests/pipeline/test_zeek_image_pin.py enforces this
# stays in lockstep with the other 3 real capture paths.
# `set -o pipefail` makes this pipeline's status the script's status, and
# `docker run` passes the CONTAINER's exit code through verbatim (Docker
# reserves only 125/126/127 for itself). Zeek's status comes from the policy
# chain in /data/intel/config.zeek, which the unit re-copies from the repo
# checkout on every restart — so a Zeek-side 78 would convert a self-healing
# crash loop into a permanently `failed` unit that never restarts on its own
# (T1562.001: strictly better for an attacker than the pre-change
# behaviour). Exit 78 is reserved to the preflight above; anything the
# pipeline produces is remapped to an ordinary failure below.
set +e
/usr/bin/tcpdump -i "$IFACE" -s 0 -U -w - | /usr/bin/docker run -i --rm --name zeek-host-capture \
  -v /storage/PCAP/zeek_logs:/data/zeek_logs \
  -v /storage/PCAP/intel:/data/intel \
  -v "${SCRIPT_DIR}/configs/zeek:/data/policy:ro" \
  -w /data/zeek_logs \
  zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
  zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek /data/policy/scan-detection.zeek \
    policy/protocols/ssh/detect-bruteforcing
rc=$?
set -e
# Only capture_iface_preflight.sh may mint EX_CONFIG (78).
[ "$rc" -ne 78 ] || rc=1
exit "$rc"

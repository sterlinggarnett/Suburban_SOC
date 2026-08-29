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
/usr/bin/tcpdump -i "$IFACE" -s 0 -U -w - | /usr/bin/docker run -i --rm --name zeek-host-capture \
  -v /storage/PCAP/zeek_logs:/data/zeek_logs \
  -v /storage/PCAP/intel:/data/intel \
  -v "${SCRIPT_DIR}/configs/zeek:/data/policy:ro" \
  -w /data/zeek_logs \
  zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
  zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek /data/policy/scan-detection.zeek \
    policy/protocols/ssh/detect-bruteforcing

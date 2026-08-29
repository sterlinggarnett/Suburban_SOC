#!/usr/bin/env bash
# Suburban-SOC — trust-on-first-use (TOFU) pinning for the Elasticsearch CA
# cert intel-refresh.service and slo-metrics.service both re-extract from
# the `elasticsearch` container on every run (#270).
#
# Neither unit previously verified the extracted cert against anything —
# whatever sat at that container path each run silently became the sole
# trust anchor for a request carrying an ES credential. An attacker able to
# write into that container path, or start a container named `elasticsearch`
# first, could MITM the connection and harvest the credential.
#
# A repo-committed static pin (the issue's own literal suggestion) isn't
# possible here: the real fingerprint depends on each deployment's own
# generated CA, which this repo has no access to, and shipping a fabricated
# placeholder "expected" value would be worse than no check at all — this
# repo's own blue-team conventions already forbid inventing hashes for the
# same reason (a made-up value teaches nothing and just needs replacing by
# hand before the check does anything real). TOFU instead: pin the
# fingerprint actually seen on the FIRST run this machine ever sees,
# persisted under the caller's own StateDirectory= (NOT RuntimeDirectory=,
# which is torn down between every Type=oneshot run and would silently
# re-learn a swapped cert as the new "trusted" value on every single run,
# defeating the entire point). Every later run must match that persisted
# pin, or this script fails and deletes the untrusted cert.
#
# Usage: verify_ca_fingerprint.sh <ca.crt path> <pin file path>
#   - ca.crt path missing/empty: nothing to verify yet (the extraction step
#     that should have produced it already logs/handles that failure on its
#     own terms) -- exits 0.
#   - pin file missing/empty: first run seen on this host -- learn and
#     persist the current fingerprint, exit 0.
#   - fingerprint mismatch: DELETE the ca.crt (so a caller whose CA
#     extraction is best-effort degrades exactly as if extraction had
#     failed outright, rather than leaving an untrusted cert sitting where
#     a later step might still read it) and exit 1.
#   - deliberate cert rotation: an operator deletes the pin file to re-arm
#     TOFU for one more first-use pin.
set -euo pipefail

CA_PATH="${1:?Usage: $0 <ca.crt path> <pin file path>}"
PIN_PATH="${2:?Usage: $0 <ca.crt path> <pin file path>}"

if [ ! -s "$CA_PATH" ]; then
  echo "[INFO] $CA_PATH missing or empty, nothing to verify" >&2
  exit 0
fi

fingerprint="$(openssl x509 -in "$CA_PATH" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
if [ -z "$fingerprint" ]; then
  echo "[FATAL] could not compute a SHA-256 fingerprint of $CA_PATH" >&2
  rm -f "$CA_PATH"
  exit 1
fi

if [ ! -s "$PIN_PATH" ]; then
  printf '%s\n' "$fingerprint" > "$PIN_PATH"
  echo "[INFO] pinned ES CA fingerprint on first use: $fingerprint" >&2
  exit 0
fi

pinned="$(cat "$PIN_PATH")"
if [ "$fingerprint" != "$pinned" ]; then
  echo "[FATAL] ES CA fingerprint changed: expected $pinned, got $fingerprint -- refusing to trust it. If this is a deliberate cert rotation, delete $PIN_PATH to re-pin." >&2
  rm -f "$CA_PATH"
  exit 1
fi

exit 0

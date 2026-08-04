#!/usr/bin/env bash
# =============================================================================
# verify_encryption.sh — WS3.1 acceptance evidence: encryption in transit & at rest.
#
# Confirms, against the RUNNING stack, that telemetry is encrypted on every hop
# (no plaintext on the wire) and reports the at-rest posture. Exit 0 only if every
# transit check passes. Safe to run repeatedly; read-only (no mutations).
#
#   bash scripts/setup/verify_encryption.sh
#
# SOC 2 control evidence — pairs with docs/SOP-011-encryption.md. Collected by the
# WS3.7 continuous control monitor.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVF="$HERE/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENVF" ]] && { set -a; . "$ENVF"; set +a; }
ES_PASS="${ELASTIC_PASSWORD:-${ES_PASS:-}}"
# Defaults match docker-compose.yml's explicit `name: suburban-soc` (top-level
# project name), which prefixes every auto-named resource - NOT the directory
# name (scripts/setup), which is what older `setup_*` defaults assumed and
# what compose falls back to only when no `name:` is set. Confirmed via
# `docker network ls` / `docker volume ls` against the live stack (#219).
NET="${SOC_NET:-suburban-soc_soc-mesh-net}"
CERTVOL="${SOC_CERT_VOL:-suburban-soc_certs}"
LS_IMG="docker.elastic.co/logstash/logstash:${STACK_VERSION:-9.3.2}"
fails=0
pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; fails=$((fails+1)); }
info() { echo "  [INFO] $1"; }

echo "== Encryption in transit =="

# 1) ES HTTP layer must be TLS-only — a plaintext request to :9200 must be refused.
code="$(curl -s -m5 -o /dev/null -w '%{http_code}' http://localhost:9200 2>/dev/null)"
[[ "$code" == "000" ]] && pass "ES :9200 rejects plaintext HTTP (TLS-only)" \
                        || fail "ES :9200 answered plaintext HTTP with $code (expected TLS-only)"

# 2) ES TLS cert must chain to the stack CA (verified, not -k).
docker run --rm -v "$CERTVOL":/certs alpine cat /certs/ca/ca.crt >/tmp/soc_ca.crt 2>/dev/null
if curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" https://localhost:9200 \
     | grep -q '"cluster_name"'; then
  pass "ES :9200 HTTPS cert verifies against the stack CA"
else
  fail "ES :9200 HTTPS cert did NOT verify against the stack CA"
fi

# 3) ES transport layer (inter-node) must run TLS — required for HA (WS2.4) / scale-out.
ttls="$(curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" \
        'https://localhost:9200/_nodes/settings?filter_path=nodes.*.settings.xpack.security.transport.ssl.enabled' 2>/dev/null)"
echo "$ttls" | grep -q '"enabled":"true"' \
  && pass "ES transport TLS enabled (xpack.security.transport.ssl.enabled=true)" \
  || info "ES transport TLS not reported enabled (single-node MVP; required before scale-out)"

# 4) Beats input (:5044, Filebeat->Logstash) must require TLS, present a CA-signed
#    cert, AND require the CLIENT to present one too (mTLS, #219). Two checks: a
#    legitimate client (with the filebeat cert) must succeed; a client presenting
#    no certificate at all must be rejected. Before #219, ssl_certificate_authorities
#    was set but ssl_client_authentication was not, so the second check below FAILED
#    (any client could complete the handshake with no certificate) even though the
#    original single-check version of this test PASSED, since it only proved TLS was
#    present, not that client auth was enforced — do not collapse these back into one.
hs_authed="$(docker run --rm --user 0 --network "$NET" -v "$CERTVOL":/certs --entrypoint sh "$LS_IMG" -c \
      'echo | openssl s_client -connect logstash:5044 -CAfile /certs/ca/ca.crt -cert /certs/filebeat/filebeat.crt -key /certs/filebeat/filebeat.key 2>/dev/null' 2>/dev/null)"
if echo "$hs_authed" | grep -q 'Verify return code: 0 (ok)' && echo "$hs_authed" | grep -q 'CN=logstash'; then
  proto="$(echo "$hs_authed" | grep -oE 'TLSv1\.[0-9]' | head -1)"
  pass "Beats :5044 serves TLS ($proto), cert verifies against the CA, legit client-cert auth succeeds"
else
  fail "Beats :5044 did NOT complete a verified TLS handshake WITH a valid client cert (legitimate shippers would be broken)"
fi

# TLS 1.3 quirk (caught testing this): the CLIENT's own handshake summary
# ("Verify return code: 0 (ok)") reflects the client verifying the SERVER's
# cert, which completes in the same flight as the server's Finished message -
# before the server has even processed the client's (empty) Certificate
# message. So `openssl s_client` reports a clean handshake from the client's
# side REGARDLESS of whether the server then rejects for missing client auth;
# it is not a reliable signal either way. What IS reliable: the server-side
# reject happens milliseconds later when it decodes the client's Certificate
# message, and Logstash logs it immediately
# ("SSLHandshakeException: (certificate_required) Empty client certificate
# chain") — so this checks the Logstash container's own log output around the
# probe instead of the client-side TLS summary.
LS_CONTAINER="${SOC_LOGSTASH_CONTAINER:-logstash}"
# `docker logs --since <timestamp>` proved unreliable here (WSL host clock vs.
# Docker Desktop's internal VM clock can drift enough to miss a log line
# emitted within the same second) — follow the log stream from before the
# probe runs instead, which isn't subject to clock comparison at all.
noauth_logfile="$(mktemp)"
trap 'kill "$noauth_tail_pid" 2>/dev/null; rm -f "$noauth_logfile"' EXIT
docker logs --tail 0 -f "$LS_CONTAINER" >"$noauth_logfile" 2>&1 &
noauth_tail_pid=$!
sleep 1
docker run --rm --user 0 --network "$NET" -v "$CERTVOL":/certs --entrypoint sh "$LS_IMG" -c \
      'openssl s_client -connect logstash:5044 -CAfile /certs/ca/ca.crt <<< "x"' >/dev/null 2>&1
sleep 2
kill "$noauth_tail_pid" 2>/dev/null
noauth_log="$(cat "$noauth_logfile")"
if echo "$noauth_log" | grep -qi 'certificate_required\|SSLHandshakeException.*[Cc]lient certificate'; then
  pass "Beats :5044 REJECTS a connection with no client certificate (mTLS enforced, #219 — confirmed via Logstash's own SSLHandshakeException log)"
else
  fail "Beats :5044 did not log a client-certificate rejection for a certless connection - mTLS may NOT be enforced (or Logstash logs/container name changed - check \$SOC_LOGSTASH_CONTAINER)"
fi

echo "== Encryption at rest =="
# 5) Snapshot repository present (off-cluster immutable copy lives on encrypted storage).
if curl -s -m5 --cacert /tmp/soc_ca.crt -u "elastic:${ES_PASS}" \
     https://localhost:9200/_snapshot/suburban-soc-snapshots 2>/dev/null | grep -q '"type"'; then
  pass "Snapshot repository 'suburban-soc-snapshots' registered"
else
  info "Snapshot repository not registered (run apply-lifecycle.sh)"
fi
# 6) At-rest encryption of the ES data volume + snapshot storage is delivered by
#    host full-disk/volume encryption (LUKS/dm-crypt or cloud-provider encrypted
#    disks) — see docs/SOP-011-encryption.md. Operator attestation item; the script
#    cannot read the host crypto layer from inside a container.
info "Data-at-rest: ES volume + snapshot store rely on host disk encryption (SOP-011, operator attestation)"

rm -f /tmp/soc_ca.crt
echo
if [[ $fails -eq 0 ]]; then echo "[=] Encryption-in-transit verified on every checked hop."; exit 0
else echo "[=] $fails encryption check(s) FAILED."; exit 1; fi

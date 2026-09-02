#!/usr/bin/env bash
# =============================================================================
# generate_certs.sh — Internal CA + service certificates  (CDP §6)
# =============================================================================
# Re-enables transport security by minting a semester-scoped internal CA and
# per-service certificates for the SOC stack. Run this ONCE before
# `docker compose up`. Re-run each semester to rotate (CDP §6).
#
#   ./generate_certs.sh
#
# Produces (under ./certs, git-ignored):
#   certs/ca/ca.crt           internal CA certificate (trust anchor)
#   certs/ca/ca.key           CA private key (KEEP OFF GIT)
#   certs/es/es.crt|es.key    Elasticsearch node cert (http + transport)
#
# The transport layer is configured with verification_mode=certificate, so
# every node/client must present a cert signed by this CA — i.e. mTLS.
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# SAFETY GUARD (added after a live incident): this standalone script is NOT the
# stack's source of truth for certificates. docker-compose.yml runs a one-shot
# `setup` service that mints an Elastic-certutil CA + node certs into the shared
# `certs` volume. This script instead mints a SEPARATE "Suburban-SOC Internal CA" with
# a different layout (certs/es/...). If its output reaches the compose `certs`
# volume, the CA no longer matches the running Elasticsearch node cert and every
# client (Logstash, Kibana, curl) fails TLS with "PKIX path building failed",
# silently halting ingestion. Do NOT run this against a stack provisioned by
# docker compose. Require an explicit opt-in so it can't be run by accident.
if [[ "${ALLOW_STANDALONE_CERTS:-0}" != "1" ]]; then
  cat >&2 <<'WARN'
[REFUSED] generate_certs.sh is a standalone alternative and is NOT needed for the
          docker-compose stack — the compose `setup` service is the single source
          of truth for certificates. Running this can overwrite the stack CA and
          break Elasticsearch TLS for every client (ingestion stops).

          If you really intend to mint standalone certs (no compose stack), re-run:
              ALLOW_STANDALONE_CERTS=1 ./generate_certs.sh
WARN
  exit 1
fi

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
CA_DIR="$CERT_DIR/ca"
ES_DIR="$CERT_DIR/es"
DAYS=180   # one semester; rotate on expiry

mkdir -p "$CA_DIR" "$ES_DIR"

if [[ -f "$CA_DIR/ca.crt" ]]; then
  echo "[=] CA already exists at $CA_DIR/ca.crt — delete ./certs to regenerate. Skipping."
  echo "[!] If this CA predates the O=Suburban-SOC subject fix (#508), it still carries"
  echo "    the old O=UIW-SOC subject — delete ./certs and re-run to pick up the fix."
  exit 0
fi

echo "[*] Generating internal CA (valid ${DAYS} days)..."
openssl genrsa -out "$CA_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days "$DAYS" \
  -subj "/O=Suburban-SOC/OU=CDP/CN=Suburban-SOC Internal CA" \
  -out "$CA_DIR/ca.crt"

echo "[*] Generating Elasticsearch node certificate..."
openssl genrsa -out "$ES_DIR/es.key" 4096
# SANs cover the in-network service name and localhost for host access.
openssl req -new -key "$ES_DIR/es.key" \
  -subj "/O=Suburban-SOC/OU=CDP/CN=elasticsearch" \
  -out "$ES_DIR/es.csr"

cat > "$ES_DIR/es.ext" <<'EOF'
subjectAltName = DNS:elasticsearch, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth, clientAuth
EOF

openssl x509 -req -in "$ES_DIR/es.csr" \
  -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
  -sha256 -days "$DAYS" -extfile "$ES_DIR/es.ext" \
  -out "$ES_DIR/es.crt"

rm -f "$ES_DIR/es.csr" "$ES_DIR/es.ext"
chmod 600 "$CA_DIR/ca.key" "$ES_DIR/es.key"

echo "[+] Certificates written to $CERT_DIR"
echo "[!] Set ELASTIC_PASSWORD in scripts/setup/.env before 'docker compose up'."

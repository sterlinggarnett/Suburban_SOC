#!/usr/bin/env bash
# =============================================================================
# apply-templates.sh — install the Suburban-SOC index templates.
#
# Pins ECS fields in logstash-security-* and soar-actions-* to keyword/ip/date
# so cross-index aggregations and Kibana dashboards are consistent. Without
# these, Elasticsearch dynamically maps strings to `text` (fielddata disabled),
# which silently fails shard-level aggregations and produces data-view conflicts.
#
# Templates apply to indices created AFTER they are installed — field types
# cannot be changed in place. logstash-security-*/soar-actions-* are data
# streams (see each template's "data_stream": {}), so the fix-existing-data
# step for THOSE is a rollover, not a reindex: reindex-existing.sh predates
# the data-stream conversion, targets legacy daily indices only, and cannot
# delete a data stream as its cleanup step assumes. Force the current write
# index to roll over immediately instead — non-destructive, no data loss,
# matches the pattern already used in scripts/setup/verify_lifecycle.sh:
#   POST /<data-stream-name>/_rollover
# History still on the pre-rollover backing indices keeps the old mapping
# until it ages out under each index's ILM policy.
# agent-checkpoints-* is NOT a data stream (#245 — dropped intentionally, it
# only ever holds keyed-by-alert_id upsert/read-by-id documents, which data
# streams can't serve) — a mapping change there is a plain reindex-existing.sh
# case, or in practice a non-issue since the index is only ever populated by
# checkpoints.py's own writes going forward.
#
# Usage (from repo root or anywhere):
#   ES_URL=https://localhost:9200 ES_USER=elastic ES_PASS=... ./apply-templates.sh
# Env (auto-loaded from scripts/setup/.env if present):
#   ES_URL (default https://localhost:9200), ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD
#   ES_CA (default /certs/ca/ca.crt) — FAILS CLOSED if unreadable; set
#   ES_INSECURE=true to explicitly skip TLS verification (lab only).
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

# Shared ES creds + TLS + es() (issue #156; audit #166 — no local -k downgrade).
# shellcheck source=../../scripts/setup/lib/es_common.sh
source "$HERE/../../scripts/setup/lib/es_common.sh"

# A template PUT that ES rejects (e.g. an unsupported mapping parameter) still
# gets a normal curl exit code (curl considers receiving any HTTP response a
# success) — the old fire-and-print-the-code version of this script would have
# shipped a silently-discarded template update with no error anywhere. Assert
# on the code instead of just printing it.
put_and_check() {
  local label="$1" url="$2" body_file="$3"
  local response code body
  response="$(esj -X PUT "$url" --data-binary "@$body_file" -w $'\nHTTPSTATUS:%{http_code}')"
  code="${response##*HTTPSTATUS:}"
  body="${response%$'\n'HTTPSTATUS:*}"
  echo "==> Installing $label -> HTTP $code"
  if [[ "$code" != "200" ]]; then
    echo "    FAILED: $body" >&2
    exit 1
  fi
}

put_and_check "logstash-security-template" \
  "$ES_URL/_index_template/logstash-security-template" \
  "$HERE/logstash-security-template.json"

put_and_check "soar-actions-template" \
  "$ES_URL/_index_template/soar-actions-template" \
  "$HERE/soar-actions-template.json"

put_and_check "agent-checkpoints-template" \
  "$ES_URL/_index_template/agent-checkpoints-template" \
  "$HERE/agent-checkpoints-template.json"

echo "==> Dropping replicas to 0 on existing indices (single-node -> clears yellow)"
esj -o /dev/null -w '    logstash-security-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/logstash-security-*/_settings" -d '{"index":{"number_of_replicas":0}}'
esj -o /dev/null -w '    soar-actions-*      -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/soar-actions-*/_settings" -d '{"index":{"number_of_replicas":0}}'
esj -o /dev/null -w '    agent-checkpoints-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/agent-checkpoints-*/_settings" -d '{"index":{"number_of_replicas":0}}'

echo "Done."

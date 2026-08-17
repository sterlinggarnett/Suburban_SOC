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

# #276 security-auditor MEDIUM: a template PUT only shapes indices created
# AFTER it lands (see the file header above) — it does NOT retrofit an
# agent-checkpoints-<tenant> index that already exists from before this
# change. Under this template's dynamic:strict, that left
# resolved_by/resolved_at/resolution_reason/resolution_source (added for
# manage_stuck_claims.py's --actor/--reason attribution) unwritable on any
# non-greenfield deployment: the operator recovery tool's one write path
# would hard-fail with strict_dynamic_mapping_exception exactly when it's
# needed. Adding new properties to an existing mapping is a legal in-place
# ES operation (no reindex required) — unlike a data stream, this index
# accepts it directly. A wildcard target with zero matching indices (a
# genuinely fresh install) returns 404, which is expected and harmless.
echo "==> Adding #276 claim-attribution fields to any pre-existing agent-checkpoints-* index"
esj -o /dev/null -w '    agent-checkpoints-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/agent-checkpoints-*/_mapping" -d '{
    "properties": {
      "resolved_by":       { "type": "keyword" },
      "resolved_at":       { "type": "date" },
      "resolution_reason": { "type": "keyword" },
      "resolution_source": { "type": "keyword" },
      "resolution_actor_claimed": { "type": "keyword" }
    }
  }'

# #345: templates shape indices created AFTER they're installed (see file
# header) - for logstash-security-*/soar-actions-* (both real data streams),
# making a just-applied mapping change actually take effect on an ALREADY-
# EXISTING deployment's active write index needs an explicit rollover (see
# file header for why this is a rollover, not reindex-existing.sh, for these
# two). Every prior ignore_above/normalizer fix to these templates (#249/
# #250, #263, #290) needed this as a separate, manual, undocumented-in-code
# step to actually take effect on a live cluster - #263's own PR narrative
# records doing it by hand ("Applied live, all 6 logstash-security-* data
# streams rolled over"). Gated behind an explicit flag so it never fires
# implicitly on a routine template-apply run, matching the exact API call
# this file's own header already specifies and the pattern
# scripts/setup/verify_lifecycle.sh:111 already uses elsewhere in this repo.
# agent-checkpoints-* is deliberately excluded (see file header - it is NOT
# a data stream, #245, and _rollover only accepts a data stream/alias name).
#
# Eager rollover (not ?lazy - live-confirmed supported on the pinned ES
# 9.3.2, marks rollover_on_write:true and defers the actual index swap
# until the stream's next write instead): the file header's own existing
# language says "Force the current write index to roll over immediately",
# and an idle tenant data stream with no near-term write has no urgency
# either way, so lazy's main benefit (skip an unnecessary empty backing
# index/shard on a stream nothing is writing to) doesn't offset diverging
# from that already-documented immediate-effect intent. Costs one extra
# shard per data stream per ROLLOVER=1 run on a single-node deployment
# (security-auditor finding) - not a concern at this deployment's scale,
# but don't run this back-to-back in a loop, and check
# `GET _cat/allocation` first on a cluster already close to
# cluster.max_shards_per_node or a disk watermark.
_list_data_streams() {
  # security-auditor + code-reviewer, independently: the discovery GET's
  # HTTP status was never checked - a 403/500 (or any non-2xx) parses as
  # invalid JSON just as readily as a genuine zero-match response, both
  # silently reported "nothing to roll over" and exited 0, exactly the
  # silent-no-op #345 exists to kill. A wildcarded pattern with zero
  # matches actually returns 200 + {"data_streams":[]} (not 404 as this
  # comment previously, incorrectly, claimed - only an exact non-wildcard
  # missing name 404s) - status-check this like every other ES call in
  # this file (put_and_check's own comment: "assert on the code instead
  # of just printing it"), not silently swallow it.
  local pattern="$1" response code body
  response="$(es "$ES_URL/_data_stream/$pattern" -w $'\nHTTPSTATUS:%{http_code}')"
  code="${response##*HTTPSTATUS:}"
  body="${response%$'\n'HTTPSTATUS:*}"
  if [[ "$code" != "200" ]]; then
    echo "    FAILED to list data streams matching $pattern -> HTTP $code: $body" >&2
    exit 1
  fi
  echo "$body" | python3 -c "
import json, sys
for ds in json.load(sys.stdin).get('data_streams', []):
    print(ds['name'])
" | tr -d '\r'
}

if [[ "${ROLLOVER:-0}" == "1" ]]; then
  echo "==> ROLLOVER=1: rolling over existing data streams so the just-applied template mapping takes effect on their active write index"
  # security-auditor follow-up: rollover is ADDITIVE, not idempotent, unlike
  # every other step in this script - re-running after a partial failure
  # would double-roll whichever streams already succeeded. Collect failures
  # across the WHOLE loop instead of put_and_check's abort-on-first
  # convention, so one bad stream doesn't stop the rest from being
  # attempted, and report a clear summary before exiting.
  failed=()
  for pattern in "logstash-security-*" "soar-actions-*"; do
    names="$(_list_data_streams "$pattern")"
    if [[ -z "$names" ]]; then
      echo "    $pattern -> no matching data streams yet, nothing to roll over"
      continue
    fi
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      # --globoff: a data-stream name containing "[" or "{" (not expected
      # from this repo's own tenant-provisioning naming, but this name
      # came from a live ES response, not a static string) must not be
      # interpreted as curl's own URL-glob syntax.
      code="$(es_code --globoff -X POST "$ES_URL/$name/_rollover")"
      echo "    $name -> HTTP $code"
      [[ "$code" != "200" ]] && failed+=("$name (HTTP $code)")
    done <<< "$names"
  done
  if [[ ${#failed[@]} -gt 0 ]]; then
    echo "FAILED to roll over ${#failed[@]} data stream(s): ${failed[*]}" >&2
    echo "Streams NOT listed above already rolled over successfully - do not re-run without excluding them, rollover is not idempotent." >&2
    exit 1
  fi
else
  echo "==> Skipping data-stream rollover (set ROLLOVER=1 to roll over"
  echo "    logstash-security-*/soar-actions-* so the template changes just"
  echo "    applied above take effect on their active write index too)"
  # security-auditor follow-up: ROLLOVER being opt-in (correct - see above)
  # reintroduces the exact "operator forgets, the fix silently doesn't
  # take effect" risk #345 itself is about, unless the reminder above is
  # actually seen. A live count (not just static advice) is harder to
  # tune out on a routine run - read-only, so worth doing unconditionally.
  pending=0
  for pattern in "logstash-security-*" "soar-actions-*"; do
    count="$(_list_data_streams "$pattern" | grep -c . || true)"
    pending=$((pending + count))
  done
  if [[ "$pending" -gt 0 ]]; then
    echo "    $pending existing data stream(s) will KEEP their old mapping on their active write index until rolled over"
  fi
fi

echo "==> Dropping replicas to 0 on existing indices (single-node -> clears yellow)"
esj -o /dev/null -w '    logstash-security-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/logstash-security-*/_settings" -d '{"index":{"number_of_replicas":0}}'
esj -o /dev/null -w '    soar-actions-*      -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/soar-actions-*/_settings" -d '{"index":{"number_of_replicas":0}}'
esj -o /dev/null -w '    agent-checkpoints-* -> HTTP %{http_code}\n' -X PUT \
  "$ES_URL/agent-checkpoints-*/_settings" -d '{"index":{"number_of_replicas":0}}'

echo "Done."

#!/usr/bin/env bash
# =============================================================================
# refresh_intel.sh — auto-refresh the Zeek threat-intel feed (WS1.3 / #222).
#
# Replaces the 2 static intel.dat entries with TWO live, keyless feeds
# (abuse.ch Feodo Tracker botnet-C2 IPs, Proofpoint/Emerging Threats
# compromised-host IPs) merged with the curated seed (intel.seed.dat —
# always includes the WS1.1 test indicators). Writes the Zeek Intel
# framework format, and indexes both the indicators and a freshness/heartbeat
# doc into Elasticsearch so the dashboard can show feed age and alert when stale.
#
# Fail-safe, per feed: one feed's fetch failing never empties the OTHER feed
# or the seed — but the run still records status=stale (so cron/monitoring
# catches a degraded feed even if the merged output isn't empty) and exits
# non-zero.
#
# Schedule: systemd timer (configs/systemd/intel-refresh.{service,timer}),
# installed via scripts/setup/install_intel_refresh_timer.sh — not a manual
# crontab edit (#222; superseded the old intel-refresh.cron file).
#
# Env (auto-loaded from scripts/setup/.env): ES_URL (https://localhost:9200),
#   ES_USER (elastic), ES_PASS/ELASTIC_PASSWORD. Feeds overridable via
#   FEODO_URL / ET_COMPROMISED_URL.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$HERE/../../scripts/setup/.env"
# shellcheck disable=SC1090  # .env is gitignored, no static file to point at
[[ -f "$ENV_FILE" ]] && { set -a; . "$ENV_FILE"; set +a; }

# These serve the no-ES path: the if-block below only indexes when ES_PASS is set,
# and es_common.sh (sourced inside that block) re-resolves the same three vars.
ES_URL="${ES_URL:-https://localhost:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-}}"

FEODO_URL="${FEODO_URL:-https://feodotracker.abuse.ch/downloads/ipblocklist.txt}"
# #222: second keyless feed, chosen specifically because it is the same
# plain-newline-separated-IPv4 format Feodo Tracker already uses — reuses
# fetch_feed() below with zero new parsing logic, rather than adding a
# second format (e.g. URLhaus's full-URL list) and its own risk surface.
ET_COMPROMISED_URL="${ET_COMPROMISED_URL:-https://rules.emergingthreats.net/blockrules/compromised-ips.txt}"
SEED="$HERE/intel.seed.dat"
OUT="$HERE/intel.dat"
# If the live capture's bind-mount path exists, refresh it too so running Zeek
# picks up the new feed on its next read without a manual re-sync.
LIVE_DIR="/storage/PCAP/intel"

IPV4_RE='^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$'
# security-auditor review: the IPv4 shape check alone lets bogon/infrastructure
# addresses through — 0.0.0.0, loopback, RFC1918/link-local/CGNAT, multicast,
# broadcast all match IPV4_RE cleanly. A single bad entry from either feed
# (upstream error, compromised mirror, DNS/BGP hijack of the feed host) would
# otherwise turn every internal flow to that address into an "intel hit" —
# an alert-storm on the analyst queue, not a detection.
BOGON_RE='^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|22[4-9]\.|23[0-9]\.|255\.255\.255\.255$)'

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '[intel] %s %s\n' "$(ts)" "$*"; }

# mktemp -p "$HERE": same filesystem as $OUT (configs/intel/), not the
# default /tmp — under this unit's PrivateTmp=true, /tmp is a private tmpfs,
# so `mv` from there to $OUT would be a cross-device copy (open/truncate/
# write), not an atomic rename, defeating the whole point of building the
# new file under a temp name first (security-auditor review: Zeek reads
# intel.dat in Input::REREAD mode and re-reads on any mtime change, so a
# non-atomic write risks it reading a truncated file mid-write while live).
tmp="$(mktemp -p "$HERE")"; tmp_ips="$(mktemp)"; tmp_ips_et="$(mktemp)"
trap 'rm -f "$tmp" "$tmp_ips" "$tmp_ips_et"' EXIT

# --- 1. Fetch each live feed (fail-safe per feed) ----------------------------
# One feed's failure never empties the other feed or the seed; it only drops
# that feed's IPs for this run and marks the whole run's heartbeat "stale" so
# a degraded (not just fully dead) feed is still visible to monitoring.
fetch_feed() {
  # $1=url $2=output-file. Capture to stdout (portable across curl flavors)
  # rather than -o <file>. Prints the clean, deduped, bogon-filtered IPv4
  # count; leaves $2 empty (truncated, not left unset) on any failure.
  # --max-filesize 10M (security-auditor review): curl enforces this against
  # the Content-Length header / actual bytes transferred and fails the
  # request rather than buffering an unbounded response into $raw — bounds a
  # hostile or badly-broken feed endpoint from pressuring host memory hard
  # enough to threaten Elasticsearch. 10M is roughly 400x the largest feed
  # observed live (Emerging Threats compromised-ips.txt, ~25KB).
  local url="$1" out="$2" raw
  if raw="$(curl -fsS --max-time 30 --max-filesize 10485760 "$url" 2>/dev/null)" && [[ -n "$raw" ]]; then
    # Keep only valid, non-bogon IPv4 lines (strip comments/blanks/CRs).
    printf '%s\n' "$raw" | grep -vE '^\s*#|^\s*$' | tr -d '\r' | awk '{print $1}' \
      | grep -E "$IPV4_RE" | grep -vE "$BOGON_RE" | sort -u > "$out" || true
  else
    : > "$out"
  fi
  # wc -l on the now-clean file, not grep -c on raw input: grep -c both
  # prints AND exits non-zero on zero matches, which would corrupt the count.
  wc -l < "$out" | tr -d ' '
}

# security-auditor review: a missing/empty seed silently produced a
# header-only (or seed-less) intel.dat that could still report status=ok
# if both live feeds fetched fine — quietly dropping the WS1.1 TEST
# indicator (198.51.100.66) docs/SOP-147-evidence-validation-procedure.md
# depends on, with nothing surfacing it. The seed is checked into git
# specifically so this should never happen outside a broken checkout, but
# "never happen" is exactly the case worth failing loudly on rather than
# silently.
status="ok"
if [[ ! -s "$SEED" ]]; then
  status="stale"
  log "WARN: seed file missing or empty ($SEED) — intel.dat will lack the curated fail-safe indicators"
fi

feodo_count=$(fetch_feed "$FEODO_URL" "$tmp_ips")
if [[ "$feodo_count" -eq 0 ]]; then
  status="stale"
  log "WARN: Feodo fetch failed/empty ($FEODO_URL) — keeping seed + other feed only"
else
  log "fetched $feodo_count IPs from Feodo Tracker"
fi

et_count=$(fetch_feed "$ET_COMPROMISED_URL" "$tmp_ips_et")
if [[ "$et_count" -eq 0 ]]; then
  status="stale"
  log "WARN: Emerging Threats fetch failed/empty ($ET_COMPROMISED_URL) — keeping seed + other feed only"
else
  log "fetched $et_count IPs from Emerging Threats compromised-ips"
fi

# --- 2. Build the Zeek Intel .dat (seed + both live feeds), atomically -------
{
  printf '#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\n'
  # Curated seed (skip its header/comment lines).
  grep -vE '^\s*#|^\s*$' "$SEED"
  # Live Feodo IPs as Intel::ADDR.
  while IFS= read -r ip; do
    [[ -n "$ip" ]] && printf '%s\tIntel::ADDR\tabuse.ch/Feodo\tBotnet C2 IP (auto)\n' "$ip"
  done < "$tmp_ips"
  # Live Emerging Threats compromised-host IPs as Intel::ADDR (#222).
  while IFS= read -r ip; do
    [[ -n "$ip" ]] && printf '%s\tIntel::ADDR\temergingthreats.net/compromised-ips\tCompromised host IP (auto)\n' "$ip"
  done < "$tmp_ips_et"
} > "$tmp"

# De-dupe on the indicator column while preserving the header — the two live
# feeds (and the seed) can and do overlap on individual IPs. Which source
# label "wins" among duplicates depends on sort -u's implementation and is
# not a documented guarantee (not fixed - harmless either way, since this
# column is provenance/labeling only and does not affect detection).
{ head -1 "$tmp"; tail -n +2 "$tmp" | sort -u -t$'\t' -k1,1; } > "${tmp}.dedup"
mv "${tmp}.dedup" "$tmp"

live_count=$((feodo_count + et_count))
total=$(($(grep -cvE '^\s*#' "$tmp") ))
mv "$tmp" "$OUT"
log "wrote $OUT ($total indicators: $feodo_count Feodo + $et_count ET + seed, $live_count live before de-dup)"
if [[ -d "$LIVE_DIR" ]]; then
  # Atomic (write-then-rename within the SAME directory, not a plain in-place
  # cp) for the same reason $OUT's own write is (security-auditor review) —
  # a partial in-place cp is exactly as dangerous to a live-reading Zeek as a
  # partial in-place write to $OUT itself would have been.
  if cp "$OUT" "$LIVE_DIR/.intel.dat.tmp" 2>/dev/null && mv "$LIVE_DIR/.intel.dat.tmp" "$LIVE_DIR/intel.dat" 2>/dev/null; then
    log "synced live feed -> $LIVE_DIR/intel.dat"
  else
    # The RUNNING Zeek capture is still reading whatever it last had (stale,
    # not corrupt - the failed write never touched the real file), but that
    # is exactly the condition the heartbeat exists to surface, so it must
    # not report "ok" (security-auditor review: previously this branch only
    # logged a NOTE and left status untouched).
    status="stale"
    rm -f "$LIVE_DIR/.intel.dat.tmp" 2>/dev/null
    log "WARN: could not write $LIVE_DIR (permissions?) — live Zeek capture still on the previous feed"
  fi
fi

# --- 3. Index indicators + a freshness heartbeat into Elasticsearch ----------
if [[ -n "$ES_PASS" ]]; then
  # No hardcoded Content-Type — each call sets its own (bulk=x-ndjson, doc=json),
  # so we never send two Content-Type headers (ES rejects that).
  # Shared ES creds + TLS + es()/es_bulk() (issue #156). Sourced inside the
  # `if [[ -n "$ES_PASS" ]]` block so the feed refresh still runs without ES creds.
  # shellcheck source=../../scripts/setup/lib/es_common.sh
  source "$HERE/../../scripts/setup/lib/es_common.sh"
  # 3a. Upsert each indicator (_id = indicator) into threat-intel-indicators so
  #     re-runs don't duplicate; ECS threat.indicator.* + threat.feed.name.
  bulk="$(mktemp)"
  now="$(ts)"
  # No python/jq dependency: indicators are validated IPv4/domains and the type/feed
  # are fixed strings, so they embed in JSON safely without escaping.
  grep -vE '^\s*#|^\s*$' "$OUT" | while IFS=$'\t' read -r ind itype isrc _; do
    [[ -z "$ind" ]] && continue
    if [[ "$itype" == "Intel::ADDR" ]]; then field="ip"; else field="domain"; fi
    printf '{"index":{"_index":"threat-intel-indicators","_id":"%s"}}\n' "$ind"
    printf '{"@timestamp":"%s","threat":{"indicator":{"%s":"%s","type":"%s"},"feed":{"name":"%s"}}}\n' \
      "$now" "$field" "$ind" "$itype" "$isrc"
  done > "$bulk"
  if [[ -s "$bulk" ]]; then
    # security-auditor review: the previous version discarded the response
    # body/status entirely (-o /dev/null -w ''), so an auth failure, a
    # rejected bulk, or a partial per-item failure inside a 200 response
    # (ES's _bulk can return HTTP 200 with an embedded "errors":true — same
    # failure mode agent.py's write_audit() already guards against) all
    # logged "indexed N indicators" regardless of what actually happened.
    # Pipe via stdin (@-) rather than @file for portability across curl flavors.
    bulk_resp="$(mktemp)"
    bulk_code="$(es -X POST "$ES_URL/_bulk" -H 'Content-Type: application/x-ndjson' \
      --data-binary @- -o "$bulk_resp" -w '%{http_code}' < "$bulk" 2>/dev/null)"
    if [[ "$bulk_code" == 2* ]] && ! grep -q '"errors":true' "$bulk_resp"; then
      log "indexed $total indicators into threat-intel-indicators"
    else
      status="stale"
      log "WARN: bulk index to threat-intel-indicators failed or partially failed (HTTP $bulk_code) — indicator index may be incomplete/stale"
    fi
    rm -f "$bulk_resp"
  fi
  rm -f "$bulk"
  # 3b. Heartbeat doc for the freshness panel / stale-feed alert. One combined
  # doc per run (not one per feed, #222) — intel_feed_stale.json's Watcher
  # only checks for ANY status=ok doc in the window, and the "Live
  # Indicators"/"Indicators in Feed" dashboard panels (configs/server/
  # intel_feed_health.ndjson) are single metric tiles keyed on live_count/
  # indicator_count, not broken out per feed. Per-feed counts (feeds.feodo/
  # feeds.et_compromised) are included anyway, unused by any panel today,
  # so "which feed died" is answerable from raw data without needing a
  # dashboard change (security-auditor review).
  heartbeat_code="$(es -X POST "$ES_URL/threat-intel-meta/_doc" -H 'Content-Type: application/json' -o /dev/null -w '%{http_code}' \
    -d "{\"@timestamp\":\"$now\",\"feed\":{\"name\":\"abuse.ch/Feodo + emergingthreats.net/compromised-ips\"},\"feeds\":{\"feodo\":{\"count\":$feodo_count},\"et_compromised\":{\"count\":$et_count}},\"indicator_count\":$total,\"live_count\":$live_count,\"status\":\"$status\"}" 2>/dev/null)"
  if [[ "$heartbeat_code" == 2* ]]; then
    log "recorded freshness heartbeat (status=$status)"
  else
    # Can't set status=stale here - this IS the doc that carries status, and
    # it just failed to write. Loud enough to be found in the unit's journal.
    log "ERROR: heartbeat write to threat-intel-meta failed (HTTP $heartbeat_code) — intel_feed_stale Watcher will eventually catch this via the missing heartbeat itself"
  fi
else
  log "NOTE: ES_PASS unset — skipped ES indexing (feed file still updated)"
fi

[[ "$status" == "ok" ]] && exit 0 || exit 2

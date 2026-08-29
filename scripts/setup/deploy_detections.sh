#!/usr/bin/env bash
# =============================================================================
# deploy_detections.sh — WS1.2 detection-as-code (#93).
#
# Converts the version-controlled Sigma rules (rules/sigma/*.yml) into Elastic
# Security detection rules with pySigma + the elasticsearch backend, then imports
# them into the Kibana Detection Engine. Detection LOGIC lives in the Sigma rule,
# not in inline logstash.conf regex.
#
# Flow:  sigma convert (lucene/siem_rule_ndjson, suburban-soc-ecs pipeline)
#        -> set index to logstash-* per rule
#        -> POST /api/detection_engine/rules/_import?overwrite=true  (idempotent;
#           stable rule_id comes from each Sigma rule's `id`).
#
# rules/elastic/threshold/*.ndjson (issue #192): hand-authored Elastic `type:
# threshold` rules for the count/cardinality logic pySigma's lucene target can't
# express (see the paired `status: experimental` Sigma files, which this script's
# promotion-gate selection deliberately excludes). Imported via the same _import
# endpoint, unmodified — no index/enabled override, no pipeline conversion.
#
# The toolchain (sigma-cli + pysigma-backend-elasticsearch) is set up in a local
# venv if `sigma` is not already on PATH. Use --no-build to require it on PATH.
#
# Usage (from anywhere; env auto-loaded from scripts/setup/.env):
#   ./scripts/setup/deploy_detections.sh            # convert + import (+ enable)
#   ./scripts/setup/deploy_detections.sh --no-enable # import disabled rules
#   DETECTION_INDEX='logstash-*' ./deploy_detections.sh
# Env: KIBANA_URL (https://localhost:5601 — #177: Kibana is TLS-only now), ES_USER (elastic),
#      ES_PASS/ELASTIC_PASSWORD, DETECTION_INDEX (logstash-*).
# =============================================================================
set -euo pipefail

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
[[ -f "$SCRIPT_DIR/.env" ]] && { set -a; . "$SCRIPT_DIR/.env"; set +a; }

KIBANA_URL="${KIBANA_URL:-https://localhost:5601}"
# Shared ES creds + TLS + helpers (issue #156).
source "$SCRIPT_DIR/lib/es_common.sh"
DETECTION_INDEX="${DETECTION_INDEX:-logstash-*}"
RULES_DIR="$REPO_ROOT/rules/sigma"
PIPELINE="$REPO_ROOT/configs/detections/suburban-soc-ecs.yml"

NO_BUILD=0; ENABLE=1
for a in "$@"; do case "$a" in
  --no-build)  NO_BUILD=1 ;;
  --no-enable) ENABLE=0 ;;
  --include-experimental) INCLUDE_EXPERIMENTAL=1 ;;
  *) red "Unknown flag: $a"; exit 1 ;;
esac; done
INCLUDE_EXPERIMENTAL="${INCLUDE_EXPERIMENTAL:-0}"

# --- 1. Ensure the Sigma toolchain -------------------------------------------
SIGMA="$(command -v sigma || true)"
if [[ -n "$SIGMA" ]] && ! "$SIGMA" version 2>/dev/null | grep -qi "sigma"; then
  SIGMA=""
fi
if [[ -z "$SIGMA" ]]; then
  [[ $NO_BUILD -eq 1 ]] && { red "ERROR: 'sigma' not on PATH and --no-build set."; exit 1; }
  VENV="$REPO_ROOT/.venv-detections"
  SIGMA="$VENV/bin/sigma"; [[ -x "$SIGMA" ]] || SIGMA="$VENV/Scripts/sigma.exe"
  if [[ ! -x "$SIGMA" ]]; then
    blue "==> Setting up Sigma toolchain venv ($VENV)"
    python3 -m venv "$VENV"
    PY="$VENV/bin/python"; [[ -x "$PY" ]] || PY="$VENV/Scripts/python.exe"
    # #330: pinned to match .github/workflows/detections.yml and
    # docs/detections/SIEM_KQL_Documentation.md's generating toolchain — an
    # unpinned install here can compile a rule slightly differently
    # (semantically identical, textually different Lucene escaping) than
    # what CI/the committed docs expect.
    "$PY" -m pip install -q --disable-pip-version-check sigma-cli==3.1.0 pysigma==1.5.0 pysigma-backend-elasticsearch==2.1.1
    SIGMA="$VENV/bin/sigma"; [[ -x "$SIGMA" ]] || SIGMA="$VENV/Scripts/sigma.exe"
  fi
fi
green "    sigma: $("$SIGMA" version 2>/dev/null | tail -1)"

# --- 2. Select rules by promotion status, then convert -----------------------
# WS2.1 promotion gate: only deploy rules that have passed the test/stable gate
# (tests/detections/). `experimental` rules are excluded unless --include-experimental.
RULES=()
for f in "$RULES_DIR"/*.yml; do
  st="$(grep -m1 '^status:' "$f" | awk '{print $2}' | tr -d '[:space:]')"
  if [[ "$st" == "stable" || "$st" == "test" || "$INCLUDE_EXPERIMENTAL" == "1" ]]; then
    RULES+=("$f")
  fi
done
[[ ${#RULES[@]} -gt 0 ]] || { red "ERROR: no rules selected (all experimental? use --include-experimental)."; exit 1; }
blue "==> Converting ${#RULES[@]} Sigma rule(s) [status test/stable$([[ $INCLUDE_EXPERIMENTAL == 1 ]] && echo '+experimental')] -> Elastic detection rules"
RAW="$(mktemp)"; NDJSON="$(mktemp)"; ERR="$(mktemp)"; THRESH_TMP="$(mktemp)"
trap 'rm -f "$RAW" "$NDJSON" "$ERR" "$THRESH_TMP"' EXIT
# sigma convert is all-or-nothing: ONE invalid rule fails the whole batch, so we
# surface its stderr rather than swallowing it. JSON rule lines start with '{';
# the "Parsing Sigma rules" progress lines do not.
"$SIGMA" convert -t lucene -f siem_rule_ndjson -p "$PIPELINE" "${RULES[@]}" 2>"$ERR" \
  | grep '^{' > "$RAW" || true
count=$(wc -l < "$RAW" | tr -d ' ')
if [[ "${count:-0}" -eq 0 ]]; then
  red "ERROR: conversion produced 0 rules. sigma reported:"
  grep -iE 'error|unknown|invalid' "$ERR" | head -10 | sed 's/^/    /'
  exit 1
fi

# --- 3. Point each rule at our data index (logstash-*) + honour --no-enable ---
# audit #185: RAW is read via an explicit path (RAW_PATH), not stdin — a `<
# "$RAW"` redirect here competes with the `<<'PY'` heredoc for fd 0 (the
# heredoc always wins, since python3 - reads its own script FROM stdin first),
# which silently produced an empty NDJSON on every run. Only stdout is
# redirected to a file; the heredoc supplies the script source as intended.
ENABLE="$ENABLE" DETECTION_INDEX="$DETECTION_INDEX" RAW_PATH="$RAW" RULES_DIR="$RULES_DIR" python3 > "$NDJSON" <<'PY'
import json, os, yaml, glob
idx = os.environ["DETECTION_INDEX"].split(",")
enable = os.environ["ENABLE"] == "1"
rules_dir = os.environ["RULES_DIR"]

# Pre-parse tags from YAMLs to preserve compliance metadata
yaml_tags = {}
for f in glob.glob(os.path.join(rules_dir, "*.yml")):
    with open(f) as fdoc:
        try:
            doc = yaml.safe_load(fdoc)
            if "id" in doc and "tags" in doc:
                yaml_tags[doc["id"]] = doc["tags"]
        except Exception:
            pass

with open(os.environ["RAW_PATH"]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        r["index"] = idx
        r["enabled"] = enable
        
        # Merge compliance/custom tags missing from pySigma backend output
        rid = r.get("rule_id")
        if rid in yaml_tags:
            existing_tags = set(r.get("tags", []))
            for t in yaml_tags[rid]:
                existing_tags.add(t)
            r["tags"] = sorted(list(existing_tags))
            
        print(json.dumps(r))
PY
green "    converted $count rules (index=$DETECTION_INDEX, enabled=$([[ $ENABLE -eq 1 ]] && echo true || echo false))"

# --- 3b. Append the threshold-rule companions (issue #192) -------------------
# rules/elastic/threshold/*.ndjson pair with `status: experimental` Sigma files
# (excluded from the batch above) for the count/cardinality logic pySigma's lucene
# target can't express. Same index override + --no-enable handling as step 3,
# applied via THRESH_TMP so a "0 rules produced" failure (e.g. every file present
# but empty) is caught the same way step 3 catches it, rather than silently
# appending nothing.
#
# security-auditor review (issue #192): the import below runs with
# ?overwrite=true against stable rule_ids from the Sigma batch. Without a
# type/rule_id check here, a malformed or malicious threshold ndjson could
# silently overwrite an unrelated deployed rule. Enforce the same invariant
# tests/detections/test_threshold_rules.py already checks in CI (type ==
# "threshold", rule_id ends in "-threshold") at deploy time too — CI and
# deploy are separate trust boundaries.
THRESHOLD_DIR="$REPO_ROOT/rules/elastic/threshold"
threshold_count=0
if compgen -G "$THRESHOLD_DIR"/*.ndjson > /dev/null; then
  blue "==> Appending Elastic threshold-rule companion(s)"
  ENABLE="$ENABLE" DETECTION_INDEX="$DETECTION_INDEX" THRESHOLD_DIR="$THRESHOLD_DIR" python3 > "$THRESH_TMP" <<'PY'
import glob, json, os, sys
idx = os.environ["DETECTION_INDEX"].split(",")
enable = os.environ["ENABLE"] == "1"
for f in sorted(glob.glob(os.path.join(os.environ["THRESHOLD_DIR"], "*.ndjson"))):
    with open(f) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("type") != "threshold" or not str(r.get("rule_id", "")).endswith("-threshold"):
                print(f"REFUSING {f}: type={r.get('type')!r} rule_id={r.get('rule_id')!r} "
                      f"(expected type=threshold, rule_id ending in -threshold)", file=sys.stderr)
                sys.exit(1)
            r["index"] = idx
            r["enabled"] = enable
            print(json.dumps(r))
PY
  threshold_count=$(wc -l < "$THRESH_TMP" | tr -d ' ')
  if [[ "${threshold_count:-0}" -eq 0 ]]; then
    red "ERROR: $THRESHOLD_DIR has *.ndjson file(s) but 0 threshold rules were produced (empty/malformed/rejected file — see above)."
    exit 1
  fi
  cat "$THRESH_TMP" >> "$NDJSON"
  green "    appended $threshold_count threshold rule(s) (index=$DETECTION_INDEX, enabled=$([[ $ENABLE -eq 1 ]] && echo true || echo false))"
fi

# --- 4. Import into the Kibana Detection Engine (idempotent) -----------------
blue "==> Importing detection rules into the Kibana Detection Engine"
# Ensure the signals/alerts index exists first (no-op if already created).
es -o /dev/null -X POST \
  "${KIBANA_URL}/api/detection_engine/index" -H 'kbn-xsrf: true' || true
resp=$(es -X POST \
  "${KIBANA_URL}/api/detection_engine/rules/_import?overwrite=true" \
  -H 'kbn-xsrf: true' --form "file=@${NDJSON};type=application/ndjson" || true)

echo "$resp" | python3 -c "
import sys, json
try: d = json.load(sys.stdin)
except Exception: print('    RAW:', sys.stdin.read()[:300]); sys.exit(1)
ok = d.get('success')
print(f\"    success={ok}  imported={d.get('success_count')}  errors={len(d.get('errors',[]))}\")
for e in d.get('errors', [])[:5]:
    print('      error:', e.get('rule_id'), '-', str(e.get('error',{}).get('message'))[:160])
sys.exit(0 if ok else 2)
"
rc=$?

echo
if [[ $rc -eq 0 ]]; then
  green "=== Detection rules deployed. View/triage in Kibana → Security → Rules / Alerts. ==="
  # WS3.5: record the change (deploy changelog evidence).
  bash "$SCRIPT_DIR/deploy_changelog.sh" "detections" "deployed ${count:-?} Sigma-derived + ${threshold_count:-0} threshold rules to the Elastic Detection Engine" 2>/dev/null || true
else
  red   "=== Detection rule import reported errors (see above). ==="
fi
exit $rc

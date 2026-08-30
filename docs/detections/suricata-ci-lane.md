# Suricata detection-as-code CI lane (#445, M23 Stage 2)

Companion to the Sigma detection-engineering docs (`docs/detections/attack-coverage.md`,
`docs/detections/SIEM_KQL_Documentation.md`) — this one covers
`rules/suricata/*.rules` instead of `rules/sigma/*.yml`. Same underlying
posture as the Sigma lane (WS2.1): a rule that lands with no test coverage
is untested, not detection, and CI treats it that way.

## Why this exists

Before #445, `.github/workflows/detections.yml` was entirely Sigma-shaped —
fixture TP/TN tests, the `experimental` → `stable` promotion gate,
`event.dataset` scoping, ATT&CK/KQL doc sync — all keyed off
`rules/sigma/*.yml`. A Suricata rule (#443 shipped the sensor; #444 shipped
`eve.json` → ECS ingest) landing on top of that got **zero** CI coverage:
no syntax check, no false-positive regression, no coverage accounting. It
would look like detection and detect nothing.

## The three gates

### 1. Syntax gate (`.github/workflows/lint.yml`, job `suricata-syntax`)

Fast, always-on, no path filter — same posture as shellcheck/ruff/mypy/
yamllint. Installs the real `suricata` apt package (host-package
deployment, #443's own choice — no Docker daemon needed) and runs
`suricata -T` against the real `configs/suricata/suricata.yaml` plus every
file under `rules/suricata/*.rules` (via `-S` per file, discovered by
glob — a new category file needs no workflow edit to be covered, the same
directory-glob discipline issue #286 established for `tests/pipeline/*.py`).
A rule that fails to parse fails this job.

### 2. SID registry (`tests/detections/suricata_rules_eval.py` / `test_suricata_rules.py`)

Every SID used anywhere under `rules/suricata/` must be:

- **Unique** repo-wide. A collision (with a local rule, or with a real
  vendor SID copy-pasted by mistake) is a hard CI failure.
- **Inside a registered range** — see `SID_RANGES` in
  `suricata_rules_eval.py`:
  - `9000001`–`9000100`: the #446 university starter set.
  - `9500001`–`9599999`: genuinely local, non-vendor-derived signatures
    (`rules/suricata/local.rules`).

  A SID outside both is rejected — it's either an un-reviewed vendor SID
  liable to collide with a real `suricata-update` pull later, or a typo.

A landed `.rules` file must also be referenced in `suricata.yaml`'s
`rule-files:` list — a file that parses fine locally but was never wired
into the production config is the file-level version of the same
"looks like coverage, detects nothing" gap.

### 3. Pcap-replay promotion gate

Mirrors the Sigma lane's own promotion gate (`test_sigma_detections.py`):
an **enabled** rule (not commented out with a leading `#`) must have a
passing pcap fixture, or it "cannot enter the enabled set" (#445's own
wording). See `tests/detections/fixtures/suricata/README.md` for the
fixture-naming convention (`<sid>_tp.pcap` / `<sid>_tn.pcap`) and how to
build one.

The replay itself runs a **real** `suricata` binary against the fixture
(`suricata -r <pcap> -S <one-rule file> -c configs/suricata/suricata.yaml`)
and inspects the real `eve.json` output for an `alert` event carrying that
SID — genuine verification of Suricata's own match behavior, not a
reimplementation of it (the same posture `test_suricata_config.py`'s
`ConfigSyntaxTests` established for `-T`).

A rule with no fixture stays disabled; a fixture that doesn't actually
fire the rule (or a true-negative fixture that fires when it shouldn't)
fails CI just as loudly as a Sigma fixture mismatch does.

## Where it runs

- `suricata-syntax` (lint.yml): every PR, no path filter.
- `Suricata SID registry + pcap-replay promotion gate (issue #445)`
  (detections.yml, `detections` job): every PR, no path filter, required
  — it installs `suricata` (apt) and `scapy` (pip, pinned) itself, the
  same non-flaky "real package install" pattern `live-fire`'s tcpdump
  step already uses, so it did not need the non-required `live-fire`
  job's isolation from Docker/Elasticsearch container-pull flakiness.

## Current status (Stage 2, 2026-08-30)

`rules/suricata/` carries exactly one file, `local.rules`, and it is
empty — Stage 1/2 shipped sensor deployment, ECS ingest, and this CI lane
itself, no rule content. Every check above therefore passes vacuously
today; `tests/detections/test_suricata_rules.py`'s meta-tests
(`SidRegistryMetaTests`, `PromotionGateMetaTests`,
`ReplayHarnessRealSuricataTests`) prove the checkers themselves actually
catch a duplicate SID, an out-of-range SID, and an enabled-rule-without-
fixture using synthetic content, independent of whether `rules/suricata/`
has any real content yet.

**Disclosed, not done:** ATT&CK coverage accounting
(`scripts/setup/build_attack_coverage.py`) does not yet include Suricata
SIDs — explicitly scoped out per #445's own either/or, see
`findings/20260830-445-suricata-attack-coverage-scope.md`. Revisit once
#446 (Stage 3) lands real rule content.

## Adding a new Suricata rule

1. Pick a SID inside `9500001`–`9599999` (local) — the `9000001`–`9000100`
   block is reserved for #446's starter set.
2. Write the rule **disabled** (leading `#`) in the appropriate
   `rules/suricata/*.rules` file, wire the file into `suricata.yaml`'s
   `rule-files:` if it's new.
3. Build a pcap fixture at `tests/detections/fixtures/suricata/<sid>_tp.pcap`
   (and optionally `_tn.pcap`) — see the fixtures README for the
   scapy-based pattern.
4. Run `pytest tests/detections/test_suricata_rules.py -v` locally; once
   the TP fixture fires and the TN (if any) doesn't, remove the leading
   `#` to enable the rule.
5. `suricata -T` (or the CI `suricata-syntax` job) confirms the aggregate
   ruleset still loads cleanly.

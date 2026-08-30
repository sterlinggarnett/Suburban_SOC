# Suricata pcap fixtures (#445 promotion gate)

Mirrors `tests/detections/fixtures.json`'s role for the Sigma lane, but as
pcap files instead of JSON events — Suricata's detection engine replays
real packets, not a Sigma-style field/value match.

## Naming convention

For a rule with `sid:<SID>;`:

- `<SID>_tp.pcap` — **required** for any rule that is enabled (not
  commented out) in its `.rules` file. Must contain traffic that fires
  the rule when replayed via `suricata -r <pcap> -S <rule file>`.
- `<SID>_tn.pcap` — optional. If present, must contain traffic that does
  **not** fire the rule — a false-positive regression guard, the Suricata
  equivalent of a Sigma `true_negatives` entry.

`tests/detections/test_suricata_rules.py`'s `PromotionGateRealRepoTests`
enforces this for every enabled rule under `rules/suricata/`: no fixture,
no enable — the same "cannot enter the enabled set" contract #445/#446
both describe.

## Building a fixture

Any tool that produces a real pcap works. The repo's own test suite builds
small synthetic ones with `scapy` (see
`ReplayHarnessRealSuricataTests` in `tests/detections/test_suricata_rules.py`
for the pattern) — a raw IP/UDP or IP/TCP packet carrying the exact bytes
the rule's `content:`/`http.*` keywords match. Keep fixtures minimal
(one flow, a handful of packets) — this is a unit-test fixture, not a
traffic sample.

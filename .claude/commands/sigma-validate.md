---
name: sigma-validate
description: Use to audit existing Sigma rules against the repo's testing standard —
  fixture coverage, conversion, and CI gate status for every rule.
---
Audit the Sigma rules given in: $ARGUMENTS (default: every rule in rules/sigma/)

For each rule:
1. Check tests/detections/fixtures.json for fixtures referencing it. The schema
   holds exactly one `true_positive` object per rule (never a list) plus a
   `true_negatives` list. Flag any rule with no `true_positive` entry or an empty/
   missing `true_negatives` list — this mirrors the actual enforced gate
   (`test_promotion_gate` in tests/detections/test_sigma_detections.py), which
   requires >=1 TP and >=1 TN, not a fixed count.
2. Verify it converts cleanly:
   sigma convert -t lucene -f siem_rule_ndjson -p configs/detections/suburban-soc-ecs.yml <rule file>
3. Run the CI gate once and map failures back to specific rules:
   python -m pytest tests/detections/test_sigma_detections.py -q

Output a table: rule file | status field | TP fixtures | TN fixtures | converts |
gate result | verdict (compliant / missing tests / failing).
Base every cell on actual command output or file contents — never assume a rule
passes without running the check. If a rule's status is test/stable but it lacks
fixtures, flag it as a promotion-gate violation.

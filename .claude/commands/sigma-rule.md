---
name: sigma-rule
description: Use whenever writing or modifying a Sigma detection rule. Enforces
  fixture creation, conversion check, and the CI gate before the rule counts as done.
---
Write a Sigma rule to detect: $ARGUMENTS (ATT&CK technique ID + short description).

1. Author the rule in rules/sigma/ following the repo's existing rule conventions.
2. Add fixtures to tests/detections/fixtures.json: 5 events that must fire (TP)
   and 5 near-miss events that must not (TN), matching the existing fixture format.
3. Verify the new rule file converts cleanly:
   sigma convert -t lucene -f siem_rule_ndjson -p configs/detections/suburban-soc-ecs.yml rules/sigma/<the file created in step 1>
4. Run the CI gate and show the output:
   python -m pytest tests/detections/test_sigma_detections.py -q
5. Not done until: conversion succeeds, all TP fixtures fire, all TN fixtures pass,
   benign baseline stays clean.
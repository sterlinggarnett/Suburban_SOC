#!/usr/bin/env python3
"""
test_sigma_detections.py — WS2.1 detection-engineering CI.

For every Sigma rule in rules/sigma/*.yml, evaluate its detection logic against
fixtures (tests/detections/fixtures.json):

  * the true_positive event MUST fire   -> a change that breaks the rule fails CI;
  * every true_negative MUST NOT fire   -> false-positive regression suite;
  * a benign baseline event fires NO rule (cross-rule FP guard);
  * promotion gate: any rule at status `test` or `stable` MUST have fixtures
    (>=1 TP and >=1 TN) and pass — experimental rules may be untested.

Prints a rule -> test coverage report. Requires PyYAML (the Detections CI installs
sigma-cli, which provides it).

Run:  pytest tests/detections/test_sigma_detections.py
"""

import json
import unittest
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
from sigma_eval import detection_matches  # noqa: E402

ROOT = HERE.parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))

# Tiers that require a passing test before a rule may carry them (promotion gate).
TESTED_STATUSES = {"test", "stable"}
BENIGN = {"Image": "C:\\Windows\\explorer.exe", "CommandLine": "C:\\Windows\\explorer.exe"}


def load_rule(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class SigmaDetectionTests(unittest.TestCase):
    def setUp(self):
        self.rules = sorted(SIGMA_DIR.glob("*.yml"))
        self.assertGreaterEqual(len(self.rules), 10)

    def test_true_positives_fire(self):
        for path in self.rules:
            fx = FIXTURES.get(path.name)
            if not fx:
                continue
            det = load_rule(path)["detection"]
            self.assertTrue(
                detection_matches(det, fx["true_positive"]),
                f"{path.name}: true_positive did NOT fire — rule logic broken")

    def test_true_negatives_do_not_fire(self):
        for path in self.rules:
            fx = FIXTURES.get(path.name)
            if not fx:
                continue
            det = load_rule(path)["detection"]
            for i, neg in enumerate(fx.get("true_negatives", [])):
                self.assertFalse(
                    detection_matches(det, neg),
                    f"{path.name}: true_negative[{i}] fired — false positive")

    def test_benign_event_fires_no_rule(self):
        for path in self.rules:
            det = load_rule(path)["detection"]
            self.assertFalse(detection_matches(det, BENIGN),
                             f"{path.name}: benign baseline event fired (false positive)")

    def test_promotion_gate(self):
        # A rule may only be `test`/`stable` if it has fixtures (>=1 TP, >=1 TN).
        violations = []
        for path in self.rules:
            status = str(load_rule(path).get("status", "experimental")).lower()
            fx = FIXTURES.get(path.name)
            if status in TESTED_STATUSES:
                if not fx:
                    violations.append(f"{path.name}: status={status} but no fixtures")
                elif "true_positive" not in fx or not fx.get("true_negatives"):
                    violations.append(f"{path.name}: status={status} needs >=1 TP and >=1 TN")
        self.assertEqual([], violations, f"promotion-gate violations: {violations}")

    def test_coverage_complete(self):
        # Every rule must have a fixture entry (rule -> test mapping is complete).
        missing = [p.name for p in self.rules if p.name not in FIXTURES]
        self.assertEqual([], missing, f"rules without fixtures: {missing}")

    def test_sharphound_flags_only_branch_fires_without_name_match(self):
        # M13 US3 (#233) security review: fixtures.json's true_positive only
        # exercises the selection_name branch of "selection_name or
        # selection_cli_flags" (Image/CommandLine contains "sharphound"). The
        # OR's other branch — the CLI-flag-only signal that fires with no
        # "sharphound" anywhere — had zero coverage, so a regression there
        # would pass CI. One targeted assertion, not a fixture entry.
        det = load_rule(SIGMA_DIR / "proc_creation_win_sharphound_bloodhound_collection.yml")["detection"]
        flags_only = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                      "CommandLine": "powershell.exe Invoke-BloodHound -CollectionMethod All"}
        self.assertTrue(detection_matches(det, flags_only),
                         "SharpHound rule regressed: CollectionMethod flags alone "
                         "(no 'sharphound' anywhere) no longer fire")

    def test_net_share_recon_catches_renamed_net1_by_original_file_name(self):
        # M13 US3 (#233) security review: net.exe internally invokes net1.exe,
        # a separate signed binary with its own PE metadata. The rule's
        # OriginalFileName fallback only checked 'net.exe', so a copy of
        # net1.exe renamed to an arbitrary filename evaded detection even
        # though the equivalent evasion against net.exe was caught. No
        # fixtures.json entry can prove this specific branch (the file's
        # single true_positive already covers the plain net.exe case).
        det = load_rule(SIGMA_DIR / "proc_creation_win_net_share_recon.yml")["detection"]
        renamed_net1 = {"Image": "C:\\Users\\Public\\svc99.exe",
                        "OriginalFileName": "net1.exe",
                        "CommandLine": "svc99.exe view \\\\FILESERVER"}
        self.assertTrue(detection_matches(det, renamed_net1),
                         "net share recon rule regressed: a renamed net1.exe "
                         "(matched only by OriginalFileName) no longer fires")

    def test_accessibility_backdoor_catches_ifeo_debugger_variant(self):
        # M13 US3 (#233) security review: the rule's original 6-selector
        # design can ONLY match when Image itself ends with an accessibility
        # binary name. The IFEO Debugger variant launches cmd.exe (not
        # sethc.exe) with the target name as an ARGUMENT — the rule's own
        # description had claimed this variant was covered; it structurally
        # could not be, since none of the Image|endswith selectors can ever
        # match cmd.exe. A dedicated selection_ifeo_* path was added; this
        # proves it actually fires, and that a legitimate accessibility
        # launch from winlogon.exe still does not.
        det = load_rule(SIGMA_DIR / "proc_creation_win_accessibility_binary_debugger_swap.yml")["detection"]
        ifeo_redirect = {"ParentImage": "C:\\Windows\\System32\\winlogon.exe",
                         "Image": "C:\\Windows\\System32\\cmd.exe",
                         "CommandLine": 'cmd.exe "sethc.exe"',
                         "OriginalFileName": "Cmd.exe"}
        self.assertTrue(detection_matches(det, ifeo_redirect),
                         "Accessibility-backdoor rule regressed: the IFEO Debugger "
                         "redirect variant (Image=cmd.exe, target name as an "
                         "argument) no longer fires")
        legit_sethc_from_winlogon = {"ParentImage": "C:\\Windows\\System32\\winlogon.exe",
                                     "Image": "C:\\Windows\\System32\\sethc.exe",
                                     "CommandLine": "sethc.exe",
                                     "OriginalFileName": "sethc.exe"}
        self.assertFalse(detection_matches(det, legit_sethc_from_winlogon),
                          "Accessibility-backdoor rule over-fired: a legitimate "
                          "sethc.exe launch from winlogon.exe should not match")


def coverage_report():
    rows = []
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        r = load_rule(path)
        fx = FIXTURES.get(path.name, {})
        rows.append((path.name, str(r.get("status", "experimental")),
                     1 if fx.get("true_positive") else 0, len(fx.get("true_negatives", []))))
    width = max(len(n) for n, *_ in rows)
    print("\nrule -> test coverage:")
    print(f"  {'rule'.ljust(width)}  status      TP  TN")
    for name, status, tp, tn in rows:
        print(f"  {name.ljust(width)}  {status.ljust(10)}  {tp}   {tn}")


if __name__ == "__main__":
    coverage_report()
    unittest.main(verbosity=2)

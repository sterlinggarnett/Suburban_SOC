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
from sigma_eval import _TEXT_MAPPED_FIELDS, detection_matches  # noqa: E402

ROOT = HERE.parents[1]
SIGMA_DIR = ROOT / "rules" / "sigma"
FIXTURES = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
INDEX_TEMPLATE_PATH = ROOT / "configs" / "elasticsearch" / "logstash-security-template.json"


def _text_mapped_fields_in_template() -> set:
    """Every field path mapped `type: text` in the real index template, at
    any nesting depth, as a dotted Sigma-style field name (#230/#243
    security review: sigma_eval.py's _TEXT_MAPPED_FIELDS is a hardcoded set
    used to decide word-boundary vs whole-string bare-equality matching -
    this walks the SAME template test_live_fire.py already loads, so a
    future field added/changed to `text` fails this test loudly instead of
    silently desyncing the two)."""
    props = json.loads(INDEX_TEMPLATE_PATH.read_text(encoding="utf-8"))["template"]["mappings"]["properties"]

    def walk(node, prefix=""):
        found = set()
        for key, val in node.items():
            path = f"{prefix}{key}"
            if val.get("type") == "text":
                found.add(path)
            if "properties" in val:
                found |= walk(val["properties"], path + ".")
        return found

    return walk(props)

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

    def test_text_mapped_fields_matches_real_index_template(self):
        # M13 US7 (#230/#243) security review (LOW): sigma_eval.py's
        # _TEXT_MAPPED_FIELDS is a hardcoded set, keyed on the pre-pipeline
        # Sigma field name, that decides whether bare equality does word-
        # boundary or whole-string matching. It's correct today (verified:
        # `message` is the only `text`-mapped field in the whole template,
        # and no pySigma transformation renames anything to/from it), but
        # nothing enforced that staying true. This fails loudly the day
        # someone adds a second `text` field or converts `message` to
        # `keyword`, instead of silently letting the two drift apart.
        actual = _text_mapped_fields_in_template()
        self.assertEqual(_TEXT_MAPPED_FIELDS, actual,
                          f"sigma_eval.py's _TEXT_MAPPED_FIELDS {_TEXT_MAPPED_FIELDS} "
                          f"no longer matches the real index template's text-mapped "
                          f"fields {actual} — update both together")

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

    def test_bcdedit_recoveryenabled_branch_fires_independently(self):
        # M13 US4 (#235/#236) code review: the fixtures.json true_positive
        # only exercises the 'ignoreallfailures' branch of
        # "recoveryenabled no OR ignoreallfailures" — the other branch never
        # fires in any fixture, so a regression there would pass CI. Also
        # proves the tab-delimited variant added for the same rule.
        det = load_rule(SIGMA_DIR / "proc_creation_win_bcdedit_recovery_disabled.yml")["detection"]
        recovery_disabled = {"Image": "C:\\Windows\\System32\\bcdedit.exe",
                             "CommandLine": "bcdedit /set {default} recoveryenabled no"}
        self.assertTrue(detection_matches(det, recovery_disabled),
                         "bcdedit rule regressed: 'recoveryenabled no' branch no longer fires")
        recovery_disabled_tab = {"Image": "C:\\Windows\\System32\\bcdedit.exe",
                                 "CommandLine": "bcdedit /set {default} recoveryenabled\tno"}
        self.assertTrue(detection_matches(det, recovery_disabled_tab),
                         "bcdedit rule regressed: tab-delimited 'recoveryenabled no' no longer fires")

    def test_posh_credential_harvesting_dpapi_branch_fires_independently(self):
        # M13 US4 (#235/#236) code review: the fixtures.json true_positive
        # only exercises selection_browser_creds — selection_dpapi (the
        # narrower DPAPI/.NET-class branch left after security review
        # dropped the too-common ConvertFrom-SecureString indicator) never
        # fires in any fixture.
        det = load_rule(SIGMA_DIR / "posh_credential_harvesting_scriptblock.yml")["detection"]
        dpapi_only = {"EventID": 4104,
                      "ScriptBlockText": "[System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 0)"}
        self.assertTrue(detection_matches(det, dpapi_only),
                         "PowerShell credential-harvesting rule regressed: the DPAPI "
                         "branch (no browser-path indicator) no longer fires")
        convertfrom_alone = {"EventID": 4104,
                             "ScriptBlockText": "$cred | ConvertFrom-SecureString | Out-File C:\\creds.xml"}
        self.assertFalse(detection_matches(det, convertfrom_alone),
                          "PowerShell credential-harvesting rule over-fired: bare "
                          "ConvertFrom-SecureString (deliberately excluded, too common "
                          "in benign ops scripting) should not match alone")

    def test_posh_data_compression_staging_compress_cmdlet_branch_fires_independently(self):
        # M13 US4 (#235/#236) code review: the fixtures.json true_positive
        # only exercises selection_dotnet_compression — the entire second
        # OR-branch (Compress-Archive AND a temp-style destination, the
        # specific design named in this rule's own description) never
        # fires in any fixture. A typo dropping a temp-path entry would
        # pass CI silently.
        det = load_rule(SIGMA_DIR / "posh_data_compression_staging.yml")["detection"]
        compress_to_temp = {"EventID": 4104,
                            "ScriptBlockText": "Compress-Archive -Path C:\\data -DestinationPath $env:TEMP\\out.zip"}
        self.assertTrue(detection_matches(det, compress_to_temp),
                         "PowerShell data-compression-staging rule regressed: "
                         "Compress-Archive + temp destination branch no longer fires")

    def test_lazagne_survives_rename_off_lazagne_path(self):
        # M13 US2 (#232) security review: the fixtures.json true_positive for
        # this rule has "lazagne" in its own filename, so it alone cannot prove
        # the category+output path added specifically to survive a PyInstaller
        # rename (which loses OriginalFileName) still fires with NO name match
        # anywhere on the command line. One targeted assertion, not a fixture
        # entry — the schema only carries one true_positive per rule.
        det = load_rule(SIGMA_DIR / "proc_creation_win_lazagne_credential_harvest.yml")["detection"]
        renamed = {"Image": "C:\\Users\\Public\\svc42.exe", "CommandLine": "svc42.exe all -oN"}
        self.assertTrue(detection_matches(det, renamed),
                         "LaZagne rule regressed: renamed binary + category/output "
                         "pairing no longer fires without a name match")
        category_only = {"Image": "C:\\Users\\Public\\svc42.exe", "CommandLine": "svc42.exe all"}
        self.assertFalse(detection_matches(det, category_only),
                          "LaZagne rule over-fired: category keyword alone "
                          "(no output switch, no name match) should not match")

    def test_cmdkey_rule_also_catches_vaultcmd(self):
        # M13 US2 (#232) security review: cmdkey.exe and vaultcmd.exe are
        # separate signed binaries reading the same credential store — the
        # vaultcmd branch added to selection_img had zero fixture coverage,
        # so a future edit to that list could silently drop it with CI green.
        det = load_rule(SIGMA_DIR / "proc_creation_win_cmdkey_saved_creds_enum.yml")["detection"]
        vaultcmd = {"Image": "C:\\Windows\\System32\\vaultcmd.exe",
                    "CommandLine": 'vaultcmd /listcreds:"Windows Credentials" /all'}
        self.assertTrue(detection_matches(det, vaultcmd),
                         "cmdkey/vaultcmd rule regressed: vaultcmd.exe listcreds no longer fires")

    def test_self_signed_rule_catches_both_openssl_wordings(self):
        # M13 US5 (#228) security review round 2: the round-1 rule only
        # matched OpenSSL's older "self signed certificate" (space) wording;
        # a real local OpenSSL 3.0.13 `openssl verify` run against a freshly
        # generated self-signed cert produced the hyphenated "self-signed
        # certificate" instead - confirming this would have been a second,
        # value-level silent no-op on any current OpenSSL 3.x build. The
        # fixture's true_positive only exercises the hyphenated (now-real)
        # form; this proves the older form the OR-list also lists still
        # fires, so a future edit dropping it wouldn't pass CI unnoticed.
        det = load_rule(SIGMA_DIR / "net_zeek_ssl_self_signed_c2.yml")["detection"]
        older_wording = {"validation_status": "self signed certificate"}
        self.assertTrue(detection_matches(det, older_wording),
                         "self-signed rule regressed: older 'self signed' (space) wording no longer fires")

    def test_doh_rule_catches_quad9_subdomains_and_firefox_canary(self):
        # M13 US5 (#228) security review round 2: round-1 only matched the
        # literal `dns.quad9.net`, missing the dns9/dns10/dns11.quad9.net
        # hostnames browsers actually configure — widened to bare
        # `quad9.net`. Also added use-application-dns.net (Firefox's DoH
        # canary domain, the single strongest DoH-adoption signal on this
        # logsource). fixtures.json's true_positive only exercises
        # dns.google; this proves both round-2 additions actually fire.
        det = load_rule(SIGMA_DIR / "net_zeek_dns_doh_non_standard.yml")["detection"]
        quad9_variant = {"query": "dns11.quad9.net"}
        firefox_canary = {"query": "use-application-dns.net"}
        self.assertTrue(detection_matches(det, quad9_variant),
                         "DoH rule regressed: dns11.quad9.net no longer fires")
        self.assertTrue(detection_matches(det, firefox_canary),
                         "DoH rule regressed: Firefox's use-application-dns.net canary no longer fires")

    def test_sensitive_group_recon_catches_name_branch_independently(self):
        # M13 US6 (#229/#242) code review: round-1 used ObjectName|contains
        # for the RID suffixes ('-512' etc), which false-fires on any object
        # whose domain-identifier component happens to contain those digits
        # (a domain SID's sub-authority is shared by every object in the
        # domain). Fixed to ObjectName|endswith for the RID arm, split into
        # its own named block OR'd with the name-based arm. fixtures.json's
        # true_positive only exercises the RID branch after that fix; this
        # proves the name-based branch (selection_name) still fires too.
        det = load_rule(SIGMA_DIR / "auth_win_sensitive_group_recon.yml")["detection"]
        name_branch = {"EventID": 4661, "ObjectName": "CN=Domain Admins,CN=Users,DC=example,DC=com"}
        self.assertTrue(detection_matches(det, name_branch),
                         "sensitive-group-recon rule regressed: name-based branch no longer fires")

    def test_disabled_account_rule_catches_uppercase_substatus_and_status_field(self):
        # M13 US6 (#229/#242) security review: round-1 matched only the
        # uppercase SubStatus wording; Windows renders this NTSTATUS code in
        # lowercase in the raw EVTX EventData XML Winlogbeat actually parses,
        # so the fixture's true_positive was switched to the real lowercase
        # form. This proves the uppercase form (kept for robustness against
        # any source that does render it that way) and the separate Status
        # field (some logon paths report the code there instead of
        # SubStatus, per Microsoft's own single shared code table) both
        # still fire independently.
        det = load_rule(SIGMA_DIR / "auth_win_disabled_account_logon_attempt.yml")["detection"]
        uppercase_substatus = {"EventID": 4625, "SubStatus": "0xC0000072"}
        status_field = {"EventID": 4625, "Status": "0xc0000072"}
        self.assertTrue(detection_matches(det, uppercase_substatus),
                         "disabled-account rule regressed: uppercase SubStatus no longer fires")
        self.assertTrue(detection_matches(det, status_field),
                         "disabled-account rule regressed: Status-field branch no longer fires")


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

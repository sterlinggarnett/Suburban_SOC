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

    def test_match_one_evaluates_multi_valued_fields_per_element(self):
        # #351: code-reviewer finding - the rule-level test below
        # (test_dns_txt_answer_abuse_matches_multi_element_answers_array_
        # per_element) does NOT actually pin this regression. That rule's
        # pattern is `.*[a-zA-Z0-9+/=]{40,}.*` under re.fullmatch - the
        # wrapping `.*` on both sides absorbs a Python list's str() repr
        # punctuation (brackets/quotes/comma), so a single element 40+
        # chars long still satisfies a full-string match against the OLD,
        # buggy str(the_whole_list) blob too. Empirically confirmed: with
        # #351's _match_one list branch reverted, that rule-level test
        # stays green. Bare equality has no such blind spot - the target
        # must equal the ENTIRE stringified value under the old code, which
        # a multi-element list's repr never does, so it's what actually
        # discriminates old vs. new behavior. Calls _match_one() directly
        # (not detection_matches against a rule) so the proof doesn't
        # depend on any particular rule's regex shape happening to
        # discriminate.
        from sigma_eval import _match_one
        self.assertTrue(
            _match_one(["zzz-benign-first-element", "exact-target"], [], "exact-target", "field"),
            "a bare-equality target matching the SECOND element of a "
            "multi-value field did not fire - per-element OR semantics "
            "regressed, or a list value is being stringified as one blob "
            "again")
        self.assertFalse(
            _match_one(["zzz-benign-first", "zzz-benign-second"], [], "exact-target", "field"),
            "a bare-equality target matching NEITHER element incorrectly fired")

    def test_match_one_all_modifier_ands_across_targets_not_within_one_element(self):
        # #351: security-auditor finding - a naive
        # any(_match_one(v, mods, target, field) for v in value) gets `all`
        # backwards for a multi-valued field. Elasticsearch compiles
        # `field|all: [a, b]` to `field:a AND field:b`, two clauses
        # independently evaluated per-element against the SAME field - a
        # document matches if element X equals a and a DIFFERENT element Y
        # equals b, not requiring one element to equal both.
        # tester-debugger finding: an earlier draft of this test used
        # `contains`, whose substring search happens to ALSO pass against
        # the real (not hypothetical) pre-#351 code, which has no list
        # handling at all and stringifies the whole list to one blob (e.g.
        # str(["has-alpha-only", "has-bravo-only"])) - both target
        # substrings are trivially present somewhere in that blob
        # regardless of which element they came from, so `contains` cannot
        # tell old code from fixed code here. Bare equality (fullmatch)
        # doesn't have this blind spot: the pre-#351 whole-list-repr blob
        # (with its brackets/quotes/comma) can never exactly equal a bare
        # target word, so old code returns False for EVERY target
        # regardless of element content - empirically confirmed by
        # reverting the fix and re-running this test, which then failed as
        # expected. Only the fixed AND-over-targets(OR-over-elements) shape
        # can return True here.
        from sigma_eval import _match_one
        self.assertTrue(
            _match_one(["exact-alpha", "exact-bravo"], ["all"],
                       ["exact-alpha", "exact-bravo"], "field"),
            "an `all` target list against a multi-valued field, where each "
            "target is satisfied by a DIFFERENT element, did not fire - "
            "Elasticsearch ANDs across elements, not within one")
        # True negative: "exact-charlie" is satisfied by no element at all -
        # AND must still fail even though the other target is satisfied.
        self.assertFalse(
            _match_one(["exact-alpha", "exact-bravo"], ["all"],
                       ["exact-alpha", "exact-charlie"], "field"),
            "an `all` target list incorrectly fired when one target was "
            "satisfied by no element at all")

    def test_match_one_rejects_all_modifier_combined_with_cidr_or_numeric(self):
        # #386 (security-auditor, #351 review): the cidr branch always ORed
        # across a target list regardless of `all`, and the numeric
        # (gt/gte/lt/lte) branch accepted `all` syntactically without ever
        # validating it - both silently diverged from Sigma's documented
        # AND semantics instead of failing loudly the way this module
        # already does for other unsupported modifier combinations (re +
        # list target, text-field word-boundary). Zero rules in the corpus
        # combine `all` with `cidr` or a numeric modifier (confirmed via
        # corpus grep) - this pins the fail-loud contract for the day a
        # rule author tries it.
        from sigma_eval import _match_one
        with self.assertRaises(ValueError):
            _match_one("10.0.0.5", ["cidr", "all"], ["10.0.0.0/24", "192.168.0.0/24"], "field")
        with self.assertRaises(ValueError):
            _match_one("5", ["gt", "all"], "3", "field")
        # A single-network cidr scalar (no `all`) still fires normally -
        # proves the new guard is scoped to `all`, not a regression on the
        # existing cidr path.
        self.assertTrue(_match_one("10.0.0.5", ["cidr"], "10.0.0.0/24", "field"))
        # code-reviewer follow-up (live-confirmed): `re` had the identical
        # gap - issue #386's own title names it alongside cidr, but the
        # first draft of this fix only guarded cidr/numeric.
        with self.assertRaises(ValueError):
            _match_one("foo", ["re", "all"], "foo", "field")
        # security-auditor follow-up: the guard must also fire through the
        # #351 multi-valued-EVENT-FIELD recursion path (event value is a
        # list), not just the direct scalar-value call above - a future
        # refactor of that recursion could silently reintroduce the bypass
        # without failing CI if only the scalar path were pinned.
        with self.assertRaises(ValueError):
            _match_one(["10.0.0.5"], ["cidr", "all"], ["10.0.0.0/24", "192.168.0.0/24"], "field")
        with self.assertRaises(ValueError):
            _match_one(["5"], ["gt", "all"], "3", "field")
        # security-auditor follow-up: an empty TARGET list against a
        # multi-valued event field must not vacuously return True via
        # all([]) without ever reaching the guards above.
        with self.assertRaises(ValueError):
            _match_one(["10.0.0.5"], ["contains", "all"], [], "field")

    def test_match_one_rejects_dict_shaped_values_and_validates_empty_list_shape(self):
        # #351: security-auditor findings.
        # (1) A dict-shaped value (the ECS-canonical dns.answers.data/type/
        # ttl object shape, which this evaluator deliberately does not
        # model - see module docstring) must fail loudly, not silently
        # regex-match its Python repr the same way a bare list used to
        # before #351's own fix.
        # (2) An EMPTY list value must not bypass this evaluator's
        # rule-authoring shape guards (e.g. `re` with a list target) just
        # because any([]) is vacuously False - a malformed rule should
        # fail the same way regardless of what a specific event's field
        # happens to contain.
        from sigma_eval import _match_one
        with self.assertRaises(TypeError):
            _match_one({"data": "1.2.3.4", "type": "A", "ttl": 300}, [], "1.2.3.4", "field")
        with self.assertRaises(ValueError):
            _match_one([], ["re"], ["a", "b"], "field")
        self.assertFalse(_match_one([], [], "exact-target", "field"))

    def test_dns_txt_answer_abuse_matches_multi_element_answers_array_per_element(self):
        # #351: fixtures.json's true_positive/true_negatives all model
        # `answers` as a scalar (matching this repo's established fixture
        # convention) - Zeek's real `answers` field is a JSON array. This is
        # an end-to-end smoke check that the real rule evaluates a genuine
        # multi-element array without crashing and without an obvious
        # false positive/negative; the actual regression pin for the old
        # str(list)-stringify bug is test_match_one_evaluates_multi_valued_
        # fields_per_element above (code-reviewer finding: this rule's own
        # `.*pattern.*` shape doesn't discriminate old vs. new behavior).
        det = load_rule(SIGMA_DIR / "net_zeek_dns_txt_answer_abuse.yml")["detection"]
        true_positive = {
            "qtype_name": "TXT",
            "query": "1a2b3c.c2.example.com",
            "answers": [
                "v=spf1 include:_spf.example.com ~all",
                "dGhpcyBpcyBhIHNpbXVsYXRlZCBlbmNvZGVkIEMyIHBheWxvYWQgY2h1bmsgMTIzNDU=",
            ],
        }
        self.assertTrue(
            detection_matches(det, true_positive),
            "net_zeek_dns_txt_answer_abuse.yml: a multi-element answers array "
            "with one genuinely long encoded element did not fire - #351's fix "
            "regressed, or the array is being matched as a single stringified "
            "blob again")

        # True negative: every element benign - must NOT fire just because
        # the field is a (non-empty) list.
        true_negative = {
            "qtype_name": "TXT",
            "query": "example.com",
            "answers": [
                "v=spf1 include:_spf.example.com ~all",
                "v=spf1 include:_spf.google.com include:mailgun.org ip4:203.0.113.0/24 -all",
            ],
        }
        self.assertFalse(
            detection_matches(det, true_negative),
            "net_zeek_dns_txt_answer_abuse.yml: an all-benign multi-element "
            "answers array fired - false positive")

    def test_match_one_re_modifier_matches_dot_across_a_literal_newline(self):
        # #387: live-verified against a real running Elasticsearch (this
        # stack's pinned 9.3.2) that Lucene's compiled `regexp` query
        # matches `.` against a literal newline with no DOTALL-equivalent
        # toggle needed. The target string below is constructed so a
        # non-DOTALL Python `.*` genuinely cannot reach a full match: two
        # 60-char runs of the rule's own charset separated by one `\n` -
        # the class excludes `\n`, so the middle `{40,}` run can only ever
        # consume ONE side; the OTHER side's `.*` must cross the `\n` for
        # `re.fullmatch` to consume the entire 121-char string. Confirmed
        # empirically (live ES session, 2026-08-17): this exact string
        # matched the real compiled query for net_zeek_dns_txt_answer_
        # abuse.yml's `answers|re: '.*[a-zA-Z0-9+/=]{40,}.*'` pattern.
        from sigma_eval import _match_one
        newline_value = ("aB3" * 20) + "\n" + ("cD9" * 20)
        pattern = ".*[a-zA-Z0-9+/=]{40,}.*"
        self.assertTrue(
            _match_one(newline_value, ["re"], pattern, "answers"),
            "a newline-containing value that the real compiled Lucene regexp "
            "query matches did not fire here - re.fullmatch is missing "
            "re.DOTALL, or the DOTALL fix regressed")

    def test_match_one_wildcard_translated_modifiers_match_dot_across_a_literal_newline(self):
        # #387 follow-up (code-reviewer, live-verified): the identical
        # DOTALL gap the test above pins for the `re` modifier also exists
        # in cmp()'s contains/endswith/startswith/bare-equality paths, all
        # of which build `.`/`.*` from Sigma's OWN `*`/`?` wildcard syntax
        # via _sigma_wildcard_to_regex() (see that function's docstring) -
        # a target embedding an unescaped `?`/`*` has the same newline-
        # crossing question as the `re` modifier's pattern does. Live-
        # verified against the real dev-stack Elasticsearch (2026-08-17):
        # indexed {"msg": "ab\ncd"}, queried `msg:ab?cd` and `msg:ab*cd`
        # (the real compiled form of contains/endswith/startswith) - both
        # matched, confirming Lucene's wildcard automaton crosses an
        # embedded newline the same way the `regexp` query's `.` does.
        # Currently latent in the real corpus (no rule embeds a bare `*`/
        # `?` in a contains/endswith/startswith/bare-equality target -
        # confirmed via corpus grep), but the same bug class, same file,
        # same PR.
        from sigma_eval import _match_one
        newline_value = "ab\ncd"
        self.assertTrue(
            _match_one(newline_value, ["contains"], "ab?cd", "msg"),
            "contains: a newline-containing value that a `?`-wildcard "
            "target should match (per live ES confirmation) did not fire - "
            "the contains path is missing re.DOTALL, or the fix regressed")
        self.assertTrue(
            _match_one(newline_value, ["startswith"], "ab?cd", "msg"),
            "startswith: same newline-crossing gap, startswith path")
        self.assertTrue(
            _match_one(newline_value, ["endswith"], "b?cd", "msg"),
            "endswith: same newline-crossing gap, endswith path")
        self.assertTrue(
            _match_one(newline_value, [], "ab?cd", "msg"),
            "bare equality: same newline-crossing gap, fullmatch path")

    def test_zeek_executable_and_smtp_rules_catch_every_live_verified_mime_type(self):
        # #365: fixtures.json's true_positive for both rules only exercises
        # application/x-dosexec — the OTHER 3 mime_type branches
        # (application/x-executable, application/x-sharedlib,
        # text/x-shellscript, all live-verified against the real pinned
        # zeek/zeek image, see net_zeek_executable_download.yml's own
        # description) had zero fixture coverage. application/x-dosexec is
        # included here too (security-auditor finding) so this test is
        # self-contained proof of every live-verified value, not dependent
        # on fixtures.json separately covering the 4th. text/x-shellscript in
        # particular is the exact regression #365 was filed over — a typo
        # or an accidental revert back to application/x-shellscript (which
        # Zeek never actually produces) must fail this test, not silently
        # pass CI. One targeted assertion set per rule, not fixture entries
        # — the schema only carries one true_positive per rule.
        for rule_name, source in (
                ("net_zeek_executable_download.yml", "HTTP"),
                ("net_zeek_smtp_attachment_executable.yml", "SMTP")):
            det = load_rule(SIGMA_DIR / rule_name)["detection"]
            for mime_type in ("application/x-dosexec", "application/x-executable",
                              "application/x-sharedlib", "text/x-shellscript"):
                with self.subTest(rule=rule_name, mime_type=mime_type):
                    self.assertTrue(
                        detection_matches(det, {"source": source, "mime_type": mime_type}),
                        f"{rule_name} regressed: {mime_type!r} (source={source}) no longer fires")

    def test_zeek_executable_and_smtp_rules_share_the_exact_same_mime_type_list(self):
        # security-auditor finding: both rules' descriptions claim their
        # mime_type lists are "kept in sync", but nothing enforced that
        # claim — a future edit to only ONE of the two rules would drift
        # silently. Asserts the exact 4-element list, in the same order,
        # on both rules at once.
        expected = ['application/x-dosexec', 'application/x-executable',
                    'application/x-sharedlib', 'text/x-shellscript']
        for rule_name in ("net_zeek_executable_download.yml",
                          "net_zeek_smtp_attachment_executable.yml"):
            det = load_rule(SIGMA_DIR / rule_name)["detection"]
            self.assertEqual(
                det["selection_payload"]["mime_type"], expected,
                f"{rule_name}: mime_type list no longer matches its sibling rule's "
                f"list exactly — both rules' descriptions claim they're kept in sync")

    def test_zeek_executable_and_smtp_rules_no_longer_match_the_dead_mime_types(self):
        # #365: application/x-msdownload, application/vnd.microsoft.
        # portable-executable, application/x-elf, application/x-pie-
        # executable, application/x-sh, and application/x-shellscript were
        # REMOVED — confirmed live against the real pinned zeek/zeek image
        # that Zeek's own (non-libmagic) file-analysis signature engine
        # never produces any of them, so they provided zero real detection
        # value. Pins the removal so a well-meaning "restore the fuller
        # list" edit doesn't silently reintroduce dead entries.
        # code-reviewer finding: application/x-shellscript (the ORIGINAL
        # wrong string #365 was filed over — distinct from application/x-sh
        # above) was missing from this tuple, empirically confirmed by
        # reintroducing it and observing this test still pass. It's the
        # single most likely typo a future edit would reintroduce (it
        # differs from the correct text/x-shellscript only by the type
        # prefix), so it belongs here more than any other entry.
        for rule_name, source in (
                ("net_zeek_executable_download.yml", "HTTP"),
                ("net_zeek_smtp_attachment_executable.yml", "SMTP")):
            det = load_rule(SIGMA_DIR / rule_name)["detection"]
            for dead_mime_type in ("application/x-msdownload",
                                   "application/vnd.microsoft.portable-executable",
                                   "application/x-elf", "application/x-pie-executable",
                                   "application/x-sh", "application/x-shellscript"):
                with self.subTest(rule=rule_name, mime_type=dead_mime_type):
                    self.assertFalse(
                        detection_matches(det, {"source": source, "mime_type": dead_mime_type}),
                        f"{rule_name}: {dead_mime_type!r} was removed as confirmed-dead on "
                        f"real Zeek (#365) — if it's back, either it was reintroduced by "
                        f"accident, or new evidence means this test itself needs updating")


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

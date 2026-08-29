#!/usr/bin/env python3
"""
#299: Sigma's `description:` field renders VERBATIM in the Kibana Detection
Engine alert flyout — it's analyst-facing runtime text, not a code comment.
Four Linux auth rules (the issue also names a 5th, "sibling" rule,
auth_linux_ssh_root_login.yml — see below for why it's excluded here) each
carried 15-30 lines explaining Elasticsearch `query_string`/analyzer
internals (why `contains` is unsafe against a `text`-mapped field, why bare
equality was split into separate selectors, etc.) inline in their
description — reasoning that matters for a rule author or reviewer, not an
analyst triaging a 3am alert.

The shared analyzer rationale now lives in ONE place —
tests/detections/sigma_eval.py's `_TEXT_MAPPED_FIELDS` comment — and each
affected rule's description carries a short pointer back to it instead.
Genuinely operational content stays in each rule's own description: scope
limits an analyst needs at triage time, AND a rule-specific verified fact
about that rule's own selector value (round-2 code review: the general
rule in sigma_eval.py doesn't by itself guarantee any specific value stays
a single token — only that IF it does, bare equality matches it safely).

auth_linux_ssh_root_login.yml was inspected and left completely unchanged:
it selects on keyword-mapped ECS fields (user.name, event.outcome,
event.module), not `message`, so it never carried the ES-analyzer/
query_string rationale this issue is about. It carries its own short
comment (not part of the parsed `description:` field) recording this, so
a future reader can tell it was excluded deliberately, not missed.

Round-2 security review finding: the first version of this test file only
banned specific jargon STRINGS from reappearing inline — it would have
stayed green even if the underlying REASONING (not just those exact words)
had been deleted rather than migrated to sigma_eval.py, which is exactly
what happened to two pieces of content in round 1. This version also pins
that the specific migrated reasoning is actually present in sigma_eval.py,
not just that the rule descriptions are shorter.

Static text assertions against the real rule files, no live
Kibana/Elasticsearch needed.

Run:  pytest tests/detections/test_rule_description_hygiene.py
"""

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "rules" / "sigma"
SIGMA_EVAL = (ROOT / "tests" / "detections" / "sigma_eval.py").read_text(encoding="utf-8")

# The 4 rules actually touched by #299 — auth_linux_ssh_root_login.yml is
# deliberately NOT here; see module docstring for why.
AFFECTED_RULES = [
    "auth_linux_ssh_authorized_keys_change.yml",
    "auth_linux_sudo_privilege_escalation.yml",
    "auth_linux_invalid_user_ssh_attempt.yml",
    "auth_linux_su_session_opened.yml",
]

# Substrings from the OLD, verbose analyzer-internals paragraphs — none of
# these should survive in a rule's description after the #299 fix. Not an
# exhaustive ban on the underlying words (a rule could legitimately need to
# mention "query" in an operational sense some day) but specific enough to
# catch a regression back to the old inline-explanation shape. Deliberately
# excludes "sigma convert", which the authorized_keys rule's own restored
# rule-specific note (see below) legitimately still uses.
ANALYZER_JARGON = [
    "query_string",
    "unanalyzed",
    "tokenized",
]


def _description(rule_filename: str) -> str:
    data = yaml.safe_load((SIGMA_DIR / rule_filename).read_text(encoding="utf-8"))
    return data["description"]


def _raw_text(rule_filename: str) -> str:
    return (SIGMA_DIR / rule_filename).read_text(encoding="utf-8")


class SharedAnalyzerRationaleLivesInOnePlaceTests(unittest.TestCase):
    def test_sigma_eval_comment_is_the_canonical_explanation(self):
        # The shared rationale must actually be present and self-contained
        # in sigma_eval.py — this is the ONE place it should now live.
        self.assertIn("query_string", SIGMA_EVAL)
        self.assertIn("tokenized", SIGMA_EVAL)
        self.assertIn("_TEXT_MAPPED_FIELDS", SIGMA_EVAL)

    def test_sigma_eval_comment_covers_the_multi_token_combining_caveat(self):
        # Round-2 security review: this specific reasoning (why 2+ ANDed
        # single-token selectors are used instead of one multi-word bare-
        # equality value) was deleted from auth_linux_sudo_privilege_
        # escalation.yml and auth_linux_invalid_user_ssh_attempt.yml in
        # round 1 without being migrated anywhere — their pointers claimed
        # sigma_eval.py explained this when it didn't. It must actually be
        # here now, not just asserted-by-absence in the rule files.
        self.assertIn("query_string parser", SIGMA_EVAL)
        self.assertIn("has NOT", SIGMA_EVAL)
        self.assertIn("multi-token bare-equality value", SIGMA_EVAL)

    def test_sigma_eval_comment_covers_the_token_non_collision_fact(self):
        # Round-2 security review: auth_linux_su_session_opened.yml's
        # pointer claims sigma_eval.py explains why 'su'/'sudo'/'sshd'
        # don't collide as tokens — that specific claim must actually be
        # backed by real text here, not just implied.
        self.assertIn("collide", SIGMA_EVAL)
        self.assertIn("su", SIGMA_EVAL)
        self.assertIn("sudo", SIGMA_EVAL)
        self.assertIn("sshd", SIGMA_EVAL)

    def test_sigma_eval_comment_no_longer_points_at_the_rule_descriptions(self):
        # Before #299, this comment pointed OUT to the rule descriptions
        # for "the full reasoning" — that direction is now backwards, since
        # the rules point back here instead. A stale forward-pointer would
        # send a reader in a circle.
        self.assertNotIn("for the full reasoning", SIGMA_EVAL)

    def test_sigma_eval_comment_correctly_excludes_root_login_from_its_scope(self):
        # Round-2 code review: the comment's first draft said "rules/sigma/
        # auth_linux_*.yml" — a glob that also matches auth_linux_ssh_
        # root_login.yml, which does NOT use bare equality against message
        # at all. The comment must name the affected rules precisely
        # enough not to imply it covers that one too.
        self.assertIn("auth_linux_ssh_root_login.yml", SIGMA_EVAL,
                      "the comment should explicitly note root_login is excluded")

    def test_each_affected_rule_points_back_to_the_shared_comment(self):
        for rule_filename in AFFECTED_RULES:
            description = _description(rule_filename)
            self.assertIn(
                "sigma_eval.py", description,
                f"{rule_filename}: description no longer points back to the "
                f"shared analyzer-rationale comment")
            self.assertIn(
                "_TEXT_MAPPED_FIELDS", description,
                f"{rule_filename}: pointer should name _TEXT_MAPPED_FIELDS "
                f"specifically, not just the file")

    def test_each_affected_rule_no_longer_repeats_analyzer_jargon_inline(self):
        for rule_filename in AFFECTED_RULES:
            description = _description(rule_filename)
            for jargon in ANALYZER_JARGON:
                self.assertNotIn(
                    jargon, description,
                    f"{rule_filename}: description still repeats ES-analyzer "
                    f"implementation detail ({jargon!r}) inline — this is "
                    f"exactly what #299 moved to sigma_eval.py's shared "
                    f"comment")

    def test_operational_scope_limit_disclosures_are_preserved(self):
        # #299 is explicit that genuinely operational content (an analyst
        # needs it at triage time) must NOT be removed, only the ES-internal
        # rationale. Spot-check the one rule with a real, significant,
        # analyst-relevant scope limit.
        description = _description("auth_linux_ssh_authorized_keys_change.yml")
        self.assertIn("auditd", description,
                      "the auditd/file-integrity-monitoring scope-limit "
                      "disclosure must survive the #299 trim")
        self.assertIn("invisible to this rule", description)

    def test_authorized_keys_rule_specific_token_verification_is_preserved(self):
        # Round-2 security review: this rule's OWN verified fact (that its
        # specific selector value, "authorized_keys", survives the
        # analyzer as one token) is genuinely rule-specific, not a general
        # property sigma_eval.py's shared comment states — it must stay in
        # THIS rule's own description, not just be implied by the general
        # rule.
        description = _description("auth_linux_ssh_authorized_keys_change.yml")
        self.assertIn("authorized_keys", description)
        self.assertIn("one token", description)
        self.assertIn("sigma convert", description,
                      "the specific verification method for THIS rule's "
                      "selector value should stay documented here")

    def test_su_session_disambiguation_reasoning_is_preserved(self):
        # This rule's description mixes operational reasoning (why 3 tokens,
        # not 2 -- to avoid colliding with ordinary sshd sessions) with
        # analyzer internals. Only the latter should have moved.
        description = _description("auth_linux_su_session_opened.yml")
        self.assertIn("sshd", description)
        self.assertIn("isolates su-specific sessions", description)

    def test_root_login_carries_a_traceable_exclusion_note(self):
        # Round-2 code review: without this, a future reader has no way to
        # tell whether root_login was missed by accident or excluded on
        # purpose. The note lives as a YAML comment above `description:`,
        # not inside the parsed field itself (it's a rule-authoring note,
        # not analyst-facing content) — read the raw file text for it.
        raw = _raw_text("auth_linux_ssh_root_login.yml")
        self.assertIn("#299", raw)
        self.assertIn("deliberately left unchanged", raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)

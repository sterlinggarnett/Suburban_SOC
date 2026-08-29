#!/usr/bin/env python3
"""
#299: Sigma's `description:` field renders VERBATIM in the Kibana Detection
Engine alert flyout — it's analyst-facing runtime text, not a code comment.
Five Linux auth rules each carried 15-30 lines explaining Elasticsearch
`query_string`/analyzer internals (why `contains` is unsafe against a
`text`-mapped field, why bare equality was split into separate selectors,
etc.) inline in their description — reasoning that matters for a rule
author or reviewer, not an analyst triaging a 3am alert.

The shared analyzer rationale now lives in ONE place —
tests/detections/sigma_eval.py's `_TEXT_MAPPED_FIELDS` comment — and each
affected rule's description carries a single-line pointer back to it
instead. Genuinely operational disclosures (scope limits, false-positive
reasoning) stay in the description itself, since an analyst does need
those at triage time.

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

# The 5 rules #299 names as carrying inline ES-analyzer internals.
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
# catch a regression back to the old inline-explanation shape.
ANALYZER_JARGON = [
    "query_string",
    "unanalyzed",
    "tokenized",
    "sigma convert",
]


def _description(rule_filename: str) -> str:
    data = yaml.safe_load((SIGMA_DIR / rule_filename).read_text(encoding="utf-8"))
    return data["description"]


class SharedAnalyzerRationaleLivesInOnePlaceTests(unittest.TestCase):
    def test_sigma_eval_comment_is_the_canonical_explanation(self):
        # The shared rationale must actually be present and self-contained
        # in sigma_eval.py — this is the ONE place it should now live.
        self.assertIn("query_string", SIGMA_EVAL)
        self.assertIn("tokenized", SIGMA_EVAL)
        self.assertIn("_TEXT_MAPPED_FIELDS", SIGMA_EVAL)

    def test_sigma_eval_comment_no_longer_points_at_the_rule_descriptions(self):
        # Before #299, this comment pointed OUT to the rule descriptions
        # for "the full reasoning" — that direction is now backwards, since
        # the rules point back here instead. A stale forward-pointer would
        # send a reader in a circle.
        self.assertNotIn("for the full reasoning", SIGMA_EVAL)

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

    def test_su_session_disambiguation_reasoning_is_preserved(self):
        # This rule's description mixes operational reasoning (why 3 tokens,
        # not 2 -- to avoid colliding with ordinary sshd sessions) with
        # analyzer internals. Only the latter should have moved.
        description = _description("auth_linux_su_session_opened.yml")
        self.assertIn("sshd", description)
        self.assertIn("isolates su-specific sessions", description)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/validate_emulation_map.py -- tactic-name validation tests (#437).

emulation_telemetry.map's tactic.name declarations previously validated
against nothing but presence: a PRESENT-but-WRONG value (typo, wrong
casing, a name that doesn't match ATT&CK's exact wording) passed silently,
and even absence was only a non-blocking WARN. This mirrors #430's
equivalent fix for configs/logstash.conf's tactic-name surface -- both now
resolve against build_attack_coverage.py's own TACTICS dict.

Run:  pytest tests/test_validate_emulation_map.py
"""

import unittest

import validate_emulation_map as vem


def _validated(text, check_sigma=False):
    """Parses+validates a synthetic map (no real repo root needed since
    check_sigma=False skips artifact-existence checks not under test here)."""
    ems, parse_errors = vem.parse_map(text)
    assert not parse_errors, parse_errors
    for e in ems:
        vem.derive_fields(e)
        vem.validate(e, root=vem.Path("."), check_sigma=check_sigma)
    return ems[0]


class TacticNameValidationTests(unittest.TestCase):
    def test_real_tactic_name_passes_clean(self):
        em = _validated(
            '[EMULATION: TEST]\n'
            'Execution_Vector : x\n'
            'Log_Source : x\n'
            'ECS_Mapping : threat.technique.id = "T1046" | threat.tactic.name = "Discovery"\n'
            'Target_Sigma_Rule : x\n'
            'NIST_CSF_Control : DE.CM-01\n'
        )
        self.assertEqual(em.cell("ecs-technique"), vem.Severity.OK)

    def test_typoed_tactic_name_is_error_not_silent(self):
        # Same class of typo #430 fixed on the configs/logstash.conf surface
        # -- a plausible authoring mistake, not a hypothetical. Checks the
        # specific "ecs-technique" cell, not overall status() -- the
        # fixture's Execution_Vector/Log_Source/Target_Sigma_Rule are
        # deliberately fake paths (irrelevant to this check), which would
        # already push status() to ERROR on their own and mask a bug here.
        em = _validated(
            '[EMULATION: TEST]\n'
            'Execution_Vector : x\n'
            'Log_Source : x\n'
            'ECS_Mapping : threat.technique.id = "T1046" | threat.tactic.name = "Discoveryy"\n'
            'Target_Sigma_Rule : x\n'
            'NIST_CSF_Control : DE.CM-01\n'
        )
        self.assertEqual(em.cell("ecs-technique"), vem.Severity.ERROR)
        messages = " ".join(f.message for f in em.findings if f.check == "ecs-technique")
        self.assertIn("Discoveryy", messages)

    def test_wrong_casing_tactic_name_is_error(self):
        # ATT&CK tactic names are exact strings ("Command and Control", not
        # "command and control") -- casing drift is the same silent-drop
        # class as a hyphen/spelling typo, not a cosmetic difference.
        em = _validated(
            '[EMULATION: TEST]\n'
            'Execution_Vector : x\n'
            'Log_Source : x\n'
            'ECS_Mapping : threat.technique.id = "T1046" | threat.tactic.name = "discovery"\n'
            'Target_Sigma_Rule : x\n'
            'NIST_CSF_Control : DE.CM-01\n'
        )
        self.assertEqual(em.cell("ecs-technique"), vem.Severity.ERROR)

    def test_missing_tactic_name_still_only_warns_not_errors(self):
        # Unchanged pre-existing behavior -- #437 is scoped to a PRESENT
        # but wrong value; absence stays a WARN (its own, separate,
        # non-blocking finding), not folded into this ERROR check.
        em = _validated(
            '[EMULATION: TEST]\n'
            'Execution_Vector : x\n'
            'Log_Source : x\n'
            'ECS_Mapping : threat.technique.id = "T1046"\n'
            'Target_Sigma_Rule : x\n'
            'NIST_CSF_Control : DE.CM-01\n'
        )
        self.assertEqual(em.cell("ecs-technique"), vem.Severity.WARN)

    def test_real_map_file_has_zero_tactic_name_errors(self):
        # Regression guard against the real corpus: every one of the ~25
        # real threat.tactic.name declarations must already resolve.
        map_path = vem.Path(__file__).resolve().parents[1] / "configs" / "detections" / "emulation_telemetry.map"
        text = map_path.read_text(encoding="utf-8")
        ems, parse_errors = vem.parse_map(text)
        self.assertFalse(parse_errors)
        root = map_path.resolve().parents[2]
        for e in ems:
            vem.derive_fields(e)
            vem.validate(e, root=root, check_sigma=False)
        tactic_errors = [
            f for e in ems for f in e.findings
            if f.check == "ecs-technique" and f.severity is vem.Severity.ERROR
            and "tactic.name" in f.message
        ]
        self.assertEqual(tactic_errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

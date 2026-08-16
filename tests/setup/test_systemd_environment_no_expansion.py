"""
Repo-wide guard against the systemd Environment=${VAR}-doesn't-expand bug
class (#357, following #259 for slo-metrics.service and #271 for
intel-refresh.service/threat-intel-compact.service).

systemd's `Environment=` directive does NOT perform ${VAR} expansion — per
systemd.exec(5), "$" has no special meaning there (only %-specifier
expansion is). `Environment=KEY=${OTHER_VAR}` resolves to the LITERAL
string "${OTHER_VAR}", not OTHER_VAR's value. This bug shape has now
recurred FOUR times across independent units in this repo (slo-metrics.service
originally, then intel-refresh.service and threat-intel-compact.service
found live in #271's session, then checkpoints-compact.service in #357) —
each fix so far pinned only its OWN unit's specific broken line, which is
why the bug kept recurring: nothing generalized the check.

This test scans every configs/systemd/*.service file for the bug SHAPE —
any non-comment line starting with `Environment=` that contains a literal
`$` character — rather than one specific historical string, so it also
catches evasions the per-unit string checks would miss (a quoted value,
`$VAR` without braces, systemd's multi-assignment form, or a future unit
this repo doesn't have yet).

Run:  python -m pytest tests/setup/test_systemd_environment_no_expansion.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIR = ROOT / "configs" / "systemd"

_ENVIRONMENT_LINE_RE = re.compile(r"^Environment=.*\$")


def _active_lines(text: str) -> list:
    return [line for line in text.splitlines() if not line.strip().startswith("#")]


def find_dollar_in_environment_lines(text: str) -> list:
    """Every active (non-comment) `Environment=...` line containing a "$" —
    the shape every known instance of this bug has taken, regardless of
    the specific variable name or quoting style."""
    return [line for line in _active_lines(text) if _ENVIRONMENT_LINE_RE.match(line.strip())]


class NoSystemdEnvironmentVariableExpansionTests(unittest.TestCase):
    def test_no_service_file_relies_on_environment_line_variable_expansion(self):
        service_files = sorted(SYSTEMD_DIR.glob("*.service"))
        self.assertGreater(len(service_files), 0, f"no *.service files found under {SYSTEMD_DIR}")
        offenders = {}
        for path in service_files:
            hits = find_dollar_in_environment_lines(path.read_text(encoding="utf-8"))
            if hits:
                offenders[path.name] = hits
        self.assertEqual(
            {}, offenders,
            f"{list(offenders)} have an active Environment= line containing '$' — "
            f"systemd does NOT expand ${{VAR}} references there (systemd.exec(5); "
            f"empirically confirmed via `systemd-run --user` this session). Extract the "
            f"real secret into a scratch EnvironmentFile= instead — see any of "
            f"slo-metrics.service / intel-refresh.service / threat-intel-compact.service / "
            f"checkpoints-compact.service for the established pattern.")


class FindDollarInEnvironmentLinesSelfTests(unittest.TestCase):
    """Mutation check on the checker itself — confirms it actually fails
    closed on each shape this bug has taken or could plausibly take, not
    just on the one literal string each individual unit's own test pins."""

    def test_detects_the_original_unbraced_form(self):
        self.assertEqual(
            ["Environment=ES_PASS=${SLO_METRICS_PASSWORD}"],
            find_dollar_in_environment_lines("Environment=ES_PASS=${SLO_METRICS_PASSWORD}"))

    def test_detects_a_quoted_value(self):
        self.assertEqual(
            ['Environment="ES_PASS=${SLO_METRICS_PASSWORD}"'],
            find_dollar_in_environment_lines('Environment="ES_PASS=${SLO_METRICS_PASSWORD}"'))

    def test_detects_a_reference_without_braces(self):
        self.assertEqual(
            ["Environment=ES_PASS=$SLO_METRICS_PASSWORD"],
            find_dollar_in_environment_lines("Environment=ES_PASS=$SLO_METRICS_PASSWORD"))

    def test_detects_a_multi_assignment_line(self):
        self.assertEqual(
            ["Environment=FOO=bar ES_PASS=${SLO_METRICS_PASSWORD}"],
            find_dollar_in_environment_lines("Environment=FOO=bar ES_PASS=${SLO_METRICS_PASSWORD}"))

    def test_ignores_a_literal_dollar_free_value(self):
        self.assertEqual([], find_dollar_in_environment_lines("Environment=ES_HOST=https://localhost:9200"))

    def test_ignores_a_comment_even_if_it_quotes_the_broken_pattern(self):
        # The exact shape every per-unit test in this repo also has to
        # guard against: an explanatory comment quoting the broken pattern
        # verbatim as documentation of what NOT to do.
        text = "# Environment=ES_PASS=${SLO_METRICS_PASSWORD} is the bug to avoid"
        self.assertEqual([], find_dollar_in_environment_lines(text))

    def test_ignores_an_unrelated_line_containing_a_dollar_sign(self):
        # e.g. an ExecStart bash -c string referencing a real shell
        # variable (which DOES get expanded, by bash, not systemd) —
        # must not false-positive on lines that aren't Environment=.
        text = "ExecStart=/bin/bash -c 'echo $HOME'"
        self.assertEqual([], find_dollar_in_environment_lines(text))


if __name__ == "__main__":
    unittest.main()

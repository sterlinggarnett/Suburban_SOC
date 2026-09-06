#!/usr/bin/env python3
"""
#318 Findings 2 & 3: scripts/setup/docker-compose.yml's `provision` service
had no error handling (no `set -e`, every `curl` call redirected to
`/dev/null` with no status-code check, unlike the sibling `roles` service)
-- a failed role/user PUT (403, timeout, ...) still reached the final
`echo` and exited 0, so every downstream `service_completed_successfully`
gate (Kibana, `roles`, Logstash) proceeded as if provisioning had actually
succeeded. It also relied on YAML's "more-indented lines aren't folded"
rule to keep its `bash -c '...'` body as a multi-line script under a
`command: >` FOLDED scalar -- a future re-indentation to match the
`bash -c '` line's own indentation would silently fold the whole script
onto one line, with the first `#` comment then commenting out everything
after it (bash -n and pytest would both still pass; the container would
just do nothing).

Fixed by switching to `entrypoint: ["/bin/bash", "-c"]` + `command: |`
(literal block scalar, matching `cert_pkcs8`/`roles` in this same file --
removes the folding dependency), `set -euo pipefail`, and a shared `put()`
helper that captures the HTTP status via `-w '%{http_code}'` and exits 1
loudly on anything outside 200/201.

This test extracts the REAL script bash will receive at container launch
(reading docker-compose.yml's `provision` command directly and manually
collapsing Compose's `$$` escape to `$` -- `docker compose config` does
NOT perform that collapse in its own displayed/JSON output; empirically
confirmed against a real Docker Compose v5 install this session, and
distinct from Compose's `${VAR}` substitution, which config DOES apply),
then actually executes it under bash with `curl`/`sleep` replaced by fakes
on PATH -- no live Elasticsearch needed, matching this directory's
existing convention of static/dry-run checks over live-cluster ones.

Run:  python -m pytest tests/setup/test_provision_error_handling.py
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "scripts" / "setup" / "docker-compose.yml"
COMPOSE_TEXT = COMPOSE_PATH.read_text(encoding="utf-8")

_FAKE_CURL = """#!/bin/bash
# Fake curl for tests/setup/test_provision_error_handling.py's dry-run:
# logs every call, fakes the two "wait until ready" polls, and fakes
# put()'s "-w '%{http_code}'" calls -- returning FAIL_PATH's status from
# $PROVISION_TEST_FAIL_STATUS (default 200) and every other path's as 200.
# If PROVISION_TEST_CURL_CRASH_PATH matches, curl itself exits non-zero
# with no stdout/outfile write at all -- simulating a connection/TLS-level
# failure (as opposed to an HTTP-level one) for put()'s `if ! resp=...` path.
echo "CURL_CALLED: $*" >> "$PROVISION_TEST_CURL_LOG"
args="$*"
if [[ -n "$PROVISION_TEST_CURL_CRASH_PATH" && "$args" == *"$PROVISION_TEST_CURL_CRASH_PATH"* ]]; then
    exit 7
fi
if [[ "$args" == *"-X POST"* && "$args" == *"_password"* ]]; then
    echo '{}'
    exit 0
fi
if [[ "$args" != *"-X"* ]]; then
    echo "missing authentication credentials"
    exit 0
fi
if [[ "$args" == *"-w"*"%{http_code}"* ]]; then
    prev=""; outfile=""
    for a in "$@"; do
        if [[ "$prev" == "-o" ]]; then outfile="$a"; fi
        prev="$a"
    done
    if [[ -n "$PROVISION_TEST_FAIL_PATH" && "$args" == *"$PROVISION_TEST_FAIL_PATH"* ]]; then
        echo -n '{"error":"forced failure"}' > "$outfile"
        echo -n "${PROVISION_TEST_FAIL_STATUS:-403}"
    else
        echo -n '{}' > "$outfile"
        echo -n "200"
    fi
    exit 0
fi
echo '{}'
exit 0
"""

_FAKE_SLEEP = "#!/bin/bash\nexit 0\n"

# Every credential the real `provision` service's environment: block
# populates -- required ones get a real value, optional ones get the
# empty string Compose's own ${VAR:-} default guarantees when unset.
_REQUIRED_ENV = {"ELASTIC_PASSWORD": "e", "KIBANA_PASSWORD": "k", "LOGSTASH_PASSWORD": "l"}
_OPTIONAL_ENV = {
    "SOC_AGENT_KIBANA_PASSWORD": "", "SLO_METRICS_PASSWORD": "",
    # #555: the self-health lane's own least-privilege identity, so
    # stack-health.service does not authenticate as the elastic superuser.
    "SOC_HEALTH_PASSWORD": "",
    "BROKER_AUDIT_PASSWORD": "", "AGENT_CHECKPOINTS_PASSWORD": "",
    "AGENT_CHECKPOINTS_COMPACTOR_PASSWORD": "", "INTEL_WRITER_PASSWORD": "",
    "THREAT_INTEL_COMPACTOR_PASSWORD": "", "LOGSTASH_ENRICH_PASSWORD": "",
}


def _provision_service_block(compose_text: str) -> str:
    start = compose_text.index("\n  provision:\n")
    end = compose_text.index("\n  elasticsearch:\n", start)
    return compose_text[start:end]


def _real_provision_script() -> str:
    """The actual script bash executes at container launch: Compose's own
    ${VAR} substitution has already run by the time docker-compose.yml
    reaches this repo (nothing to do there for a script body with no bare
    ${VAR} secret refs left, per #306/#318), so the only remaining step is
    manually collapsing every $$ to a literal $ -- the one thing `docker
    compose config` does NOT show in its own output (verified empirically:
    a minimal `$$(echo hi)` compose file round-trips through `docker
    compose config --format json` as literal `$$(echo hi)`, unchanged)."""
    service = _provision_service_block(COMPOSE_TEXT)
    command_start = service.index("\n    command:\n      - |\n")
    command_block = service[command_start:]
    # Strip the `command:\n  - |\n` header and this block's fixed 8-space
    # script indentation (matching cert_pkcs8/roles' identical convention).
    lines = command_block.splitlines()[3:]  # drop "", "command:", "  - |"
    script_lines = [line[8:] if line.startswith(" " * 8) else line for line in lines]
    script = "\n".join(script_lines)
    return script.replace("$$", "$")


class ProvisionEnvFixtureMatchesComposeTests(unittest.TestCase):
    """_REQUIRED_ENV/_OPTIONAL_ENV above are a hand-maintained mirror of the
    provision service's own `environment:` block, and the two silently drifted
    when #555 added SOC_HEALTH_PASSWORD: every test in this file then ran
    provision.sh under `set -u` without that variable, and the resulting
    "unbound variable" failure looked like a bug in the compose change rather
    than a stale fixture. Derive the real list and compare, so the next
    credential added to provision fails HERE with a clear message."""

    def test_fixture_covers_every_variable_provision_actually_receives(self):
        service = _provision_service_block(COMPOSE_TEXT)
        names = set()
        collecting = False
        for line in service.splitlines():
            if line.strip() == "environment:":
                collecting = True
                continue
            if not collecting:
                continue
            stripped = line.strip()
            if not stripped.startswith("- "):
                break
            names.add(stripped[2:].split("=", 1)[0].strip())
        self.assertTrue(names, "could not parse provision's environment: block")
        missing = names - set(_REQUIRED_ENV) - set(_OPTIONAL_ENV)
        self.assertEqual(
            set(), missing,
            f"provision's environment: block passes {sorted(missing)}, which this "
            "file's _REQUIRED_ENV/_OPTIONAL_ENV fixture does not supply — every "
            "test here would run provision.sh under `set -u` without it"
        )


class ProvisionUsesLiteralBlockScalarTests(unittest.TestCase):
    """#318 Finding 3: locks in the entrypoint/literal-block-scalar shape,
    so a future edit can't silently reintroduce the folded-scalar footgun
    (a `command: >` + `bash -c '...'` whose re-indentation would fold the
    whole script onto one line behind its first `#` comment)."""

    def test_provision_uses_entrypoint_and_literal_block_scalar(self):
        service = _provision_service_block(COMPOSE_TEXT)
        self.assertIn(
            '    entrypoint: ["/bin/bash", "-c"]', service,
            "provision must use entrypoint: [\"/bin/bash\", \"-c\"] + "
            "command: | (matching cert_pkcs8/roles), not a folded "
            "`command: >` scalar (#318)"
        )
        self.assertIn(
            "\n    command:\n      - |\n", service,
            "provision must use a literal block scalar (command: | ) for "
            "its script body, not a folded scalar (#318)"
        )
        self.assertNotIn("command: >", service)
        self.assertNotIn("bash -c '", service)


class ProvisionErrorHandlingTests(unittest.TestCase):
    """#318 Finding 2: a role/user PUT that comes back non-2xx must abort
    the whole provisioning run loudly (exit 1, stderr naming what failed),
    never silently reach 'Provisioning complete.' and exit 0."""

    def setUp(self):
        self.script = _real_provision_script()
        self.assertIn("set -euo pipefail", self.script,
                      "provision's script must fail fast (#318)")
        self.tmpdir = tempfile.mkdtemp()
        fake_curl = Path(self.tmpdir) / "curl"
        fake_curl.write_text(_FAKE_CURL)
        fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IEXEC)
        fake_sleep = Path(self.tmpdir) / "sleep"
        fake_sleep.write_text(_FAKE_SLEEP)
        fake_sleep.chmod(fake_sleep.stat().st_mode | stat.S_IEXEC)
        self.curl_log = Path(self.tmpdir) / "curl.log"
        self.script_path = Path(self.tmpdir) / "provision.sh"
        self.script_path.write_text(self.script)

    def _run(self, extra_env=None):
        env = dict(os.environ)
        env["PATH"] = f"{self.tmpdir}:{env['PATH']}"
        env["PROVISION_TEST_CURL_LOG"] = str(self.curl_log)
        env.update(_REQUIRED_ENV)
        env.update(_OPTIONAL_ENV)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(self.script_path)],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_happy_path_with_every_optional_account_exits_0(self):
        env = dict(_OPTIONAL_ENV)
        for key in env:
            env[key] = "set"  # non-empty -> every "if [ x$VAR != x ]" runs
        result = self._run(extra_env=env)
        self.assertEqual(
            0, result.returncode,
            f"expected exit 0, got {result.returncode}\nstderr: {result.stderr}"
        )
        self.assertIn("Provisioning complete.", result.stdout)

    def test_blank_optional_passwords_skip_cleanly_and_exit_0(self):
        # Every optional "if [ x$VAR != x ]" guard should skip its block --
        # this must not trip `set -u` (nounset), since every one of these
        # vars is guaranteed non-unset (empty-string default) by
        # provision's own environment: block.
        result = self._run()
        self.assertEqual(
            0, result.returncode,
            f"expected exit 0, got {result.returncode}\nstderr: {result.stderr}"
        )
        self.assertIn("Provisioning complete.", result.stdout)
        self.assertNotIn("unbound variable", result.stderr)

    def test_a_failed_put_aborts_loudly_instead_of_exiting_0(self):
        # This is the #318 regression itself: pre-fix, a 403 here would
        # have been silently discarded (`> /dev/null`, no status check)
        # and the script would still reach "Provisioning complete." / exit 0.
        result = self._run(extra_env={
            "PROVISION_TEST_FAIL_PATH": "/_security/role/soc_audit_appender",
            "PROVISION_TEST_FAIL_STATUS": "403",
        })
        self.assertEqual(
            1, result.returncode,
            f"a failed PUT must abort with a non-zero exit; got "
            f"{result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        self.assertIn("soc_audit_appender", result.stderr)
        self.assertIn("403", result.stderr)
        self.assertNotIn("Provisioning complete.", result.stdout)

    def test_a_curl_process_failure_aborts_loudly_too(self):
        # Security-auditor review of #318: a bare `resp=$(curl ...)` under
        # `set -e` would abort on curl's own raw exit code (connection
        # refused, TLS error -- no HTTP response ever produced) with none
        # of put()'s ERROR/path attribution. put() now wraps the assignment
        # in `if ! resp=...` so this failure mode gets the same loud,
        # attributed diagnostic as an HTTP-level failure.
        result = self._run(extra_env={
            "PROVISION_TEST_CURL_CRASH_PATH": "/_security/role/soc_audit_appender",
        })
        self.assertEqual(
            1, result.returncode,
            f"a curl process failure must abort with a non-zero exit; got "
            f"{result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        self.assertIn("soc_audit_appender", result.stderr)
        self.assertIn(
            "curl could not complete the request", result.stderr,
            "expected put()'s curl-process-failure diagnostic, not just a "
            "bare non-zero exit"
        )
        self.assertNotIn("Provisioning complete.", result.stdout)


if __name__ == "__main__":
    unittest.main()

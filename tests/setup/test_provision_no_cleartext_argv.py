#!/usr/bin/env python3
"""
#306 Finding 1: scripts/setup/docker-compose.yml's `provision` service uses
single-`$` Compose-time interpolation for most of its `-u "elastic:${...}"`/
`-d "{...${...}...}"` password references. Compose splices a single-`$`
`${VAR}` into the container's `command:` text BEFORE the container ever
starts, so the cleartext password is readable via `docker inspect`,
`docker ps --no-trunc`, or `/proc/<pid>/cmdline` for as long as that
one-shot container persists after exit (#303: possibly indefinitely). The
correct pattern, already established elsewhere in this same file
(AGENT_CHECKPOINTS_PASSWORD/INTEL_WRITER_PASSWORD before this fix), is
`$${VAR}` (double-dollar): Compose does NOT interpolate that at parse time,
so bash expands it at container runtime from the service's own
`environment:` block instead — never touching argv.

This test scans every *_PASSWORD/*_SECRET variable name declared in
scripts/setup/.env.example (not a hardcoded snapshot — #306's own issue
text already went stale once, missing BROKER_AUDIT_PASSWORD/
SLO_METRICS_PASSWORD's own "if" guard lines even after their PUT bodies
were fixed) against the `provision` service's command block specifically —
NOT the `setup` service, which deliberately keeps ELASTIC_PASSWORD/
KIBANA_PASSWORD/LOGSTASH_PASSWORD as single-`$` Compose-time references by
its own documented design (see that service's own comment, docker-
compose.yml lines ~124-134) and is out of scope for #306.

A second, equally important check: converting a reference to `$$` only
works if that variable is ALSO declared in the service's own
`environment:` block (that's what bash expands it FROM at runtime) — a
code-reviewer catch during #306's own review found `BROKER_AUDIT_PASSWORD`
had been converted to `$$` without ever being added there, so it silently
resolved to empty and the entire hive_mind_broker provisioning branch
stopped running. `test_every_escaped_secret_has_an_environment_entry`
guards against that specific regression shape.

Run:  python -m pytest tests/setup/test_provision_no_cleartext_argv.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "scripts" / "setup" / "docker-compose.yml"
ENV_EXAMPLE_PATH = ROOT / "scripts" / "setup" / ".env.example"
COMPOSE_TEXT = COMPOSE_PATH.read_text(encoding="utf-8")
ENV_EXAMPLE_TEXT = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

_SECRET_VAR_RE = re.compile(r"^([A-Z_]+_(?:PASSWORD|SECRET))=", re.MULTILINE)
_ENV_ENTRY_RE = re.compile(r"^\s*-\s*([A-Z_]+)=", re.MULTILINE)


def _secret_var_names(env_example_text: str) -> list:
    """Every *_PASSWORD/*_SECRET variable name .env.example declares --
    derived dynamically so a future credential is covered automatically."""
    return sorted(set(_SECRET_VAR_RE.findall(env_example_text)))


def _provision_service_block(compose_text: str) -> str:
    """The whole `provision:` service, from its own key up to the next
    top-level (2-space-indented) service key."""
    start = compose_text.index("\n  provision:\n")
    end = compose_text.index("\n  elasticsearch:\n", start)
    return compose_text[start:end]


def _provision_command_block(compose_text: str) -> str:
    """Isolate just the `provision:` service's `command:` bash script --
    NOT its `environment:` block above, where `PASSWORD=${PASSWORD}`-style
    single-`$` references are the correct, unavoidable Compose mechanism
    for passing a host .env value into the container's own environment in
    the first place (every already-`$$`-escaped secret, e.g.
    AGENT_CHECKPOINTS_PASSWORD, has an identical line there) -- and not
    `setup`'s own deliberately-single-`$` ELASTIC_PASSWORD/KIBANA_PASSWORD/
    LOGSTASH_PASSWORD lines either."""
    service = _provision_service_block(compose_text)
    command_start = service.index("\n    command: >\n")
    return service[command_start:]


def _provision_environment_names(compose_text: str) -> set:
    """Every variable name provision's own `environment:` block declares --
    what `$$`-escaped references in its command block actually expand
    from at container runtime."""
    service = _provision_service_block(compose_text)
    env_start = service.index("\n    environment:\n")
    env_end = service.index("\n    volumes:\n", env_start)
    return set(_ENV_ENTRY_RE.findall(service[env_start:env_end]))


def find_unescaped_secret_refs(command_block: str, var_names: list) -> list:
    """Every bare (single-`$`) `${VAR}` reference to a known secret variable
    -- a `$${VAR}` (already-escaped, runtime-shell) reference is NOT a
    match, via the negative lookbehind."""
    hits = []
    for name in var_names:
        hits.extend(re.findall(rf"(?<!\$)\$\{{{name}\}}", command_block))
    return hits


def find_escaped_secret_refs(command_block: str, var_names: list) -> set:
    """Every `$$`-escaped ($${VAR}) reference to a known secret variable."""
    return {name for name in var_names if f"$${{{name}}}" in command_block}


class ProvisionNoCleartextArgvTests(unittest.TestCase):
    def test_no_secret_var_is_compose_time_interpolated_in_provision(self):
        var_names = _secret_var_names(ENV_EXAMPLE_TEXT)
        self.assertGreater(len(var_names), 0,
                            f"no *_PASSWORD/*_SECRET vars found in {ENV_EXAMPLE_PATH}")
        block = _provision_command_block(COMPOSE_TEXT)
        offenders = find_unescaped_secret_refs(block, var_names)
        self.assertEqual(
            [], offenders,
            f"provision service still Compose-time-interpolates: {offenders} -- "
            f"use $${{VAR}} (double-dollar) instead, so bash expands it at "
            f"container runtime from the service's own environment: block "
            f"rather than Compose splicing the cleartext value into the "
            f"container's command text before it ever starts (#306)"
        )

    def test_every_escaped_secret_has_an_environment_entry(self):
        # A $$-escaped reference only actually works if bash has something
        # to expand it FROM at runtime -- that's provision's own
        # environment: block, populated from Compose-time interpolation
        # there (the one place single-$ is correct and required). Without
        # a matching entry, $${VAR} silently expands to empty rather than
        # failing loudly, which is exactly the regression this test exists
        # to catch (found live during #306's own review: BROKER_AUDIT_
        # PASSWORD was converted to $$ without being added here first,
        # silently disabling all hive_mind_broker provisioning).
        var_names = _secret_var_names(ENV_EXAMPLE_TEXT)
        block = _provision_command_block(COMPOSE_TEXT)
        escaped = find_escaped_secret_refs(block, var_names)
        declared = _provision_environment_names(COMPOSE_TEXT)
        missing = sorted(escaped - declared)
        self.assertEqual(
            [], missing,
            f"provision's command block references $${{VAR}} for {missing}, "
            f"but provision's own environment: block declares no such "
            f"variable -- it will silently expand to empty at runtime"
        )


if __name__ == "__main__":
    unittest.main()

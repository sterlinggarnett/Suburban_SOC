#!/usr/bin/env python3
"""
#359: `elasticsearch`'s host port mapping in scripts/setup/docker-compose.yml
used to publish on `0.0.0.0:9200` (any host interface) rather than being
restricted to the localhost the rest of this file assumes (SOP docs, health
checks, and every in-repo `curl` example all target `localhost:9200`). With
Elasticsearch's own auth as the only remaining control at that point, this
made every credential-based safeguard on the cluster reachable from anywhere
on the LAN rather than only from the host itself. Fixed by binding to
`127.0.0.1`, matching the pattern the `hive_mind_broker` and AI-agent
services already use for their own published ports.

Pure stdlib, static text/regex assertion against the real compose file — no
live Docker/Elasticsearch, matching this directory's existing convention
(see tests/pipeline/test_mac_correlation.py).

Run:  python tests/setup/test_docker_compose_ports.py  (or: pytest tests/setup)
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKER_COMPOSE = (ROOT / "scripts" / "setup" / "docker-compose.yml").read_text(encoding="utf-8")


def _service_block(text: str, service: str) -> str:
    """Isolate one top-level service's body under `services:`, so a match
    can't be accidentally satisfied by an unrelated service further down."""
    match = re.search(rf"^  {re.escape(service)}:\n(?:^ {{4}}.*\n|^\n)*", text, re.MULTILINE)
    assert match, f"could not locate a '{service}:' service block in docker-compose.yml"
    return match.group(0)


class ElasticsearchPortBindingTests(unittest.TestCase):
    def test_elasticsearch_port_is_bound_to_localhost_only(self):
        block = _service_block(DOCKER_COMPOSE, "elasticsearch")
        self.assertIn(
            '"127.0.0.1:${ES_PORT:-9200}:9200"',
            block,
            "elasticsearch's published port must bind to 127.0.0.1 only (#359 "
            "regression: a bare '${ES_PORT:-9200}:9200' publishes on all host "
            "interfaces, reachable from anywhere on the LAN with ES auth as the "
            "only remaining control)",
        )
        self.assertNotRegex(
            block,
            r"\n\s*-\s*\$\{ES_PORT:-9200\}:9200\s*\n",
            "elasticsearch's ports entry must not be an unqualified "
            "'${ES_PORT:-9200}:9200' mapping (binds 0.0.0.0, not localhost)",
        )


if __name__ == "__main__":
    unittest.main()

"""
suricata_rules_eval.py — pure parsing/checking logic for the Suricata
detection-as-code CI lane (#445, M23 Stage 2).

Split out from test_suricata_rules.py the same way sigma_eval.py is split
from test_sigma_detections.py: the checking logic is exercised both against
the real rules/suricata/ tree AND against synthetic, in-memory rule text in
meta-tests that prove the checker itself catches a broken/duplicate-SID
rule — the issue's own "done when" acceptance criterion — without needing
#446's still-outstanding 100-rule content to exist first.

SID range registry
-------------------
Suricata/Snort convention reserves low SIDs (roughly 1-3,999,999) for
vendor rulesets (Emerging Threats, Sourcefire/VRT, etc.); anything a site
authors locally is expected to pick a distinct, unclaimed range so a
future `suricata-update` pull of a real vendor ruleset can never collide
with it. This repo has claimed two:

  - 9000001-9000100: the #446 university starter set (10 categories,
    SIDs 9000001-9000100 exactly, fixed by the source ruleset itself).
  - 9500001-9599999: genuinely local, non-vendor-derived signatures
    (rules/suricata/local.rules) — a distinct range per that file's own
    header, wide enough for organic growth without touching #446's block.

A SID outside both ranges is rejected: either a real vendor SID got
copy-pasted in by mistake (unreviewed, uncredited, and liable to collide
with a real `suricata-update` pull), or it's a typo in a hand-assigned
local SID.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SID_RANGES: tuple[tuple[str, int, int], ...] = (
    ("M23 Stage 3 university starter set (#446)", 9_000_001, 9_000_100),
    ("Suburban-SOC local site-authored rules (local.rules)", 9_500_001, 9_599_999),
)

# A rule line, optionally commented-out (disabled) with a single leading
# '#'. Matches Suricata's one-line rule syntax: an action keyword, then
# anything, then a `(...)` options block containing `sid:<digits>;`.
# Deliberately anchored on the action keyword so a prose comment that
# merely mentions "sid:" in passing (e.g. explaining the convention) is
# never mistaken for a rule.
_ACTIONS = ("alert", "drop", "pass", "reject", "log")
_RULE_LINE_RE = re.compile(
    r"^(?P<hash>#\s*)?(?P<action>" + "|".join(_ACTIONS) + r")\b.*\(.*\bsid:\s*(?P<sid>\d+)\s*;.*\)\s*$"
)


@dataclass(frozen=True)
class RuleRecord:
    file: Path
    line_no: int
    raw: str
    sid: int
    enabled: bool

    @property
    def uncommented(self) -> str:
        """The rule text with a single leading disable-comment stripped,
        i.e. what would run if this rule were enabled. Used to replay a
        currently-disabled rule against its own fixture during authoring,
        before flipping it on."""
        text = self.raw.strip()
        if text.startswith("#"):
            text = text[1:].lstrip()
        return text


def parse_rule_line(path: Path, line_no: int, raw: str) -> RuleRecord | None:
    m = _RULE_LINE_RE.match(raw.strip())
    if not m:
        return None
    return RuleRecord(
        file=path,
        line_no=line_no,
        raw=raw,
        sid=int(m.group("sid")),
        enabled=m.group("hash") is None,
    )


def load_records(rule_files: list[Path]) -> list[RuleRecord]:
    records: list[RuleRecord] = []
    for path in rule_files:
        for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            rec = parse_rule_line(path, line_no, raw)
            if rec is not None:
                records.append(rec)
    return records


def find_duplicate_sids(records: list[RuleRecord]) -> dict[int, list[RuleRecord]]:
    by_sid: dict[int, list[RuleRecord]] = {}
    for rec in records:
        by_sid.setdefault(rec.sid, []).append(rec)
    return {sid: recs for sid, recs in by_sid.items() if len(recs) > 1}


def sid_range_name(sid: int) -> str | None:
    for name, lo, hi in SID_RANGES:
        if lo <= sid <= hi:
            return name
    return None


def find_out_of_range(records: list[RuleRecord]) -> list[RuleRecord]:
    return [rec for rec in records if sid_range_name(rec.sid) is None]


def fixture_paths(fixtures_dir: Path, sid: int) -> tuple[Path, Path]:
    """(true-positive pcap, true-negative pcap) conventional paths for a
    SID. The TN path is optional — its absence is not itself a promotion-
    gate failure, only a weaker guarantee (no cross-check that the rule
    stays quiet on benign traffic)."""
    return fixtures_dir / f"{sid}_tp.pcap", fixtures_dir / f"{sid}_tn.pcap"


class ReplayError(RuntimeError):
    pass


def replay_pcap(rule_text: str, pcap_path: Path, suricata_bin: str, timeout: int = 60) -> set[int]:
    """Real `suricata -r <pcap>` replay of exactly one rule (Suricata's
    detection engine, not a reimplementation of its match semantics — the
    same "genuine local verification" posture test_suricata_config.py's
    ConfigSyntaxTests established for `-T`). Returns the set of
    signature_id values that fired an `alert` event in eve.json.

    Uses `-S <tmpfile>` to add exactly this one rule on top of the real
    repo config (configs/suricata/suricata.yaml) rather than `-c` a
    stripped-down config, so a fixture is validated against the same
    HOME_NET/output settings production actually runs with.
    """
    root = Path(__file__).resolve().parents[2]
    config_path = root / "configs" / "suricata" / "suricata.yaml"
    if not pcap_path.is_file():
        raise ReplayError(f"pcap fixture not found: {pcap_path}")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        rule_file = tmp_path / "replay.rules"
        rule_file.write_text(rule_text.strip() + "\n", encoding="utf-8")
        log_dir = tmp_path / "log"
        log_dir.mkdir()
        result = subprocess.run(
            [
                suricata_bin,
                "-r", str(pcap_path),
                "-k", "none",
                "-S", str(rule_file),
                "-l", str(log_dir),
                "-c", str(config_path),
                "--runmode=single",
            ],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            raise ReplayError(
                f"suricata -r failed (exit {result.returncode}):\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        eve_path = log_dir / "eve.json"
        fired: set[int] = set()
        if eve_path.is_file():
            for line in eve_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("event_type") == "alert":
                    fired.add(rec["alert"]["signature_id"])
        return fired


def promotion_gate_violations(
    records: list[RuleRecord], fixtures_dir: Path, suricata_bin: str | None
) -> list[str]:
    """Mirrors test_sigma_detections.py's test_promotion_gate: an enabled
    rule with no passing pcap fixture is a violation — it "cannot enter
    the enabled set" (#445's own wording). SKIPS (returns no violations
    for that rule, doesn't silently pass it as "fine") the actual replay
    check when no suricata binary is available, since a missing-fixture
    violation is still real and worth reporting even with no binary to
    replay against.
    """
    violations: list[str] = []
    for rec in records:
        if not rec.enabled:
            continue
        tp_path, tn_path = fixture_paths(fixtures_dir, rec.sid)
        if not tp_path.is_file():
            violations.append(
                f"{rec.file.name}:{rec.line_no} sid={rec.sid} is enabled but has no "
                f"true-positive pcap fixture at {tp_path} — cannot enter the enabled set"
            )
            continue
        if suricata_bin is None:
            continue
        fired = replay_pcap(rec.uncommented, tp_path, suricata_bin)
        if rec.sid not in fired:
            violations.append(
                f"{rec.file.name}:{rec.line_no} sid={rec.sid}: true-positive fixture "
                f"{tp_path.name} did NOT fire the rule"
            )
        if tn_path.is_file():
            fired_tn = replay_pcap(rec.uncommented, tn_path, suricata_bin)
            if rec.sid in fired_tn:
                violations.append(
                    f"{rec.file.name}:{rec.line_no} sid={rec.sid}: true-negative fixture "
                    f"{tn_path.name} fired the rule — false positive"
                )
    return violations

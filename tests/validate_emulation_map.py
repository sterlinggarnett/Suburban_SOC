#!/usr/bin/env python3
# =============================================================================
#  Suburban-SOC :: Emulation-to-Telemetry Mapping Validator
# -----------------------------------------------------------------------------
#  Parses an emulation_telemetry.map matrix and verifies that the purple-team
#  loop it describes is actually wired up:
#
#    1. Every referenced artifact exists  (execution vector, log-source config,
#       Sigma rule) -- catches silent drift when files are renamed/moved.
#    2. The ECS technique declared in the map matches the ATT&CK tags carried
#       by the Sigma rule you point at -- catches "this emulation can never
#       fire that detection" mismatches.
#    3. The telemetry domain (Zeek/Filebeat/network vs. Windows) is sane for
#       the rule's own logsource -- catches platform mismatches.
#
#  Emits a coverage matrix to the console plus optional JSON / Markdown so it
#  can feed a dashboard or AUDIT_REPORT.md. Exits non-zero on broken mappings,
#  so it drops straight into a pre-commit hook or CI step.
#
#  Stdlib-only. PyYAML is used if present for Sigma parsing, otherwise it falls
#  back to a regex scan -- no hard dependency.
# =============================================================================

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# #437: reuse build_attack_coverage.py's own TACTICS dict as the single
# canonical set of ATT&CK tactic display names, rather than an independently
# maintained copy that could silently drift from it (or from the third
# tactic-name surface, Sigma rule tags -- see build_attack_coverage.py's own
# #430/#281 comments for the identical drift risk on those two).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "setup"))
from build_attack_coverage import TACTICS as _ATTACK_TACTICS  # noqa: E402

VALID_TACTIC_NAMES = {name for name, _ta_code in _ATTACK_TACTICS.values()}

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

REQUIRED_KEYS = [
    "Execution_Vector",
    "Log_Source",
    "ECS_Mapping",
    "Target_Sigma_Rule",
    "NIST_CSF_Control",
]


class Severity(str, Enum):
    OK = "OK"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


_RANK = {Severity.OK: 0, Severity.INFO: 1, Severity.WARN: 2, Severity.ERROR: 3}


@dataclass
class Finding:
    severity: Severity
    check: str
    message: str


@dataclass
class Emulation:
    name: str
    line: int
    raw: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    checks_run: set = field(default_factory=set)
    # derived
    technique_id: Optional[str] = None
    tactic: Optional[str] = None
    exec_vector: Optional[str] = None
    log_config: Optional[str] = None
    log_file: Optional[str] = None
    sigma_rule: Optional[str] = None
    nist_control: Optional[str] = None
    sigma_techniques: set = field(default_factory=set)

    def add(self, severity: Severity, check: str, message: str) -> None:
        self.checks_run.add(check)
        if severity is not Severity.OK:
            self.findings.append(Finding(severity, check, message))

    def cell(self, check: str) -> Optional[Severity]:
        """Worst severity recorded for a check, or OK if it ran clean, or None."""
        if check not in self.checks_run:
            return None
        worst = Severity.OK
        for f in self.findings:
            if f.check == check and _RANK[f.severity] > _RANK[worst]:
                worst = f.severity
        return worst

    def status(self) -> Severity:
        worst = Severity.OK
        for f in self.findings:
            if _RANK[f.severity] > _RANK[worst]:
                worst = f.severity
        return worst


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

SECTION_RE = re.compile(r"^\[\s*EMULATION\s*:\s*(?P<name>.+?)\s*\]\s*$", re.IGNORECASE)
TECH_ID_RE = re.compile(r'technique\.id\s*=\s*"?(?P<id>T\d{4}(?:\.\d{3})?)"?', re.IGNORECASE)
TACTIC_RE = re.compile(r'tactic\.name\s*=\s*"?(?P<t>[^"|]+)"?', re.IGNORECASE)
NIST_RE = re.compile(r"\b(?P<code>[A-Z]{2}\.[A-Z]{2}-\d{2})\b")
ATTACK_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def parse_map(text: str):
    """Return (emulations, parse_errors). parse_errors is a list of (line, msg)."""
    emulations: list[Emulation] = []
    errors: list[tuple[int, str]] = []
    current: Optional[Emulation] = None

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = SECTION_RE.match(stripped)
        if m:
            current = Emulation(name=m.group("name").strip(), line=lineno)
            emulations.append(current)
            continue

        if ":" not in stripped:
            errors.append((lineno, f"unrecognized line (not a section or key:value): {stripped!r}"))
            continue

        key, _, value = stripped.partition(":")
        key, value = key.strip(), value.strip()

        if current is None:
            errors.append((lineno, f"key {key!r} appears before any [EMULATION: ...] section"))
            continue

        if key in current.raw:
            current.add(Severity.WARN, "syntax", f"duplicate key {key!r} (line {lineno}); keeping first value")
        else:
            current.raw[key] = value

    return emulations, errors


def base_technique(tid: str) -> str:
    return tid.split(".")[0].upper()


def derive_fields(em: Emulation) -> None:
    em.exec_vector = em.raw.get("Execution_Vector")
    em.sigma_rule = em.raw.get("Target_Sigma_Rule")

    log_source = em.raw.get("Log_Source", "")
    if "->" in log_source:
        left, right = log_source.split("->", 1)
        em.log_config, em.log_file = left.strip(), right.strip()
    elif log_source:
        em.log_config = log_source.strip()

    ecs = em.raw.get("ECS_Mapping", "")
    tm = TECH_ID_RE.search(ecs)
    if tm:
        em.technique_id = tm.group("id").upper()
    ta = TACTIC_RE.search(ecs)
    if ta:
        em.tactic = ta.group("t").strip()

    nm = NIST_RE.search(em.raw.get("NIST_CSF_Control", ""))
    if nm:
        em.nist_control = nm.group("code")


# ---------------------------------------------------------------------------
# Sigma inspection
# ---------------------------------------------------------------------------

NETWORK_HINTS = (
    "zeek", "filebeat", "suricata", "network", "conn.log", "ssh.log",
    "notice.log", "files.log", "dns.log", "http.log", "nginx", "syslog",
)


def sigma_techniques(text: str) -> set:
    ids = set()
    try:
        import yaml  # optional
        data = yaml.safe_load(text)
        tags = data.get("tags") if isinstance(data, dict) else None
        for t in tags or []:
            mm = ATTACK_TAG_RE.search(str(t))
            if mm:
                ids.add(mm.group(1).upper())
    except Exception:
        pass
    # Regex fallback / supplement -- works even without PyYAML.
    for mm in ATTACK_TAG_RE.finditer(text):
        ids.add(mm.group(1).upper())
    return ids


def sigma_logsource(text: str) -> dict:
    res = {}
    for key in ("product", "category", "service"):
        km = re.search(rf"^\s*{key}\s*:\s*([^\s#]+)", text, re.MULTILINE)
        if km:
            res[key] = km.group(1).strip().strip("\"'")
    return res


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def resolve(root: Path, rel: Optional[str]) -> Optional[Path]:
    if not rel:
        return None
    p = Path(rel)
    return p if p.is_absolute() else (root / p)


def validate(em: Emulation, root: Path, check_sigma: bool) -> None:
    # Required keys
    for key in REQUIRED_KEYS:
        if key not in em.raw or not em.raw[key]:
            em.add(Severity.ERROR, "syntax", f"missing required field {key!r}")

    # Execution vector
    vec = resolve(root, em.exec_vector)
    if vec is None:
        em.add(Severity.ERROR, "exec-vector", "no Execution_Vector declared")
    elif not vec.exists():
        em.add(Severity.ERROR, "exec-vector", f"execution vector not found: {em.exec_vector}")
    else:
        em.add(Severity.OK, "exec-vector", "")
        if not os.access(vec, os.X_OK):
            em.add(Severity.WARN, "exec-vector", f"vector exists but is not executable (chmod +x {em.exec_vector})")

    # Log source config (left of '->'); the logfile on the right is runtime output.
    cfg = resolve(root, em.log_config)
    if cfg is None:
        em.add(Severity.ERROR, "log-source", "no Log_Source config declared")
    elif not cfg.exists():
        em.add(Severity.ERROR, "log-source", f"log-source config not found: {em.log_config}")
    else:
        em.add(Severity.OK, "log-source", "")

    # ECS technique
    if not em.technique_id:
        em.add(Severity.ERROR, "ecs-technique", "no valid ATT&CK technique id (expected technique.id = \"T####\")")
    else:
        em.add(Severity.OK, "ecs-technique", "")
    if not em.tactic:
        em.add(Severity.WARN, "ecs-technique", "no tactic.name declared in ECS_Mapping")
    elif em.tactic not in VALID_TACTIC_NAMES:
        # #437: a PRESENT-but-WRONG tactic.name (typo, wrong casing, a name
        # that doesn't match ATT&CK's exact wording) previously validated
        # clean -- only absence was checked (WARN, non-blocking; CI's own
        # gate only fails on ERROR-severity findings, so even a missing
        # name didn't fail the build). ERROR-severity, matching #430's
        # equivalent fix for the configs/logstash.conf tactic-name surface.
        em.add(
            Severity.ERROR, "ecs-technique",
            f"tactic.name {em.tactic!r} does not match any real ATT&CK tactic "
            f"({', '.join(sorted(VALID_TACTIC_NAMES))})",
        )

    # Sigma rule existence + cross-checks
    rule = resolve(root, em.sigma_rule)
    if rule is None:
        em.add(Severity.ERROR, "sigma-rule", "no Target_Sigma_Rule declared")
    elif not rule.exists():
        em.add(Severity.ERROR, "sigma-rule", f"Sigma rule not found: {em.sigma_rule}")
    else:
        em.add(Severity.OK, "sigma-rule", "")
        if check_sigma:
            text = rule.read_text(encoding="utf-8", errors="replace")
            em.sigma_techniques = sigma_techniques(text)

            # Technique-tag match: does the rule actually cover the declared technique?
            if em.technique_id:
                rule_bases = {base_technique(t) for t in em.sigma_techniques}
                hit = (
                    em.technique_id in em.sigma_techniques
                    or base_technique(em.technique_id) in rule_bases
                )
                if not em.sigma_techniques:
                    em.add(Severity.WARN, "tag-match", "Sigma rule carries no attack.* tags to verify against")
                elif hit:
                    em.add(Severity.OK, "tag-match", "")
                else:
                    tags = ", ".join(sorted(em.sigma_techniques)) or "none"
                    em.add(
                        Severity.WARN, "tag-match",
                        f"declared {em.technique_id} not covered by rule tags ({tags}) "
                        f"-- this emulation will not exercise this detection",
                    )

            # Platform sanity: network telemetry pointed at a Windows-only rule.
            ls = sigma_logsource(text)
            domain = f"{em.log_config or ''} {em.log_file or ''}".lower()
            if ls.get("product", "").lower() == "windows" and any(h in domain for h in NETWORK_HINTS):
                em.add(
                    Severity.WARN, "tag-match",
                    "Log_Source looks like network/host telemetry but the rule's logsource "
                    "is product:windows -- likely platform mismatch",
                )

    # NIST control
    if not em.nist_control:
        em.add(Severity.WARN, "nist", "NIST_CSF_Control does not contain a code like 'DE.CM-01'")
    else:
        em.add(Severity.OK, "nist", "")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class C:
    def __init__(self, enabled: bool):
        self.e = enabled

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.e else s

    def red(self, s): return self._w("31", s)
    def yellow(self, s): return self._w("33", s)
    def green(self, s): return self._w("32", s)
    def dim(self, s): return self._w("2", s)
    def bold(self, s): return self._w("1", s)


GLYPH = {Severity.OK: "OK", Severity.INFO: "i", Severity.WARN: "!!", Severity.ERROR: "XX", None: "--"}


def glyph(col: C, sev: Optional[Severity]) -> str:
    g = GLYPH[sev]
    if sev is Severity.OK:
        return col.green(g)
    if sev is Severity.WARN:
        return col.yellow(g)
    if sev is Severity.ERROR:
        return col.red(g)
    return col.dim(g)


COLS = [
    ("VEC", "exec-vector"),
    ("LOG", "log-source"),
    ("SIG", "sigma-rule"),
    ("TAG", "tag-match"),
    ("CSF", "nist"),
]


def render_console(ems, col: C) -> None:
    name_w = max([len("SCENARIO")] + [len(e.name) for e in ems]) + 2
    tech_w = max([len("TECHNIQUE")] + [len(e.technique_id or "-") for e in ems]) + 2

    header = (
        col.bold(f"{'SCENARIO':<{name_w}}")
        + col.bold(f"{'TECHNIQUE':<{tech_w}}")
        + "".join(col.bold(f"{h:<5}") for h, _ in COLS)
        + col.bold("STATUS")
    )
    print(header)
    print(col.dim("-" * (name_w + tech_w + 5 * len(COLS) + 6)))

    for e in ems:
        row = f"{e.name:<{name_w}}" + f"{(e.technique_id or '-'):<{tech_w}}"
        for _, check in COLS:
            row += f"{glyph(col, e.cell(check)):<5}" if not col.e else glyph(col, e.cell(check)) + "   "
        st = e.status()
        st_txt = {Severity.OK: col.green("PASS"), Severity.INFO: col.green("PASS"),
                  Severity.WARN: col.yellow("WARN"), Severity.ERROR: col.red("FAIL")}[st]
        print(row + st_txt)

    # Findings detail
    problem = [e for e in ems if e.findings]
    if problem:
        print("\n" + col.bold("Findings"))
        for e in problem:
            print(col.bold(f"  [{e.name}]  (line {e.line})"))
            for f in sorted(e.findings, key=lambda x: -_RANK[x.severity]):
                tag = {Severity.ERROR: col.red("ERROR"), Severity.WARN: col.yellow("WARN"),
                       Severity.INFO: col.dim("INFO")}.get(f.severity, f.severity.value)
                print(f"    {tag:<6} {f.check:<13} {f.message}")


def render_summary(ems, col: C) -> tuple[int, int, int]:
    errors = sum(1 for e in ems if e.status() is Severity.ERROR)
    warns = sum(1 for e in ems if e.status() is Severity.WARN)
    ok = len(ems) - errors - warns
    print(
        "\n"
        + col.bold("Summary: ")
        + f"{len(ems)} scenarios  "
        + col.green(f"{ok} clean")
        + "  "
        + col.yellow(f"{warns} warn")
        + "  "
        + col.red(f"{errors} fail")
    )
    return ok, warns, errors


def to_dict(e: Emulation) -> dict:
    return {
        "scenario": e.name,
        "line": e.line,
        "technique_id": e.technique_id,
        "tactic": e.tactic,
        "execution_vector": e.exec_vector,
        "log_config": e.log_config,
        "log_file": e.log_file,
        "sigma_rule": e.sigma_rule,
        "sigma_techniques": sorted(e.sigma_techniques),
        "nist_control": e.nist_control,
        "status": e.status().value,
        "findings": [{"severity": f.severity.value, "check": f.check, "message": f.message} for f in e.findings],
    }


def render_markdown(ems) -> str:
    lines = ["# Emulation -> Telemetry Coverage Matrix", ""]
    lines.append("| Scenario | Technique | Vector | LogSrc | Sigma | TagMatch | CSF | Status |")
    lines.append("|---|---|:--:|:--:|:--:|:--:|:--:|:--:|")
    md = {Severity.OK: "OK", Severity.WARN: "WARN", Severity.ERROR: "FAIL", Severity.INFO: "ok", None: "-"}
    for e in ems:
        cells = [md[e.cell(c)] for _, c in COLS]
        lines.append(
            f"| {e.name} | {e.technique_id or '-'} | "
            + " | ".join(cells)
            + f" | {md[e.status()] if e.status() is not Severity.OK else 'PASS'} |"
        )
    problem = [e for e in ems if e.findings]
    if problem:
        lines += ["", "## Findings", ""]
        for e in problem:
            lines.append(f"**{e.name}** (line {e.line})")
            for f in sorted(e.findings, key=lambda x: -_RANK[x.severity]):
                lines.append(f"- `{f.severity.value}` *{f.check}* — {f.message}")
            lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Validate a Suburban-SOC emulation-to-telemetry mapping matrix.",
    )
    ap.add_argument("-m", "--map", default="configs/detections/emulation_telemetry.map",
                    help="path to the .map file (default: %(default)s)")
    ap.add_argument("-r", "--root", default=".",
                    help="repo root for resolving relative artifact paths (default: cwd)")
    ap.add_argument("--json", metavar="PATH", help="write structured results as JSON")
    ap.add_argument("--markdown", metavar="PATH", help="write a Markdown coverage matrix")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures (exit 1)")
    ap.add_argument("--no-sigma", action="store_true", help="skip Sigma rule cross-checks")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = ap.parse_args(argv)

    color = C(sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR"))
    root = Path(args.root).resolve()
    map_path = Path(args.map)
    if not map_path.is_absolute():
        map_path = root / map_path

    try:
        text = map_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(color.red(f"error: cannot read map file: {exc}"), file=sys.stderr)
        return 2

    ems, parse_errors = parse_map(text)
    for lineno, msg in parse_errors:
        print(color.red(f"parse error (line {lineno}): {msg}"), file=sys.stderr)

    if not ems:
        print(color.red("error: no [EMULATION: ...] sections found"), file=sys.stderr)
        return 2

    for e in ems:
        derive_fields(e)
        validate(e, root, check_sigma=not args.no_sigma)

    print(color.bold(f"Mapping matrix: {map_path}"))
    print(color.dim(f"Resolving artifacts against: {root}\n"))
    render_console(ems, color)
    ok, warns, errors = render_summary(ems, color)

    if args.json:
        payload = {
            "map": str(map_path),
            "root": str(root),
            "summary": {"scenarios": len(ems), "clean": ok, "warn": warns, "fail": errors},
            "emulations": [to_dict(e) for e in ems],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(color.dim(f"\nwrote JSON -> {args.json}"))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown(ems), encoding="utf-8")
        print(color.dim(f"wrote Markdown -> {args.markdown}"))

    if errors or parse_errors:
        return 1
    if warns and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

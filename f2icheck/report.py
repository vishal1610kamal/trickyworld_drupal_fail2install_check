"""Findings and how they are printed."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

# Ordered from worst to best. "critical" means a sign of compromise or an open, unfixed installer.
LEVELS = ("critical", "high", "medium", "info", "ok")


@dataclass
class Finding:
    check: str            # which check produced it: version, http, files, logs, state
    level: str            # one of LEVELS
    title: str            # one line
    detail: str = ""      # what was seen
    action: str = ""      # what to do about it
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError(f"unknown level {self.level!r}")


def worst(findings: list[Finding]) -> str:
    return min((f.level for f in findings), key=LEVELS.index, default="ok")


def exit_code(findings: list[Finding]) -> int:
    """0 when nothing needs action, 1 for high/medium items, 2 when something is critical."""
    level = worst(findings)
    return 2 if level == "critical" else 1 if level in ("high", "medium") else 0


def render_text(findings: list[Finding], evidence_lines: int = 8) -> str:
    out = []
    for f in sorted(findings, key=lambda f: LEVELS.index(f.level)):
        out.append(f"[{f.level.upper()}] {f.check}: {f.title}")
        if f.detail:
            out.append(f"    {f.detail}")
        for e in f.evidence[:evidence_lines] if evidence_lines else f.evidence:
            out.append(f"      - {e}")
        if evidence_lines and len(f.evidence) > evidence_lines:
            out.append(f"      … {len(f.evidence) - evidence_lines} more (use --evidence 0 to list all)")
        if f.action:
            out.append(f"    -> {f.action}")
    counts = {lv: sum(f.level == lv for f in findings) for lv in LEVELS}
    out.append("Summary: " + ", ".join(f"{n} {lv}" for lv, n in counts.items() if n) if findings else "Summary: nothing checked")
    return "\n".join(out)


def render_json(findings: list[Finding]) -> str:
    return json.dumps({"worst": worst(findings), "findings": [asdict(f) for f in findings]}, indent=2)

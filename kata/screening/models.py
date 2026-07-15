from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScreeningSeverity = Literal["reject", "review", "note"]
ScreeningStatus = Literal["pass", "reject", "review"]


@dataclass(frozen=True)
class ScreeningFinding:
    rule_id: str
    severity: ScreeningSeverity
    path: str | None
    line: int | None
    reason: str
    evidence: str


@dataclass(frozen=True)
class ScreeningDecision:
    status: ScreeningStatus
    reject_reasons: list[ScreeningFinding] = field(default_factory=list)
    review_reasons: list[ScreeningFinding] = field(default_factory=list)
    notes: list[ScreeningFinding] = field(default_factory=list)
    score: int = 0

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def rejection_messages(self) -> list[str]:
        return [finding.reason for finding in self.reject_reasons]


def dedupe_findings(
    findings: list[ScreeningFinding],
    *,
    by_reason: bool = True,
) -> list[ScreeningFinding]:
    """Drop duplicate findings, preserving order.

    ``by_reason=True`` keeps findings that differ only in ``reason`` (used by the
    static-rule pipeline); ``by_reason=False`` dedupes purely by rule/path/line
    (used by benchmark-replay detection, where the reason text varies per match).
    """
    deduped: list[ScreeningFinding] = []
    seen: set[tuple[object, ...]] = set()
    for finding in findings:
        key: tuple[object, ...] = (
            (finding.rule_id, finding.reason, finding.path, finding.line)
            if by_reason
            else (finding.rule_id, finding.path, finding.line)
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped

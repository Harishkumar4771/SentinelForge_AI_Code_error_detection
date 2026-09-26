"""
Finding Correlator (spec §12).

Receives findings from every agent and produces one unified, deduplicated,
evidence-merged view.

Example from the spec::

    Security Agent:  SQL Injection
    Testing Agent:   Malicious payload causes database error
    Bug Hunter:      User input reaches raw SQL
              |
              v
    Unified Finding: SQL Injection
                     Severity: CRITICAL   Confidence: 96%
                     Evidence: static analysis + dynamic test + dataflow

Two findings are the same issue when they share a fingerprint (category +
normalized title + file). Findings are additionally merged across files
when they share a fingerprint with no file, and near-duplicates on the same
line are folded together even when titled differently.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from app.core.logging_config import get_logger
from app.models.enums import AgentName, Certainty, FindingStatus, Severity
from app.schemas.finding import AgentFinding

logger = get_logger(__name__)

#: Agents that count as an independent confirmation.
TRUSTED_AGENTS = {AgentName.SECURITY.value, AgentName.TESTING.value, AgentName.BUG_HUNTER.value}


@dataclass
class CorrelationStats:
    input_count: int = 0
    output_count: int = 0
    duplicates_merged: int = 0
    cross_agent_confirmed: int = 0
    by_agent: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "input_count": self.input_count,
            "output_count": self.output_count,
            "duplicates_merged": self.duplicates_merged,
            "cross_agent_confirmed": self.cross_agent_confirmed,
            "by_agent": self.by_agent,
            "by_severity": self.by_severity,
        }


class FindingCorrelator:
    """Merges agent findings into a single deduplicated set."""

    def __init__(self, *, confidence_threshold: float | None = None):
        self.confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------
    def correlate(self, findings: list[AgentFinding]) -> tuple[list[AgentFinding], CorrelationStats]:
        stats = CorrelationStats(input_count=len(findings))
        for finding in findings:
            for agent in finding.detected_by or ["unknown"]:
                stats.by_agent[agent] = stats.by_agent.get(agent, 0) + 1

        if not findings:
            return [], stats

        # -- pass 1: exact fingerprint grouping -----------------------
        groups: dict[str, list[AgentFinding]] = defaultdict(list)
        for finding in findings:
            key = finding.fingerprint or finding.compute_fingerprint()
            groups[key].append(finding)

        merged: list[AgentFinding] = []
        for key, members in groups.items():
            members.sort(key=_authority)
            unified = members[0]
            for other in members[1:]:
                unified = unified.merge(other)
            unified.fingerprint = key
            unified.merged_from = [f.fingerprint for f in members if f.fingerprint != key]
            merged.append(unified)
            stats.duplicates_merged += len(members) - 1

        # -- pass 2: same-file, adjacent-line folding ------------------
        merged = self._fold_near_duplicates(merged, stats)

        # -- pass 3: score --------------------------------------------
        for finding in merged:
            self._score(finding, stats)

        threshold = self.confidence_threshold
        if threshold is None:
            from app.core.config import settings

            threshold = settings.finding_confidence_threshold

        kept = [f for f in merged if f.confidence >= threshold]
        dropped = len(merged) - len(kept)
        if dropped:
            logger.info(
                "correlator dropped %d finding(s) below confidence %.2f",
                dropped, threshold,
            )

        kept.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.file_path or ""))
        stats.output_count = len(kept)
        for finding in kept:
            stats.by_severity[finding.severity.value] = (
                stats.by_severity.get(finding.severity.value, 0) + 1
            )
        return kept, stats

    # ------------------------------------------------------------------
    @staticmethod
    def _fold_near_duplicates(
        findings: list[AgentFinding], stats: CorrelationStats
    ) -> list[AgentFinding]:
        """
        Merge findings on the same line with related categories.

        Different tools name the same defect differently -- "SQL Injection"
        versus "Hardcoded query construction". When they land on one line
        with a compatible category, they describe one issue.
        """
        buckets: dict[tuple[str, int], list[AgentFinding]] = defaultdict(list)
        result: list[AgentFinding] = []

        for finding in findings:
            if not finding.file_path or not finding.line_number:
                result.append(finding)
                continue
            key = (finding.file_path, finding.line_number)
            compatible: AgentFinding | None = None
            for existing in buckets[key]:
                if _categories_compatible(existing.category, finding.category):
                    compatible = existing
                    break
            if compatible is not None:
                unified = compatible.merge(finding)
                buckets[key] = [unified]
                stats.duplicates_merged += 1
            else:
                buckets[key] = [finding]
                result.append(finding)
        return result

    @staticmethod
    def _score(finding: AgentFinding, stats: CorrelationStats) -> None:
        """
        Recompute confidence from how many independent agents agreed.

        A single static analyser asserting a medium issue should not outrank
        three agents independently reporting a high issue.
        """
        agents = {a for a in finding.detected_by if a in TRUSTED_AGENTS}
        independent = len(agents)
        tools = len(finding.tools or [])

        base = finding.confidence
        if independent >= 2:
            base = min(1.0, base + 0.08 * (independent - 1))
            stats.cross_agent_confirmed += 1
        if tools >= 2:
            base = min(1.0, base + 0.05)
        if finding.evidence and len(finding.evidence) >= 3:
            base = min(1.0, base + 0.03)

        # A dynamic reproduction outranks pure static reasoning.
        if any("dynamic" in e.lower() or "test" in e.lower() or "reproduc" in e.lower()
               for e in finding.evidence):
            base = min(1.0, base + 0.10)
            if finding.certainty != Certainty.CONFIRMED:
                finding.certainty = Certainty.CONFIRMED

        # Severity and confidence are not the same axis: a critical
        # unconfirmed claim should not be presented as critical fact.
        if finding.certainty == Certainty.POTENTIAL:
            base *= 0.7
        elif finding.certainty == Certainty.PROBABLE:
            base *= 0.9

        finding.confidence = round(max(0.0, min(1.0, base)), 4)

    # ------------------------------------------------------------------
    def to_rows(self, findings: list[AgentFinding]) -> list[dict]:
        """Flatten correlated findings into database column dicts."""
        rows: list[dict] = []
        for finding in findings:
            rows.append(
                {
                    "fingerprint": finding.fingerprint,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "certainty": finding.certainty.value,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "line_end": finding.line_end,
                    "code_snippet": finding.code_snippet,
                    "evidence": finding.evidence,
                    "impact": finding.impact,
                    "recommendation": finding.recommendation,
                    "detected_by": finding.detected_by,
                    "tools": finding.tools,
                    "status": FindingStatus.OPEN.value,
                    "verified": False,
                    "is_bug": finding.is_bug,
                }
            )
        return rows


# ----------------------------------------------------------------------
_COMPATIBLE_GROUPS = (
    {"injection", "cross-site scripting", "ssrf", "server-side request forgery"},
    {"path traversal", "insecure input handling", "input validation"},
    {"hardcoded secret", "configuration", "authentication"},
    {"insecure cryptography", "authentication", "insecure random"},
    {"logic bug", "error handling", "input validation", "business logic"},
    {"insecure deserialization", "injection"},
)


def _categories_compatible(left: str, right: str) -> bool:
    left, right = left.lower().strip(), right.lower().strip()
    if left == right:
        return True
    for group in _COMPATIBLE_GROUPS:
        if left in group and right in group:
            return True
    return False


def _authority(finding: AgentFinding) -> tuple:
    """
    Ordering used to pick which finding survives a merge.

    Deterministic tool output outranks an LLM claim for the same issue, so a
    model's severity guess never overrides Semgrep's.
    """
    has_tool = bool(finding.tools) and finding.tools != ["ai"]
    return (
        0 if has_tool else 1,
        -finding.severity.rank,
        -finding.confidence,
        len(finding.evidence or []),
    )


__all__ = ["CorrelationStats", "FindingCorrelator"]

"""
The standard finding format (spec §8).

Every agent -- deterministic or LLM-backed -- must emit ``AgentFinding``
instances so that the correlator can merge them uniformly. Pydantic
validation is the enforcement point; malformed LLM output is rejected here
rather than silently trusted.
"""

from __future__ import annotations

import enum
import hashlib
import re
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import Certainty, FindingCategory, FindingStatus, Severity

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


#: Raw strings that tools and models emit, mapped onto canonical categories.
_CATEGORY_ALIASES = {
    "sqli": FindingCategory.INJECTION.value,
    "sql injection": FindingCategory.INJECTION.value,
    "nosql injection": FindingCategory.INJECTION.value,
    "command injection": FindingCategory.INJECTION.value,
    "code injection": FindingCategory.INJECTION.value,
    "xss": FindingCategory.XSS.value,
    "cross site scripting": FindingCategory.XSS.value,
    "cross-site scripting": FindingCategory.XSS.value,
    "directory traversal": FindingCategory.PATH_TRAVERSAL.value,
    "path traversal": FindingCategory.PATH_TRAVERSAL.value,
    "traversal": FindingCategory.PATH_TRAVERSAL.value,
    "secrets": FindingCategory.SECRETS.value,
    "secret": FindingCategory.SECRETS.value,
    "hardcoded secret": FindingCategory.SECRETS.value,
    "hardcoded credential": FindingCategory.SECRETS.value,
    "credential": FindingCategory.SECRETS.value,
    "crypto": FindingCategory.CRYPTOGRAPHY.value,
    "weak hash": FindingCategory.CRYPTOGRAPHY.value,
    "weak hashing": FindingCategory.CRYPTOGRAPHY.value,
    "insecure cryptography": FindingCategory.CRYPTOGRAPHY.value,
    "authn": FindingCategory.AUTHENTICATION.value,
    "auth": FindingCategory.AUTHENTICATION.value,
    "broken authentication": FindingCategory.AUTHENTICATION.value,
    "authz": FindingCategory.AUTHORIZATION.value,
    "broken authorization": FindingCategory.AUTHORIZATION.value,
    "missing authorization": FindingCategory.AUTHORIZATION.value,
    "deserialization": FindingCategory.INSECURE_DESERIALIZATION.value,
    "insecure deserialization": FindingCategory.INSECURE_DESERIALIZATION.value,
    "unsafe deserialization": FindingCategory.INSECURE_DESERIALIZATION.value,
    "ssrf": FindingCategory.SSRF.value,
    "server side request forgery": FindingCategory.SSRF.value,
    "server-side request forgery": FindingCategory.SSRF.value,
    "dangerous import": FindingCategory.IMPORT.value,
    "unsafe import": FindingCategory.IMPORT.value,
    "logic bug": FindingCategory.LOGIC.value,
    "logic": FindingCategory.LOGIC.value,
    "business logic": FindingCategory.LOGIC.value,
    "logic error": FindingCategory.LOGIC.value,
    "input validation": FindingCategory.VALIDATION.value,
    "validation": FindingCategory.VALIDATION.value,
    "improper input validation": FindingCategory.VALIDATION.value,
    "dependency risk": FindingCategory.DEPENDENCY.value,
    "vulnerable dependency": FindingCategory.DEPENDENCY.value,
    "outdated dependency": FindingCategory.DEPENDENCY.value,
    "error handling": FindingCategory.ERROR_HANDLING.value,
    "unhandled exception": FindingCategory.ERROR_HANDLING.value,
    "configuration": FindingCategory.CONFIGURATION.value,
    "misconfiguration": FindingCategory.CONFIGURATION.value,
    "other": FindingCategory.OTHER.value,
}

_KNOWN_CATEGORIES = {item.value for item in FindingCategory}


def _normalise_category(value: str) -> str:
    """
    Coerce any category spelling onto one of the canonical values.

    Analyzers, external tools and LLMs all supply categories in different
    shapes -- ``FindingCategory.INJECTION``, ``"sqli"``, ``"SQL Injection"``.
    Left alone, those strings reach the dashboard verbatim and break
    grouping, so every category is mapped through here at the schema
    boundary. Unknown categories collapse to ``Other`` rather than
    inventing a new one.
    """
    if value is None:
        return FindingCategory.OTHER.value
    if isinstance(value, enum.Enum):
        value = value.value
    text = str(value).strip()
    if not text:
        return FindingCategory.OTHER.value

    # "FindingCategory.INJECTION" -> "INJECTION"
    if "." in text:
        text = text.rsplit(".", 1)[-1].strip()

    if text in _KNOWN_CATEGORIES:
        return text
    lowered = re.sub(r"[_\s]+", " ", text).strip().lower()
    if lowered in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[lowered]
    # Try the underscored form of an alias key ("insecure_random" etc).
    underscored = re.sub(r"[\s]+", "_", lowered)
    if underscored in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[underscored]
    return FindingCategory.OTHER.value


#: CWE identifier -> canonical category. Used to infer a category for
#: analyzers that supply a CWE but no category of their own.
_CWE_CATEGORY = {
    # Injection and code execution
    "CWE-89": FindingCategory.INJECTION.value,
    "CWE-78": FindingCategory.INJECTION.value,
    "CWE-77": FindingCategory.INJECTION.value,
    "CWE-91": FindingCategory.INJECTION.value,
    "CWE-94": FindingCategory.INJECTION.value,
    "CWE-95": FindingCategory.INJECTION.value,
    "CWE-611": FindingCategory.INJECTION.value,
    "CWE-1336": FindingCategory.INJECTION.value,
    # Cross-site scripting
    "CWE-79": FindingCategory.XSS.value,
    "CWE-80": FindingCategory.XSS.value,
    "CWE-116": FindingCategory.XSS.value,
    # Path / file handling
    "CWE-22": FindingCategory.PATH_TRAVERSAL.value,
    "CWE-23": FindingCategory.PATH_TRAVERSAL.value,
    "CWE-36": FindingCategory.PATH_TRAVERSAL.value,
    "CWE-59": FindingCategory.PATH_TRAVERSAL.value,
    "CWE-73": FindingCategory.PATH_TRAVERSAL.value,
    # Secrets
    "CWE-798": FindingCategory.SECRETS.value,
    "CWE-259": FindingCategory.SECRETS.value,
    "CWE-321": FindingCategory.SECRETS.value,
    "CWE-522": FindingCategory.SECRETS.value,
    "CWE-547": FindingCategory.SECRETS.value,
    # Cryptography
    "CWE-326": FindingCategory.CRYPTOGRAPHY.value,
    "CWE-327": FindingCategory.CRYPTOGRAPHY.value,
    "CWE-328": FindingCategory.CRYPTOGRAPHY.value,
    "CWE-330": FindingCategory.CRYPTOGRAPHY.value,
    "CWE-759": FindingCategory.CRYPTOGRAPHY.value,
    "CWE-916": FindingCategory.CRYPTOGRAPHY.value,
    # Authentication
    "CWE-287": FindingCategory.AUTHENTICATION.value,
    "CWE-303": FindingCategory.AUTHENTICATION.value,
    "CWE-304": FindingCategory.AUTHENTICATION.value,
    "CWE-384": FindingCategory.AUTHENTICATION.value,
    "CWE-521": FindingCategory.AUTHENTICATION.value,
    "CWE-613": FindingCategory.AUTHENTICATION.value,
    # Authorization
    "CWE-285": FindingCategory.AUTHORIZATION.value,
    "CWE-441": FindingCategory.AUTHORIZATION.value,
    "CWE-862": FindingCategory.AUTHORIZATION.value,
    "CWE-863": FindingCategory.AUTHORIZATION.value,
    "CWE-639": FindingCategory.AUTHORIZATION.value,
    # Deserialization
    "CWE-502": FindingCategory.INSECURE_DESERIALIZATION.value,
    # SSRF
    "CWE-918": FindingCategory.SSRF.value,
    # Dangerous imports / dependencies
    "CWE-1104": FindingCategory.DEPENDENCY.value,
    "CWE-1035": FindingCategory.DEPENDENCY.value,
    "CWE-494": FindingCategory.DEPENDENCY.value,
    # Validation and error handling
    "CWE-20": FindingCategory.VALIDATION.value,
    "CWE-1286": FindingCategory.VALIDATION.value,
    "CWE-1285": FindingCategory.VALIDATION.value,
    "CWE-703": FindingCategory.ERROR_HANDLING.value,
    "CWE-390": FindingCategory.ERROR_HANDLING.value,
    "CWE-754": FindingCategory.ERROR_HANDLING.value,
    "CWE-755": FindingCategory.ERROR_HANDLING.value,
}


def _category_from_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return _CWE_CATEGORY.get(cwe.upper())


class AgentFinding(BaseModel):
    """Normalized finding produced by any agent.

    This is the contract between analyzers, agents, the correlator and the
    persistence layer.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    title: str = Field(min_length=3, max_length=500)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = 0.5
    category: str = Field(default=FindingCategory.OTHER.value)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    certainty: Certainty = Certainty.PROBABLE

    file_path: Optional[str] = None
    line_number: Optional[int] = Field(default=None, ge=0)
    line_end: Optional[int] = Field(default=None, ge=0)
    code_snippet: Optional[str] = None

    evidence: list[str] = Field(default_factory=list)
    impact: Optional[str] = None
    recommendation: Optional[str] = None

    detected_by: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    is_bug: bool = False
    verified: bool = False

    #: Workflow state, set by the orchestrator once verification has run.
    status: FindingStatus = FindingStatus.OPEN
    #: Raw sandbox verdict, kept separate from `verified` for the audit trail.
    verification_status: Optional[str] = None

    # Filled in by the correlator.
    fingerprint: Optional[str] = None
    merged_from: list[str] = Field(default_factory=list)

    @field_validator("category", mode="before")
    @classmethod
    def _clean_category(cls, value):
        return _normalise_category(str(value))

    @field_validator("cwe", mode="before")
    @classmethod
    def _clean_cwe(cls, value):
        if not value:
            return None
        match = re.search(r"CWE-(\d+)", str(value).upper())
        return f"CWE-{match.group(1)}" if match else None

    @field_validator("owasp", mode="before")
    @classmethod
    def _clean_owasp(cls, value):
        if not value:
            return None
        text = str(value).upper().replace(" ", "")
        match = re.search(r"A(\d{2}):(\d{4})", text)
        if match:
            return f"A{match.group(1)}:{match.group(2)}"
        match = re.search(r"TOP10:?A?(\d{2})", text)
        return f"A{match.group(1)}:2021" if match else None

    @field_validator("file_path", mode="before")
    @classmethod
    def _clean_path(cls, value):
        if not value:
            return None
        # Normalise separators and strip any leading "./".
        return str(value).replace("\\", "/").lstrip("./") or None

    @field_validator("evidence", "detected_by", "tools", mode="before")
    @classmethod
    def _coerce_list(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value if str(item).strip()]

    @model_validator(mode="after")
    def _post_validate(self) -> "AgentFinding":
        if self.line_end and self.line_number and self.line_end < self.line_number:
            self.line_end = self.line_number

        # A finding that carries a CWE but was left in the generic "Other"
        # bucket is classified from the CWE, so taint, Bandit and Semgrep
        # output all group with the same category as the rest.
        if self.category == FindingCategory.OTHER.value:
            inferred = _category_from_cwe(self.cwe)
            if inferred:
                object.__setattr__(self, "category", inferred)

        # Deterministic tools always assert confirmed evidence; an LLM claim
        # alone must never escalate past "probable" (spec §24).
        if self.tools and self.certainty == Certainty.POTENTIAL:
            object.__setattr__(self, "certainty", Certainty.PROBABLE)

        if self.fingerprint is None:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())
        return self

    def compute_fingerprint(self) -> str:
        """Stable identity used by the correlator to group duplicates.

        Keyed on (category, normalized title, file) so that the same issue
        reported by three agents collapses to one row.
        """
        title = re.sub(r"[^a-z0-9]+", " ", self.title.lower()).strip()
        title = re.sub(r"\s+", " ", title)
        # Drop trailing severity/confidence noise from tool-specific titles.
        title = re.sub(r"\b(possible|potential|likely|hardcoded|detected)\b", "", title).strip()
        file_key = (self.file_path or "").lower()
        raw = f"{self.category.lower()}|{title}|{file_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def merge(self, other: "AgentFinding") -> "AgentFinding":
        """Combine two findings believed to describe the same issue."""
        merged = self.model_copy(deep=True)
        merged.description = merged.description or other.description
        merged.impact = merged.impact or other.impact
        merged.recommendation = merged.recommendation or other.recommendation
        merged.code_snippet = merged.code_snippet or other.code_snippet
        merged.cwe = merged.cwe or other.cwe
        merged.owasp = merged.owasp or other.owasp

        if other.severity > merged.severity:
            merged.severity = other.severity
        merged.confidence = min(1.0, max(merged.confidence, other.confidence) + 0.05)

        for source in (*merged.evidence, *other.evidence):
            if source not in merged.evidence:
                merged.evidence.append(source)
        for agent in (*merged.detected_by, *other.detected_by):
            if agent not in merged.detected_by:
                merged.detected_by.append(agent)
        for tool in (*merged.tools, *other.tools):
            if tool not in merged.tools:
                merged.tools.append(tool)

        if merged.file_path is None:
            merged.file_path = other.file_path
            merged.line_number = other.line_number
        elif other.file_path == merged.file_path and merged.line_number is None:
            merged.line_number = other.line_number

        merged.is_bug = merged.is_bug or other.is_bug
        if merged.certainty != Certainty.CONFIRMED and other.certainty == Certainty.CONFIRMED:
            merged.certainty = Certainty.CONFIRMED
        return merged


class FindingBatch(BaseModel):
    """Container used when an agent returns many findings."""

    findings: list[AgentFinding] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):  # type: ignore[override]
        return iter(self.findings)


class CodeContext(BaseModel):
    """
    Structured code context (spec §24).

    Repositories are never sent to an LLM wholesale; agents build one of
    these and only the relevant slices reach the model.
    """

    model_config = ConfigDict(extra="allow")

    project_name: str = ""
    primary_language: str = "python"
    file_paths: list[str] = Field(default_factory=list)
    dependencies: dict[str, list[str]] = Field(default_factory=dict)
    entrypoints: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    test_files: list[str] = Field(default_factory=list)
    code_snippets: dict[str, str] = Field(default_factory=dict)
    ast_summary: dict[str, Any] = Field(default_factory=dict)
    tool_findings: list[dict] = Field(default_factory=list)

    def for_files(self, paths: list[str], root: str = "", *, max_chars: int = 40_000) -> "CodeContext":
        """Return a narrowed copy carrying only the requested files."""
        clipped: dict[str, str] = {}
        budget = max_chars
        for path in paths:
            source = self.code_snippets.get(path)
            if source is None:
                continue
            if budget <= 0:
                break
            if len(source) > budget:
                source = source[:budget] + "\n... [truncated]"
            clipped[path.removeprefix(root).lstrip("/")] = source
            budget -= len(source)
        return self.model_copy(
            update={
                "code_snippets": clipped,
                "file_paths": list(clipped),
            }
        )

    def to_prompt_block(self, *, max_chars: int = 24_000) -> str:
        """Render the context as the bounded text block handed to the LLM."""
        lines: list[str] = [
            f"PROJECT: {self.project_name or 'unknown'}",
            f"PRIMARY LANGUAGE: {self.primary_language}",
        ]
        if self.frameworks:
            lines.append(f"FRAMEWORKS: {', '.join(self.frameworks)}")
        if self.dependencies:
            for name, versions in self.dependencies.items():
                joined = ", ".join(versions[:25])
                lines.append(f"DEPENDENCY {name}: {joined}")
        if self.entrypoints:
            lines.append(f"ENTRYPOINTS: {', '.join(self.entrypoints[:10])}")
        if self.test_files:
            lines.append(f"EXISTING TESTS: {', '.join(self.test_files[:15])}")

        if self.tool_findings:
            lines.append("\nDETERMINISTIC TOOL OUTPUT:")
            for item in self.tool_findings[:60]:
                lines.append(f"  - [{item.get('tool')}] {item.get('title')} @ {item.get('file_path')}:{item.get('line_number')}")

        if self.code_snippets:
            lines.append("\nRELEVANT SOURCE:")
            for path, source in self.code_snippets.items():
                block = f"--- FILE: {path} ---\n{source}"
                if sum(len(line) for line in lines) + len(block) > max_chars:
                    lines.append(f"--- FILE: {path} --- [omitted, context budget reached]")
                    continue
                lines.append(block)
        return "\n".join(lines)


class AgentResult(BaseModel):
    """Uniform envelope returned by every agent run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    agent_name: str
    status: Literal["COMPLETED", "FAILED", "SKIPPED"] = "COMPLETED"
    findings: list[AgentFinding] = Field(default_factory=list)
    test_cases: list["GeneratedTest"] = Field(default_factory=list)
    patches: list["ProposedPatch"] = Field(default_factory=list)
    message: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

    def __len__(self) -> int:
        return len(self.findings)


class GeneratedTest(BaseModel):
    """A test the Testing Agent authored (spec §10)."""

    model_config = ConfigDict(extra="ignore")

    name: str
    description: str = ""
    test_code: str
    test_type: Literal["unit", "boundary", "security", "api", "regression"] = "unit"
    target_file: Optional[str] = None
    finding_id: Optional[str] = None
    is_exploit_test: bool = False


class ProposedPatch(BaseModel):
    """A candidate fix returned by the Fix Agent (spec §13)."""

    model_config = ConfigDict(extra="ignore")

    finding_id: Optional[str] = None
    file_path: str
    original_code: str = ""
    patched_code: str = ""
    diff: str = ""
    explanation: str = ""
    attack_to_defense: Optional[str] = None
    attack_surface_reduction: Optional[str] = None


class GeneratedTestResult(BaseModel):
    """Outcome of executing a test inside the sandbox."""

    test_name: str
    status: Literal["PASSED", "FAILED", "ERROR", "SKIPPED", "NOT_RUN"]
    output: str = ""
    duration_ms: float = 0.0
    return_code: Optional[int] = None


class ScanSummary(BaseModel):
    """Aggregated counts used by the dashboard (§17)."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    bugs_detected: int = 0
    tests_generated: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    verified_fixes: int = 0
    security_score: int = 100


AgentResult.model_rebuild()

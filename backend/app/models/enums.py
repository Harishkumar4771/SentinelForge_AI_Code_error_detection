"""Shared enumerations for the whole platform."""

from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def score_weight(self) -> int:
        """Points deducted from the 0-100 security score per finding."""
        return _SEVERITY_WEIGHT[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    ANALYZING = "ANALYZING"
    RUNNING = "RUNNING"
    CORRELATING = "CORRELATING"
    FIXING = "FIXING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}

    @property
    def is_active(self) -> bool:
        return self in {
            ScanStatus.PENDING,
            ScanStatus.ANALYZING,
            ScanStatus.RUNNING,
            ScanStatus.CORRELATING,
            ScanStatus.FIXING,
            ScanStatus.VERIFYING,
        }


class ProjectStatus(str, enum.Enum):
    PENDING = "PENDING"
    ANALYZED = "ANALYZED"
    SCANNING = "SCANNING"
    SCANNED = "SCANNED"
    FAILED = "FAILED"


class AgentName(str, enum.Enum):
    SECURITY = "security_agent"
    TESTING = "testing_agent"
    BUG_HUNTER = "bug_hunter"
    CORRELATOR = "finding_correlator"
    FIX = "fix_agent"
    SANDBOX = "sandbox_verifier"


class AgentStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class FindingCategory(str, enum.Enum):
    INJECTION = "Injection"
    XSS = "Cross-Site Scripting"
    PATH_TRAVERSAL = "Path Traversal"
    SECRETS = "Hardcoded Secret"
    CRYPTOGRAPHY = "Insecure Cryptography"
    AUTHENTICATION = "Authentication"
    AUTHORIZATION = "Authorization"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "Server-Side Request Forgery"
    IMPORT = "Dangerous Import"
    LOGIC = "Logic Bug"
    VALIDATION = "Input Validation"
    DEPENDENCY = "Dependency Risk"
    ERROR_HANDLING = "Error Handling"
    CONFIGURATION = "Configuration"
    OTHER = "Other"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    FIX_PROPOSED = "FIX_PROPOSED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


class Certainty(str, enum.Enum):
    """Evidence strength, per spec §24 (confirmed / probable / potential)."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POTENTIAL = "potential"


class TestType(str, enum.Enum):
    UNIT = "unit"
    BOUNDARY = "boundary"
    SECURITY = "security"
    API = "api"
    REGRESSION = "regression"


class TestStatus(str, enum.Enum):
    GENERATED = "GENERATED"
    QUEUED = "QUEUED"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"
    NOT_RUN = "NOT_RUN"


class ValidationStatus(str, enum.Enum):
    """Spec §14 verification states."""

    PENDING = "PENDING"
    APPLYING = "APPLYING"
    INSTALLING = "INSTALLING"
    RUNNING_TESTS = "RUNNING_TESTS"
    RESCANNING = "RESCANNING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


class SandboxBackend(str, enum.Enum):
    DOCKER = "docker"
    LOCAL = "local"

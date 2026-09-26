"""
External static-analysis tool runners (spec §9).

Bandit, Semgrep, Gitleaks and pip-audit are invoked as subprocesses over a
target directory. Each one translates its native output into
:class:`~app.schemas.finding.AgentFinding` so the correlator can merge
results without caring where they came from.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Sequence

from app.analyzers.base import ToolResult, ToolRunner, relative_to_root
from app.core.logging_config import get_logger
from app.models.enums import Certainty, FindingCategory, Severity
from app.schemas.finding import AgentFinding

logger = get_logger(__name__)

# ----------------------------------------------------------------------
# Bandit ID -> our taxonomy
# ----------------------------------------------------------------------
BANDIT_MAP: dict[str, dict[str, Any]] = {
    "B608": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "title": "SQL Injection (hardcoded query construction)",
    },
    "B611": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "title": "Command Injection via shell=True",
    },
    "B602": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "title": "Command Injection via subprocess with shell=True",
    },
    "B605": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-78",
        "title": "Command Injection via os.system",
    },
    "B307": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "title": "Command Injection via eval",
    },
    "B102": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-95",
        "title": "Code Injection via exec",
    },
    "B301": {
        "category": FindingCategory.INSECURE_DESERIALIZATION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "title": "Insecure deserialization via pickle",
    },
    "B506": {
        "category": FindingCategory.INSECURE_DESERIALIZATION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "title": "Insecure deserialization via yaml.load",
    },
    "B403": {
        "category": FindingCategory.IMPORT,
        "severity": Severity.LOW,
        "cwe": "CWE-250",
        "title": "Import of a module flagged as dangerous",
    },
    "B324": {
        "category": FindingCategory.CRYPTOGRAPHY,
        "severity": Severity.HIGH,
        "cwe": "CWE-327",
        "title": "Use of an insecure hash function",
    },
    "B303": {
        "category": FindingCategory.CRYPTOGRAPHY,
        "severity": Severity.MEDIUM,
        "cwe": "CWE-326",
        "title": "Insecure cipher mode",
    },
    "B311": {
        "category": FindingCategory.CRYPTOGRAPHY,
        "severity": Severity.MEDIUM,
        "cwe": "CWE-330",
        "title": "Use of a pseudo-random generator for a security value",
    },
    "B105": {
        "category": FindingCategory.SECRETS,
        "severity": Severity.MEDIUM,
        "cwe": "CWE-798",
        "title": "Hardcoded password string",
    },
    "B106": {
        "category": FindingCategory.SECRETS,
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
        "title": "Hardcoded password in function argument",
    },
    "B107": {
        "category": FindingCategory.SECRETS,
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
        "title": "Hardcoded default argument (possible secret)",
    },
    "B501": {
        "category": FindingCategory.XSS,
        "severity": Severity.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "title": "Cross-site scripting (request data rendered in a template)",
    },
    "B201": {
        "category": FindingCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "title": "Path traversal",
    },
    "B310": {
        "category": FindingCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "title": "Path traversal via urlopen",
    },
    "B501x": {},
}

BANDIT_DEFAULT = {
    "category": FindingCategory.OTHER,
    "severity": Severity.MEDIUM,
    "title": "Bandit security finding",
}

BANDIT_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}


class BanditRunner(ToolRunner):
    """``bandit -r -f json`` -- Python-specific static analysis."""

    name = "bandit"
    emits_json = True

    def build_command(self, target: Path) -> Sequence[str]:
        return [
            self.resolve() or "bandit",
            "-r",           # recursive
            "-f", "json",   # machine readable
            "-q",           # quiet: drop the banner
            "--exit-zero",  # findings must not look like a crash
            str(target),
        ]

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]:
        payload = self.parse_json(stdout)
        if isinstance(payload, dict):
            payload = payload.get("results", [])
        if not isinstance(payload, list):
            return []
        return [self._convert(item) for item in payload if isinstance(item, dict)]

    def _convert(self, item: dict) -> AgentFinding:
        test_id = str(item.get("test_id") or "")
        meta = BANDIT_MAP.get(test_id, BANDIT_DEFAULT)
        line = item.get("line_number") or item.get("line_range") or None
        if isinstance(line, list):
            line = line[0] if line else None
        col = item.get("col_offset") or 0
        code = item.get("code") or ""

        severity = BANDIT_SEVERITY.get(str(item.get("issue_severity", "")).upper(), Severity.MEDIUM)
        mapped_severity = meta.get("severity", severity)
        # Trust Bandit's own severity when it is more severe than our table.
        final = mapped_severity if mapped_severity > severity else severity

        text = str(item.get("issue_text") or "").strip()
        return AgentFinding(
            title=meta.get("title") or (text[:120] or f"Bandit {test_id}"),
            description=text or f"Bandit reported {test_id}.",
            severity=final,
            # Bandit is a real parser, so its output is evidence-backed.
            confidence=0.9 if final >= Severity.HIGH else 0.8,
            category=meta.get("category", FindingCategory.OTHER),
            cwe=meta.get("cwe") or _bandit_cwe(item),
            owasp=meta.get("owasp"),
            certainty=Certainty.CONFIRMED,
            file_path=relative_to_root(str(item.get("filename") or ""), self.root),
            line_number=int(line) if isinstance(line, int) else None,
            code_snippet=str(code).strip()[:1200] or None,
            evidence=[
                f"bandit {test_id}: {text}",
                f"Bandit confidence: {item.get('issue_confidence', 'UNKNOWN')}",
            ],
            impact=meta.get("title"),
            recommendation=_bandit_recommendation(test_id),
            detected_by=["security_agent"],
            tools=["bandit"],
        )


def _bandit_cwe(item: dict) -> str | None:
    cwe = item.get("issue_cwe")
    if isinstance(cwe, dict):
        cwe = cwe.get("id")
    if cwe:
        return f"CWE-{cwe}" if not str(cwe).startswith("CWE-") else str(cwe)
    return None


_BANDIT_FIXES = {
    "B608": "Use parameterized queries (cursor.execute(sql, params)) instead of building SQL by string concatenation.",
    "B611": "Pass the command and arguments as a list to subprocess.run with shell=False.",
    "B602": "Replace subprocess(..., shell=True) with subprocess.run([...], shell=False, check=True).",
    "B605": "Replace os.system with subprocess.run([...], shell=False).",
    "B301": "Replace pickle with a data-only format such as JSON, or sign the payload with hmac before loading.",
    "B506": "Use yaml.safe_load instead of yaml.load.",
    "B324": "Use hashlib.sha256 or stronger; for passwords use bcrypt, scrypt or argon2 with a unique salt.",
    "B105": "Read the value from an environment variable or a secrets manager; never commit credentials.",
    "B501": "Escape output for HTML, or render through a template engine with autoescaping enabled.",
    "B201": "Resolve the path and verify it stays inside the intended base directory before opening it.",
    "B310": "Validate the URL against an allowlist of permitted hosts and schemes before fetching it.",
}


def _bandit_recommendation(test_id: str) -> str:
    return _BANDIT_FIXES.get(
        test_id, "Review the flagged construct and apply the secure alternative for this pattern."
    )


# ----------------------------------------------------------------------
class SemgrepRunner(ToolRunner):
    """
    ``semgrep --json`` -- broad pattern matching.

    Runs with the bundled rule set; ``security-rules/`` is added to the
    search path when present so project-specific rules apply.
    """

    name = "semgrep"
    emits_json = True

    def __init__(self, *, rules_dir: Path | None = None, **kwargs):
        super().__init__(**kwargs)
        self.rules_dir = rules_dir

    def build_command(self, target: Path) -> Sequence[str]:
        command = [
            self.resolve() or "semgrep",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--disable-version-check",
            "--metrics=off",
            "--timeout", "30",       # per-rule timeout, seconds
            "--timeout-threshold", "3",
            "--max-target-bytes", "2000000",
            "--jobs", "2",
        ]
        # Local rules take precedence over the bundled registry default.
        if self.rules_dir and self.rules_dir.exists():
            command += ["--config", str(self.rules_dir)]
        else:
            command += ["--config", "auto"]
        command.append(str(target))
        return command

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]:
        payload = self.parse_json(stdout)
        if not isinstance(payload, dict):
            return []
        results = payload.get("results") or []
        return [self._convert(item) for item in results if isinstance(item, dict)]

    def _convert(self, item: dict) -> AgentFinding:
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe_refs = meta.get("cwe") or []
        cwe = None
        if isinstance(cwe_refs, list) and cwe_refs:
            first = cwe_refs[0]
            cwe = f"CWE-{first}" if not str(first).startswith("CWE-") else str(first)

        owasp_refs = meta.get("owasp") or meta.get("owasp-mobile") or []
        owasp = None
        if isinstance(owasp_refs, list) and owasp_refs:
            match = re.search(r"A(\d{2}):(\d{4})", str(owasp_refs[0]).replace(" ", ""))
            owasp = f"A{match.group(1)}:{match.group(2)}" if match else None

        severity = str(extra.get("severity") or "WARNING").upper()
        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        start = item.get("start") or {}
        end = item.get("end") or {}

        return AgentFinding(
            title=str(extra.get("message") or item.get("check_id") or "Semgrep finding")[:500],
            description=str(extra.get("message") or "")[:4000],
            severity=severity_map.get(severity, Severity.MEDIUM),
            confidence=0.9,
            category=_semgrep_category(cwe, str(extra.get("message", ""))),
            cwe=cwe,
            owasp=owasp,
            certainty=Certainty.CONFIRMED,
            file_path=relative_to_root(str(item.get("path") or ""), self.root),
            line_number=int(start.get("line") or 0) or None,
            line_end=int(end.get("line") or 0) or None,
            code_snippet=str(extra.get("lines") or "").strip()[:1200] or None,
            evidence=[f"semgrep rule {item.get('check_id')}"],
            recommendation=str(meta.get("fix") or meta.get("references") or "")[:2000] or None,
            detected_by=["security_agent"],
            tools=["semgrep"],
        )


def _semgrep_category(cwe: str | None, message: str) -> str:
    text = message.lower()
    mapping = [
        ("sql injection", FindingCategory.INJECTION),
        ("command injection", FindingCategory.INJECTION),
        ("cross-site", FindingCategory.XSS),
        ("xss", FindingCategory.XSS),
        ("traversal", FindingCategory.PATH_TRAVERSAL),
        ("secret", FindingCategory.SECRETS),
        ("password", FindingCategory.AUTHENTICATION),
        ("auth", FindingCategory.AUTHENTICATION),
        ("deserial", FindingCategory.INSECURE_DESERIALIZATION),
        ("pickle", FindingCategory.INSECURE_DESERIALIZATION),
        ("ssrf", FindingCategory.SSRF),
        ("md5", FindingCategory.CRYPTOGRAPHY),
        ("random", FindingCategory.CRYPTOGRAPHY),
        ("tls", FindingCategory.CRYPTOGRAPHY),
        ("ssl", FindingCategory.CRYPTOGRAPHY),
    ]
    for needle, category in mapping:
        if needle in text:
            return category
    if cwe == "CWE-89":
        return FindingCategory.INJECTION
    if cwe == "CWE-22":
        return FindingCategory.PATH_TRAVERSAL
    if cwe in {"CWE-798", "CWE-259"}:
        return FindingCategory.SECRETS
    if cwe in {"CWE-327", "CWE-328", "CWE-330", "CWE-916"}:
        return FindingCategory.CRYPTOGRAPHY
    if cwe in {"CWE-862", "CWE-863", "CWE-306"}:
        return FindingCategory.AUTHORIZATION
    return FindingCategory.OTHER


# ----------------------------------------------------------------------
class GitleaksRunner(ToolRunner):
    """
    ``gitleaks detect`` -- high-entropy secret detection.

    ``--redact`` keeps raw credentials out of our logs and the database.
    gitleaks v8 insists on a real report path (``/dev/stdout`` is rejected),
    so output goes to a temporary file that is read back and deleted.
    """

    name = "gitleaks"
    emits_json = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._report: Path | None = None

    def build_command(self, target: Path) -> Sequence[str]:
        self._report = Path(tempfile.mkstemp(prefix="sentinelforge-gitleaks-", suffix=".json")[1])
        return [
            self.resolve() or "gitleaks",
            "detect",
            "--source", str(target),
            "--no-git",
            "--redact",
            "--exit-code", "0",
            "--report-format", "json",
            "--report-path", str(self._report),
        ]

    async def run(self, target: Path) -> ToolResult:
        result = await super().run(target)
        if self._report and self._report.exists():
            try:
                text = self._report.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            finally:
                self._report.unlink(missing_ok=True)
            if text.strip():
                try:
                    result.findings = self.parse(text, "", 0)
                    result.error = None
                except Exception as exc:  # a parse bug must not kill the scan
                    logger.exception("gitleaks report parsing failed")
                    result.error = f"parse error: {exc}"
        return result

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]:
        payload = self.parse_json(stdout)
        if not isinstance(payload, list):
            return []
        return [self._convert(item) for item in payload if isinstance(item, dict)]

    def _convert(self, item: dict) -> AgentFinding:
        rule = str(item.get("RuleID") or "generic-secret")
        description = str(item.get("Description") or f"Secret matched rule '{rule}'")
        start = str(item.get("StartLine") or "") or None

        return AgentFinding(
            title=f"Hardcoded secret detected ({rule})",
            description=description[:2000],
            # A committed credential is critical if it is a live-looking key.
            severity=Severity.CRITICAL if _is_live_secret(rule, item) else Severity.HIGH,
            confidence=0.95,
            category=FindingCategory.SECRETS,
            cwe="CWE-798",
            owasp="A07:2021-Identification and Authentication Failures",
            certainty=Certainty.CONFIRMED,
            file_path=relative_to_root(str(item.get("File") or ""), self.root),
            line_number=int(start) if start and start.isdigit() else None,
            code_snippet=_redacted_line(item),
            evidence=[
                f"gitleaks rule {rule}",
                f"match: {_safe_match(item)}",
            ],
            impact="A committed credential can be used directly by an attacker against the corresponding service.",
            recommendation="Revoke and rotate the exposed credential, remove it from version control, and load it from a secret manager or environment variable.",
            detected_by=["security_agent"],
            tools=["gitleaks"],
        )


def _is_live_secret(rule: str, item: dict) -> bool:
    return any(
        token in rule.lower()
        for token in ("aws", "private-key", "gcp", "slack", "stripe", "openai", "github-pat")
    )


def _safe_match(item: dict) -> str:
    """Never persist the raw secret; show only a redacted fingerprint."""
    match = str(item.get("Match") or "")
    if not match:
        return ""
    return re.sub(r"[A-Za-z0-9_\-/+=]{8,}", lambda m: f"{m.group(0)[:3]}***{m.group(0)[-2:]}", match)[:200]


def _redacted_line(item: dict) -> str | None:
    line = str(item.get("Secret") or "")
    if not line:
        return None
    return f"{line[:2]}****{line[-2:]}" if len(line) > 6 else "****"


# ----------------------------------------------------------------------
class PipAuditRunner(ToolRunner):
    """
    ``pip-audit`` -- known CVEs in declared dependencies.

    Fast path: when every requirement is pinned with ``==``, audit straight
    from the manifest with ``--no-deps --disable-pip``. That avoids building
    a resolver environment, which needs network access and takes minutes.

    Slow path: unpinned requirements must be resolved by pip, so the full
    resolver runs (slower, needs network) and the tool timeout is raised.
    """

    name = "pip-audit"
    emits_json = True

    _PINNED = re.compile(r"^\s*[A-Za-z0-9_.\-\[\]]+\s*==\s*[^\s;#]+")

    def _requirements(self, target: Path) -> str | None:
        for name in ("requirements.txt", "requirements-dev.txt", "requirements/base.txt"):
            candidate = target / name
            if candidate.is_file():
                return str(candidate)
        return None

    def _fully_pinned(self, requirements: str) -> bool:
        try:
            lines = Path(requirements).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return False
        considered = [
            line for line in lines
            if line.strip() and not line.strip().startswith(("#", "-r", "--"))
        ]
        return bool(considered) and all(self._PINNED.match(line) for line in considered)

    def build_command(self, target: Path) -> Sequence[str]:
        requirements = self._requirements(target)
        if requirements is None:
            # Nothing declared: run --version so parse() can no-op cleanly.
            return [self.resolve() or "pip-audit", "--version"]

        command = [
            self.resolve() or "pip-audit",
            "-r", requirements,
            "--format", "json",
            "--progress-spinner", "off",
        ]
        if self._fully_pinned(requirements):
            command += ["--no-deps", "--disable-pip"]
        else:
            # Resolution needs to install into a throwaway environment.
            self.timeout = max(self.timeout, 300)
        return command

    def parse(self, stdout: str, stderr: str, returncode: int) -> list[Any]:
        # No requirements file: `pip-audit --version` output, not a finding.
        if stdout.strip().startswith("pip-audit"):
            return []

        payload = self.parse_json(stdout)
        if isinstance(payload, dict):
            payload = payload.get("dependencies", [])
        if not isinstance(payload, list):
            return []

        findings: list[AgentFinding] = []
        vulnerable: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            vulns = item.get("vulns") or []
            package = str(item.get("name") or "unknown")
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                findings.append(self._convert(package, vuln))
                vulnerable.append({"package": package, **vuln})

        # Twenty-seven individual dependency rows would bury the code-level
        # findings a reviewer must act on first. Above the threshold they are
        # replaced by a single manifest-level finding that still names every
        # package and advisory ID, so no detail is lost.
        if len(findings) > 3:
            aggregate = self._aggregate(vulnerable)
            if aggregate:
                return [aggregate]
        return findings

    def _aggregate(self, vulnerable: list[dict[str, Any]]) -> AgentFinding | None:
        """One finding covering all vulnerable direct dependencies."""
        packages = sorted({str(item["package"]) for item in vulnerable})
        aliases = sorted(
            {
                str(item.get("fix_versions") and item["fix_versions"][0])
                for item in vulnerable
                if item.get("fix_versions")
            }
        )
        ids = sorted(
            {str(item["id"]) for item in vulnerable if item.get("id")}
        )
        if not packages:
            return None

        highest = Severity.HIGH if len(vulnerable) > 3 else Severity.MEDIUM
        detail = ", ".join(f"{item['package']} ({item.get('id', 'no ID')})" for item in vulnerable[:15])
        if len(vulnerable) > 15:
            detail += f", and {len(vulnerable) - 15} more"

        return AgentFinding(
            title=f"Vulnerable dependencies: {len(packages)} package(s) with known CVEs",
            description=(
                f"{len(vulnerable)} known vulnerability record(s) affect "
                f"{len(packages)} direct dependencies: {detail}."
            ),
            severity=highest,
            # A declared-dependency CVE is certain, but exploitability in this
            # application is not, so confidence stays below the confirmed code
            # findings.
            confidence=0.75,
            category=FindingCategory.DEPENDENCY.value,
            cwe="CWE-1104",
            certainty=Certainty.CONFIRMED,
            file_path="requirements.txt",
            evidence=[
                f"pip-audit reported {len(vulnerable)} vulnerability record(s)",
                f"Packages affected: {', '.join(packages[:20])}",
                f"Advisory IDs: {', '.join(ids[:20])}",
            ],
            impact="A published exploit against any of these versions may apply to the application, depending on whether the affected code path is reachable.",
            recommendation=(
                "Upgrade the affected packages."
                + (f" Fixed versions available: {', '.join(aliases)}." if aliases else "")
            ),
            detected_by=["security_agent"],
            tools=[self.name],
        )

    def _convert(self, package: str, vuln: dict) -> AgentFinding:
        aliases = vuln.get("aliases") or []
        cwe = None
        for alias in aliases:
            match = re.search(r"CWE-(\d+)", str(alias))
            if match:
                cwe = f"CWE-{match.group(1)}"
                break

        fix_versions = [v for v in (vuln.get("fix_versions") or []) if v]
        return AgentFinding(
            title=f"Vulnerable dependency: {package} {vuln.get('id', '')}".strip(),
            description=str(vuln.get("description") or f"{package} is affected by {vuln.get('id')}")[:4000],
            severity=Severity.HIGH,
            confidence=0.95,
            category=FindingCategory.DEPENDENCY,
            cwe=cwe,
            owasp="A06:2021-Vulnerable and Outdated Components",
            certainty=Certainty.CONFIRMED,
            file_path="requirements.txt",
            evidence=[
                f"pip-audit matched {vuln.get('id')}",
                *([f"fixed in {', '.join(fix_versions)}"] if fix_versions else []),
            ],
            impact="A known, publicly documented vulnerability affects a declared dependency.",
            recommendation=(
                f"Upgrade {package} to {fix_versions[0]} or later."
                if fix_versions
                else f"No fixed version is published for {vuln.get('id')}; evaluate mitigations or replace the package."
            ),
            detected_by=["security_agent"],
            tools=["pip-audit"],
        )


__all__ = [
    "BanditRunner",
    "GitleaksRunner",
    "PipAuditRunner",
    "SemgrepRunner",
    "ToolResult",
]

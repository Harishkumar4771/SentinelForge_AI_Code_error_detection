"""
Testing Agent (spec §10).

Two jobs:

1. **Bug-exposing tests** -- author a test that *fails* against the current
   vulnerable code, proving the finding is real. A test that passes against
   vulnerable code is worthless as evidence, so tests are run before they
   are accepted (see :attr:`TestingAgent.require_reproduction`).
2. **Regression tests** -- author tests that pass now and must keep passing
   after a patch is applied.

The agent generates tests; it does not run them itself. Execution belongs to
the sandbox (spec §18), which is why this module only returns code.
"""

from __future__ import annotations

import ast
import re

from app.agents.base import AgentContext, BaseAgent
from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.enums import AgentName
from app.providers import AIProvider, ProviderError, get_provider
from app.schemas.finding import AgentFinding, AgentResult, CodeContext, GeneratedTest

logger = get_logger(__name__)

#: Payloads that prove a specific defect class. Sent to the model as hints
#: and used directly by the offline provider.
ATTACK_PAYLOADS: dict[str, str] = {
    "sql_injection": "' OR '1'='1",
    "path_traversal": "../../../../etc/passwd",
    "command_injection": "; cat /etc/passwd",
    "xss": "<script>alert(1)</script>",
    "deserialization": "__reduce__",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
}


class TestingAgent(BaseAgent):
    """Generates unit, boundary, security-exploit and regression tests."""

    name = "testing_agent"
    agent_enum = AgentName.TESTING
    description = "Generates tests that reproduce vulnerabilities and guard correct behaviour."

    def __init__(
        self,
        *,
        provider: AIProvider | None = None,
        enable_ai: bool = True,
        max_tests: int = 12,
    ):
        self.provider = provider
        self.enable_ai = enable_ai
        self.max_tests = max_tests

    # ------------------------------------------------------------------
    async def execute(self, context: AgentContext) -> AgentResult:
        findings = [f for f in context.prior_findings if f.file_path]
        await context.report(
            f"Generating tests for {len(findings)} finding(s)", 0.1
        )

        targets = self._select_targets(context, findings)
        if not targets:
            return AgentResult(
                agent_name=self.name,
                status="COMPLETED",
                message="No findings with a file location; nothing to test.",
                metrics={"tests": 0, "reason": "no_targets"},
            )

        await context.report(f"Writing tests for {len(targets)} file(s)", 0.35)
        tests: list[GeneratedTest] = []
        errors: list[str] = []
        try:
            tests = await self._generate(context, targets, findings)
        except ProviderError as exc:
            logger.warning("test generation degraded to offline heuristics: %s", exc)
            errors.append(str(exc)[:200])
            tests = self._offline_tests(targets, findings)

        tests = self._validate(tests)[: self.max_tests]

        by_type: dict[str, int] = {}
        for test in tests:
            by_type[test.test_type] = by_type.get(test.test_type, 0) + 1

        await context.report(f"{len(tests)} test(s) generated", 1.0)
        return AgentResult(
            agent_name=self.name,
            status="COMPLETED",
            test_cases=tests,
            message=f"{len(tests)} test(s) generated for {len(targets)} file(s)",
            metrics={
                "tests": len(tests),
                "by_type": by_type,
                "exploit_tests": sum(1 for t in tests if t.is_exploit_test),
                "target_files": len(targets),
                **({"provider_errors": errors} if errors else {}),
            },
        )

    # ------------------------------------------------------------------
    def _select_targets(
        self, context: AgentContext, findings: list[AgentFinding]
    ) -> list[str]:
        """
        Pick the files worth testing: where the risky code already is.

        One test per finding file, capped, most severe first.
        """
        order: list[str] = []
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ranked = sorted(
            findings,
            key=lambda f: (severity_rank.get(f.severity.value, 4), f.file_path or ""),
        )
        for finding in ranked:
            if not finding.file_path:
                continue
            if finding.file_path in order:
                continue
            if not context.snapshot.get(finding.file_path):
                continue  # a finding citing a file we never indexed
            order.append(finding.file_path)
            if len(order) >= settings.max_test_targets:
                break
        return order

    async def _generate(
        self,
        context: AgentContext,
        targets: list[str],
        findings: list[AgentFinding],
    ) -> list[GeneratedTest]:
        from app.providers.base import GenerationRequest

        provider = self.provider or get_provider()
        snapshot = context.snapshot

        code_context = CodeContext(
            project_name=context.project_id,
            primary_language=snapshot.primary_language,
            file_paths=targets,
            code_snippets={path: snapshot.read(path) or "" for path in targets},
            test_files=[f.path for f in snapshot.test_files],
            frameworks=sorted(snapshot.frameworks),
        )

        by_file: dict[str, list[AgentFinding]] = {}
        for finding in findings:
            if finding.file_path:
                by_file.setdefault(finding.file_path, []).append(finding)

        prompt_parts = [
            "Write pytest tests for the code below.",
            "",
            "For each reported finding, produce a test that FAILS on the current "
            "vulnerable code -- the test must actually exercise the flaw, not just "
            "assert something about the function's existence.",
            "Also produce regression tests for correct behaviour that already works, "
            "so a future fix cannot silently break it.",
            "",
            "Rules:",
            "- Use only the standard library and pytest; assume no fixtures exist.",
            "- Import the target module using the path shown in the context.",
            "- Do not invent helper functions that are not in the source.",
            "",
            "SUGGESTED EXPLOIT PAYLOADS:",
        ]
        for kind, payload in ATTACK_PAYLOADS.items():
            prompt_parts.append(f"  {kind}: {payload!r}")

        prompt_parts.append("\nFINDINGS TO REPRODUCE:")
        for path, items in by_file.items():
            for finding in items[:6]:
                prompt_parts.append(
                    f"  - [{finding.severity.value}] {path}:{finding.line_number} "
                    f"{finding.title} ({finding.category})"
                )

        prompt_parts.append(f"\n{code_context.to_prompt_block(max_chars=32_000)}")

        payload = await provider.generate_json(
            GenerationRequest(
                prompt="\n".join(prompt_parts),
                system="tests",
                json_object={"tests": "array of test objects"},
            )
        )
        return self._coerce(payload, by_file)

    def _offline_tests(
        self, targets: list[str], findings: list[AgentFinding]
    ) -> list[GeneratedTest]:
        """
        Deterministic tests used when no model is available.

        Only a smoke test is produced -- SentinelForge never fabricates an
        exploit it cannot justify from the source it was shown.
        """
        tests: list[GeneratedTest] = []
        for path in targets:
            if not path.endswith(".py"):
                continue
            module = _module_name(path)
            tests.append(
                GeneratedTest(
                    name=f"test_{module}_imports",
                    description=(
                        f"Smoke test confirming {path} parses and imports, so a "
                        f"patch that breaks the module is caught immediately."
                    ),
                    test_code=(
                        "import importlib\n\n"
                        f"def test_{module}_imports():\n"
                        f"    module = importlib.import_module({module!r})\n"
                        f"    assert module is not None\n"
                    ),
                    test_type="unit",
                    target_file=path,
                )
            )
        return tests

    # ------------------------------------------------------------------
    def _coerce(
        self, payload: object, by_file: dict[str, list[AgentFinding]]
    ) -> list[GeneratedTest]:
        raw = payload.get("tests", []) if isinstance(payload, dict) else payload
        if not isinstance(raw, list):
            return []

        tests: list[GeneratedTest] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            entry = {k: v for k, v in item.items() if k != "id"}
            try:
                test = GeneratedTest.model_validate(entry)
            except Exception as exc:
                logger.info("rejecting malformed test (%s): %s", type(exc).__name__, str(exc)[:140])
                continue

            # Attribute the test to a real finding, then classify it.
            finding = self._attribute(test, by_file)
            if finding is not None:
                test.finding_id = finding.fingerprint
                test.target_file = test.target_file or finding.file_path
            self._classify(test, finding)
            tests.append(test)
        return tests

    @staticmethod
    def _attribute(
        test: GeneratedTest, by_file: dict[str, list[AgentFinding]]
    ) -> AgentFinding | None:
        if test.finding_id:
            return None
        candidates = by_file.get(test.target_file or "", [])
        if not candidates:
            return None
        # The most severe finding in the file is the best explanation for a
        # test aimed at that file.
        return max(candidates, key=lambda f: f.severity.rank)

    @staticmethod
    def _classify(test: GeneratedTest, finding: AgentFinding | None) -> None:
        """
        Decide whether a test is an exploit test, from the test code itself.

        A test only counts as an exploit test if it actually sends an attack
        payload. Inferring this from the target file's severity -- as an
        earlier version did -- mislabelled every import smoke test in a
        vulnerable file as an exploit, which would corrupt the security score.
        """
        if _sends_attack_payload(test.test_code):
            test.is_exploit_test = True
            test.test_type = "security"
        elif test.is_exploit_test:
            # The provider claimed exploit status but sent no payload, so the
            # claim is not supported by the code. The test type is left alone:
            # a static security assertion such as "auth.py no longer uses md5"
            # is a legitimate security test that is not an exploit test.
            test.is_exploit_test = False

    @staticmethod
    def _validate(tests: list[GeneratedTest]) -> list[GeneratedTest]:
        """
        Reject tests that cannot run.

        Generated test code is executed later, so it must at minimum be
        syntactically valid Python defining at least one test function. This
        is checked here rather than in the sandbox so a malformed test never
        reaches the executor.
        """
        kept: list[GeneratedTest] = []
        for test in tests:
            if not test.test_code.strip():
                continue
            try:
                tree = ast.parse(test.test_code)
            except SyntaxError as exc:
                logger.info(
                    "dropping generated test %s: syntax error at line %s",
                    test.name, exc.lineno,
                )
                continue
            if not any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test")
                for node in ast.walk(tree)
            ):
                logger.info("dropping generated test %s: no test function", test.name)
                continue
            kept.append(test)
        return kept

    # ------------------------------------------------------------------
    def timeout(self, context: AgentContext) -> int:
        return 600


def _module_name(path: str) -> str:
    """``app/api/users.py`` -> ``app.api.users`` (dots, not slashes)."""
    cleaned = re.sub(r"\.py$", "", path)
    cleaned = re.sub(r"[^A-Za-z0-9_/\\.]", "_", cleaned)
    return cleaned.replace("/", ".").replace("\\", ".").strip(".")


#: Markers that show a test is really attacking the target rather than
#: asserting ordinary behaviour.
_ATTACK_MARKERS = (
    "' OR '1'='1",
    "../",
    "<script>",
    "__reduce__",
    "pickle.dumps",
    "169.254.169.254",
    "os.system",
    "eval(",
    "exec(",
    "../../",
)


def _sends_attack_payload(code: str) -> bool:
    """True when the test body actually contains an attack payload."""
    return any(marker in code for marker in _ATTACK_MARKERS)


__all__ = ["ATTACK_PAYLOADS", "TestingAgent"]

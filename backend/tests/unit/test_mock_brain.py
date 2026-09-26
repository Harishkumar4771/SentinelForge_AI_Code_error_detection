"""
Tests for the deterministic mock provider.

The mock stands in for the LLM, so its job is not to be clever -- it is to be
*honest*. Two failure modes matter and are pinned here:

* an exploit test attributed to the wrong file, and
* a test silently dropped because another file produced the same name.

Both silently hide real findings, which is exactly what this project exists to
stop.
"""

from __future__ import annotations

import ast

import pytest

from app.providers.mock_brain import (
    PATCHERS,
    _exploit_kind,
    _generate_tests,
    extract_code_blocks,
    respond,
)
from app.providers.base import GenerationRequest


def _prompt(findings: list[tuple[str, int, str, str]], blocks: dict[str, str]) -> str:
    lines = ["Write pytest tests for the code below.", "", "FINDINGS TO REPRODUCE:"]
    for path, line, title, category in findings:
        lines.append(f"  - [HIGH] {path}:{line} {title} ({category})")
    lines.append("")
    for path, source in blocks.items():
        lines.append(f"--- FILE: {path} ---")
        lines.append(source)
    return "\n".join(lines)


class TestExploitAttribution:
    def test_each_file_gets_its_own_exploit_test(self) -> None:
        """
        Two files with the same finding title must each keep a test.

        The analyzers emit generic titles ("tainted input reaches a query
        execution") wherever the pattern appears. Deduplicating on the test
        name alone let the first file's test swallow the second's, and the
        genuine finding lost its exploit.
        """
        title = "SQL Injection: tainted input reaches a query execution"
        sources = {
            "auth.py": "def register(username):\n    cursor.execute(sql, (username,))\n",
            "database.py": "def find(username):\n    query = \"SELECT '\" + username + \"'\"\n",
        }
        prompt = _prompt(
            [("auth.py", 67, title, "Injection"), ("database.py", 75, title, "Injection")],
            sources,
        )
        tests = _generate_tests(prompt, list(sources.items()))
        by_file = {t["target_file"] for t in tests if t["is_exploit_test"]}
        assert "database.py" in by_file, "the genuinely vulnerable file lost its exploit test"
        assert len([t for t in tests if t["is_exploit_test"]]) == 2, (
            "one exploit test was dropped by a name collision"
        )

    def test_names_stay_unique_within_a_file(self) -> None:
        prompt = _prompt(
            [("a.py", 1, "SQL Injection: one", "Injection"),
             ("a.py", 9, "SQL Injection: two", "Injection")],
            {"a.py": "def f(x):\n    pass\n"},
        )
        tests = _generate_tests(prompt, [("a.py", "def f(x):\n    pass\n")])
        names = [t["name"] for t in tests]
        assert len(names) == len(set(names))

    def test_exploit_tests_compile(self) -> None:
        prompt = _prompt(
            [("database.py", 75, "SQL Injection: tainted input", "Injection")],
            {"database.py": "def find(u):\n    pass\n"},
        )
        for test in _generate_tests(prompt, [("database.py", "def find(u):\n    pass\n")]):
            ast.parse(test["test_code"])  # must be valid Python


class TestExploitKindMapping:
    @pytest.mark.parametrize(
        "title, category, expected",
        [
            ("SQL Injection: tainted input", "Injection", "sql_injection"),
            ("Path Traversal: tainted input", "Path Traversal", "path_traversal"),
            ("Insecure deserialization: pickle", "Insecure Deserialization", "deserialization"),
            ("Missing authorization on /admin", "Access Control", "missing_authorization"),
            ("Weak password hashing with md5", "Cryptography", "weak_hash"),
            ("Something entirely unrelated", "Other", None),
            ("", "", None),
        ],
    )
    def test_mapping(self, title: str, category: str, expected: str | None) -> None:
        assert _exploit_kind(title, category) == expected


class TestPatchers:
    def test_every_patcher_output_is_valid_python(self, demo_sources) -> None:
        for name, patcher in PATCHERS.items():
            source = demo_sources.get(f"{name.split('_')[0]}.py")
            if source is None:
                continue
            result = patcher(source)
            if result is None:
                continue
            patched, explanation = result
            ast.parse(patched)
            assert patched != source, f"{name} returned the source unchanged"
            assert explanation, f"{name} returned no explanation"

    def test_sql_patcher_has_no_dangling_quotes(self, demo_sources) -> None:
        """
        The bug this guards: a placeholder left *inside* a string literal.

        The signature is a single quote immediately before the ``?`` (only
        whitespace between). It is not enough to forbid ``'?"`` -- a
        placeholder legitimately closes a double-quoted literal -- and the LIKE
        rewrite legitimately contains ``'%' || ? || '%'``.
        """
        import re

        patched, _ = PATCHERS["sql_injection"](demo_sources["database.py"])
        dangling = re.search(r"'\s*\?", patched)
        assert dangling is None, f"placeholder trapped in a string literal: {dangling}"
        # No control characters leaked in through a replacement template.
        assert not any(ord(c) < 9 or 13 < ord(c) < 32 for c in patched)

    def test_traversal_patch_blocks_and_still_allows_legitimate_use(
        self, demo_sources
    ) -> None:
        patched, _ = PATCHERS["path_traversal"](demo_sources["files.py"])
        assert "is_relative_to" in patched
        # A read that escapes must not blow up with an unhandled error.
        assert "if not target or not os.path.isfile(target):" in patched
        ast.parse(patched)

    def test_patcher_returns_none_when_nothing_to_do(self) -> None:
        assert PATCHERS["sql_injection"]("def f():\n    pass\n") is None
        assert PATCHERS["path_traversal"]("def f():\n    pass\n") is None
        assert PATCHERS["deserialization"]("x = 1\n") is None


class TestCodeBlockExtraction:
    def test_source_containing_headings_is_not_mis_split(self) -> None:
        """
        Source files contain lines like "FLAW: path traversal" in docstrings.
        A body-terminator heuristic would truncate every block at the first one.
        """
        prompt = (
            "--- FILE: a.py ---\n"
            '"""FLAW: path traversal."""\n'
            "def f():\n    pass\n"
            "--- FILE: b.py ---\n"
            "def g():\n    pass\n"
        )
        blocks = dict(extract_code_blocks(prompt))
        assert set(blocks) == {"a.py", "b.py"}
        assert "FLAW" in blocks["a.py"]
        assert "def g" in blocks["b.py"]

    def test_no_headers_yields_no_blocks(self) -> None:
        assert extract_code_blocks("just prose") == []


class TestResponsesAreValid:
    @pytest.mark.parametrize("system", ["security", "bug_hunter", "tests", "fix"])
    def test_every_system_returns_json(self, system: str, demo_sources) -> None:
        import json

        blocks = list(demo_sources.items())
        prompt = _prompt(
            [("database.py", 75, "SQL Injection: tainted input", "Injection")], dict(blocks)
        )
        payload = json.loads(respond(GenerationRequest(prompt=prompt, system=system)))
        assert isinstance(payload, dict)

    def test_unknown_system_does_not_raise(self) -> None:
        respond(GenerationRequest(prompt="anything", system="not-a-system"))

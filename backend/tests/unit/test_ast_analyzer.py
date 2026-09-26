"""
Tests for the AST security analyzer and the interprocedural taint engine.

The regression that matters most here is a *false positive*: flagging a
correctly parameterized query as SQL injection is worse than missing a real
one, because it trains users to ignore the tool. ``TestParameterizedQueriesAreSafe``
is a permanent guard against that class of bug.
"""

from __future__ import annotations

import pytest

from tests.conftest import DEMO_REPO as DEMO

from app.analyzers.ast_analyzer import analyze_module
from app.analyzers.taint import InterproceduralSecurityAnalyzer
from app.models.enums import Severity


def _analyze(source: str, path: str = "app.py"):
    """Security findings for one module (the real public entry point)."""
    security, _logic = analyze_module(path, source)
    return security


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


class TestParameterizedQueriesAreSafe:
    """Bound parameters are inert; only the statement text can be injectable."""

    def test_placeholder_query_with_tainted_parameter_is_not_flagged(self) -> None:
        source = (
            "from flask import request\n"
            "def login():\n"
            "    username = request.form['username']\n"
            "    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))\n"
        )
        findings = [f for f in _analyze(source) if f.category == "Injection"]
        assert findings == [], f"safe parameterized query flagged: {_titles(findings)}"

    def test_static_statement_is_not_flagged(self) -> None:
        source = (
            "from flask import request\n"
            "def all_users():\n"
            "    cursor.execute('SELECT * FROM users')\n"
        )
        assert not [f for f in _analyze(source) if f.category == "Injection"]

    def test_concatenated_statement_is_still_flagged(self) -> None:
        """The fix must not blind the analyzer to the real bug."""
        source = (
            "from flask import request\n"
            "def login():\n"
            "    username = request.form['username']\n"
            "    cursor.execute(\"SELECT * FROM users WHERE username = '\" + username + \"'\")\n"
        )
        findings = [f for f in _analyze(source) if f.category == "Injection"]
        assert findings, "concatenated statement went undetected"
        assert all("SQL" in f.title for f in findings)


class TestRealVulnerabilitiesAreFound:
    def test_path_traversal_via_join(self) -> None:
        source = (
            "from flask import request\n"
            "import os\n"
            "def read():\n"
            "    name = request.args.get('f')\n"
            "    return open(os.path.join('/srv/docs', name)).read()\n"
        )
        assert any(f.category == "Path Traversal" for f in _analyze(source))

    def test_untainted_path_join_is_not_reported(self) -> None:
        """A taint analyzer must stay quiet when nothing is attacker-controlled."""
        source = (
            "import os\n"
            "def read(name):\n"
            "    return open(os.path.join('/srv/docs', name)).read()\n"
        )
        assert not [f for f in _analyze(source) if f.category == "Path Traversal"]

    def test_command_injection_with_shell_true(self) -> None:
        source = (
            "import subprocess\n"
            "def run(host):\n"
            "    subprocess.run('ping ' + host, shell=True)\n"
        )
        findings = _analyze(source)
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_insecure_deserialization(self) -> None:
        source = (
            "from flask import request\n"
            "import pickle\n"
            "def load():\n"
            "    blob = request.get_data()\n"
            "    return pickle.loads(blob)\n"
        )
        findings = [f for f in _analyze(source) if f.category == "Insecure Deserialization"]
        assert findings
        assert findings[0].severity is Severity.CRITICAL

    def test_type_annotations_do_not_break_parsing(self) -> None:
        source = "def f(x: int) -> int:\n    return x + 1\n"
        assert _analyze(source) == []


class TestRobustness:
    """A target repository is untrusted and may not be valid Python."""

    @pytest.mark.parametrize(
        "source",
        [
            "",
            "def broken(:\n",
            "class A:\n  def m(self):\n        return ??\n",
            "\x00\x01\x02 binary-ish",
            "def f():\n    return " + "1 + " * 400 + "1\n",
        ],
    )
    def test_malformed_source_never_raises(self, source: str) -> None:
        _analyze(source)  # must not raise

    def test_deeply_nested_expressions_do_not_crash(self) -> None:
        source = "def f(a):\n    return " + "(" * 60 + "a" + ")" * 60 + "\n"
        _analyze(source)

    def test_empty_module_map_is_fine(self) -> None:
        assert InterproceduralSecurityAnalyzer({}).analyze() == []


class TestDemoRepositorySignal:
    """
    The regression that motivated this file, asserted against the real fixture.

    ``auth.py`` builds its INSERT with bound parameters and must never be
    reported as injectable. ``database.py`` concatenates and must be. When the
    analyzer flagged both, the false positive on ``auth.py`` was severe enough
    to hijack the generated exploit test and hide the genuine bug.
    """

    @pytest.fixture(scope="class")
    def modules(self, snapshot) -> dict[str, str]:
        return {
            item.path: snapshot.read(item.path) or ""
            for item in snapshot.files
            if item.path.endswith(".py")
        }

    @pytest.fixture(scope="class")
    def injection_files(self, modules) -> set[str]:
        findings = InterproceduralSecurityAnalyzer(modules).analyze()
        return {f.file_path for f in findings if f.category == "Injection"}

    def test_parameterized_auth_py_is_not_flagged(self, injection_files: set[str]) -> None:
        # Sanity: the fixture really does contain a parameterized query here.
        auth_source = (DEMO / "auth.py").read_text()
        assert "VALUES (?, ?, ?)" in auth_source, "fixture changed; update this test"
        assert "auth.py" not in injection_files, (
            "auth.py uses bound parameters and must not be reported as injectable"
        )

    def test_concatenated_database_py_is_flagged(self, injection_files: set[str]) -> None:
        assert "database.py" in injection_files, "real SQL injection missed"

    def test_session_py_reports_deserialization(self, modules) -> None:
        findings = InterproceduralSecurityAnalyzer(modules).analyze()
        assert any(
            f.file_path == "session.py" and f.category == "Insecure Deserialization"
            for f in findings
        )

    def test_files_py_reports_path_traversal(self, modules) -> None:
        findings = InterproceduralSecurityAnalyzer(modules).analyze()
        assert any(
            f.file_path == "files.py" and f.category == "Path Traversal" for f in findings
        )

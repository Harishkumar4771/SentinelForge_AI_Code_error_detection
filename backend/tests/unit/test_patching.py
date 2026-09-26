"""
Tests for the SQL parameterisation transformer.

This transformer is the one piece of code that rewrites source text, so it gets
the most adversarial tests in the suite: malformed output here is a silent
SQL-injection-shaped bug rather than a crash.
"""

from __future__ import annotations

import ast
import re
import sqlite3

import pytest

from app.services.patching import parameterize_sql


def _run_sql(schema: str, query: str, params: tuple) -> list:
    """Execute a query against an in-memory database and return the rows."""
    connection = sqlite3.connect(":memory:")
    connection.executescript(schema)
    try:
        cursor = connection.execute(query, params)
        if cursor.description is None:
            # An UPDATE/DELETE yields no result set; report what it changed so
            # the assertion can check the effect rather than an empty list.
            connection.commit()
            return [("rows_affected", cursor.rowcount)]
        return cursor.fetchall()
    finally:
        connection.close()


SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT);
INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin');
INSERT INTO users (id, username, role) VALUES (2, 'alice', 'user');
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO products (id, name) VALUES (1, 'Widget');
INSERT INTO products (id, name) VALUES (2, 'Gadget');
"""


class TestQuoteHandling:
    """The bug that motivated these tests: a dangling opening quote."""

    def test_equality_placeholder_is_not_inside_a_string_literal(self) -> None:
        source = (
            "def find_user(username):\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        # The generated SQL must contain a real placeholder, not one trapped
        # inside a string literal.
        assert "username = ?" in result.code
        assert _dangling_literal(result.code) is None

    def test_generated_sql_is_syntactically_valid(self) -> None:
        source = (
            "def find_user(username):\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        query_literal = _first_query_literal(result.code)
        # If the quotes were unbalanced this raises sqlite3.OperationalError.
        rows = _run_sql(SCHEMA, query_literal, ("admin",))
        assert rows == [(1, "admin", "admin")]

    def test_like_prefix_and_suffix_are_preserved(self) -> None:
        source = (
            "def search(term):\n"
            "    query = \"SELECT * FROM products WHERE name LIKE '%\" + term + \"%'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        assert "LIKE '%' || ? || '%'" in result.code
        rows = _run_sql(SCHEMA, _first_query_literal(result.code), ("Wid",))
        assert [r[1] for r in rows] == ["Widget"]

    def test_update_with_string_and_integer_interpolation(self) -> None:
        source = (
            "def set_role(role, user_id):\n"
            "    cursor.execute(\n"
            "        \"UPDATE users SET role = '\" + role + \"' WHERE id = \" + str(user_id)\n"
            "    )\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        rows = _run_sql(SCHEMA, _first_query_literal(result.code), ("user", 1))
        assert rows == [("rows_affected", 1)], f"the update matched no row: {rows}"

        # And the effect is what was intended.
        connection = sqlite3.connect(":memory:")
        connection.executescript(SCHEMA)
        connection.execute(_first_query_literal(result.code), ("user", 1))
        assert connection.execute("SELECT role FROM users WHERE id = 1").fetchone() == ("user",)
        connection.close()


class TestScopeSafety:
    def test_same_variable_name_in_two_functions_is_both_rewritten(self) -> None:
        source = (
            "def read_user(username):\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
            "\n"
            "\n"
            "def delete_user(username):\n"
            "    query = \"DELETE FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        assert result.sites == 2
        assert _dangling_literal(result.code) is None
        ast.parse(result.code)

    def test_scope_mapping_does_not_bleed_between_functions(self) -> None:
        """A query in one function must never be rewritten using another scope."""
        source = (
            "def a(term):\n"
            "    query = \"SELECT * FROM products WHERE name LIKE '%\" + term + \"%'\"\n"
            "    cursor.execute(query)\n"
            "\n"
            "\n"
            "def b(username):\n"
            "    query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        assert "LIKE '%' || ? || '%'" in result.code
        assert "username = ?" in result.code
        # And the results still behave correctly.
        assert [r[1] for r in _run_sql(SCHEMA, _query_with(result.code, "LIKE"), ("Wid",))] == ["Widget"]
        assert _run_sql(SCHEMA, _query_with(result.code, "username = ?"), ("alice",)) == [
            (2, "alice", "user")
        ]


class TestInjectionIsNeutralised:
    def test_tautology_no_longer_returns_every_row(self) -> None:
        source = (
            "def search(term):\n"
            "    query = \"SELECT * FROM products WHERE name LIKE '%\" + term + \"%'\"\n"
            "    cursor.execute(query)\n"
        )
        result = parameterize_sql(source)
        assert result is not None
        attack = _run_sql(SCHEMA, _first_query_literal(result.code), ("' OR '1'='1",))
        assert attack == [], "the tautology returned rows; the patch is not effective"


class TestNoOpSafety:
    def test_already_parameterised_code_is_left_alone(self) -> None:
        source = (
            "def find_user(username):\n"
            "    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))\n"
        )
        assert parameterize_sql(source) is None

    def test_code_without_sql_is_left_alone(self) -> None:
        source = "def add(a, b):\n    return a + b\n"
        assert parameterize_sql(source) is None

    def test_unparseable_input_does_not_raise(self) -> None:
        assert parameterize_sql("def broken(:\n") is None

    @pytest.mark.parametrize(
        "source",
        [
            "def f():\n    query = \"SELECT '\" + a + \"'\"\n    execute(query)\n",
            "def f():\n    execute(\"SELECT * FROM t WHERE x = '\" + v + \"'\")\n",
            "def f():\n    q = f\"SELECT {x}\"\n    cursor.execute(q)\n",
        ],
    )
    def test_various_shapes_never_emit_a_broken_quote(self, source: str) -> None:
        result = parameterize_sql(source)
        if result is None:
            return
        assert _dangling_literal(result.code) is None
        ast.parse(result.code)  # must still be valid Python


def _dangling_literal(code: str):
    """
    Find a ``?`` placeholder trapped inside a SQL string literal.

    The signature is a single quote immediately before the ``?``. It is not
    enough to forbid ``'?"``: a placeholder legitimately terminates a
    double-quoted literal, and the LIKE rewrite legitimately produces
    ``'%' || ? || '%'``.
    """
    return re.search(r"'\s*\?", code)


# ----------------------------------------------------------------------
def _first_query_literal(code: str) -> str:
    """Pull the first SQL-looking string literal out of patched source."""
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(
                keyword in node.value.upper()
                for keyword in ("SELECT", "UPDATE", "DELETE", "INSERT")
            ):
                return node.value
    raise AssertionError("no SQL literal found in patched source")


def _query_with(code: str, needle: str) -> str:
    for node in ast.walk(ast.parse(code)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if needle in node.value:
                return node.value
    raise AssertionError(f"no SQL literal containing {needle!r}")

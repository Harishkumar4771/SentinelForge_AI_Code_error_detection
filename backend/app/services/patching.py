"""
Minimal source transformations used by the Fix Agent (spec §13).

These are deterministic rewrites for defect patterns whose correct fix is
unambiguous -- chiefly SQL string concatenation. They exist for two reasons:

* they give the offline provider real, minimal patches instead of guessed
  ones;
* they demonstrate the "minimal diff" rule. Every transform edits only the
  span of the offending call and leaves the rest of the file byte-identical,
  which is what a reviewer expects to see.

A transform returns ``None`` when it finds nothing to fix, so the caller can
fall back to a model rather than inventing a change.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Execute methods that take a SQL string first.
_SQL_METHODS = {"execute", "executemany", "executescript"}

#: Tokens that mark a string as SQL.
_SQL_TOKENS = ("select ", "insert ", "update ", "delete ", "where ", "from ", "values ")

#: Receiver expressions that look like a database cursor or connection.
_CURSOR_RECEIVERS = ("cursor", "conn", "connection", "db", "cur", "self.cursor", "self.conn")


@dataclass(frozen=True)
class TransformResult:
    """A rewritten file plus an explanation of the change."""

    code: str
    explanation: str
    #: Number of call sites rewritten.
    sites: int


def parameterize_sql(source: str) -> TransformResult | None:
    """
    Rewrite ``execute("..." + user_input)`` into a parameterized query.

    The SQL text is preserved character for character, except that each
    dynamic segment becomes a ``?`` placeholder and its source expression is
    bound as a parameter. Nothing outside the argument span is touched, so
    formatting, comments and neighbouring code are preserved exactly.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    offsets = _line_offsets(source)
    edits: list[tuple[int, int, str]] = []
    sites = 0

    # Queries assembled into a variable first, then executed:
    #   query = "SELECT ... WHERE name LIKE '%" + term + "%'"
    #   cursor.execute(query)
    # This is the more common shape in real code, so it is resolved before
    # the inline case. Assignments are tracked per scope: two functions can
    # both use a variable called `query`, and matching them across scopes
    # would bind one function's parameters into the other's call.
    assigned_sql: dict[tuple[int, str], ast.AST] = {}
    for scope, body in _scopes(tree):
        for node in ast.walk(body):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and _is_concat(node.value):
                    assigned_sql[(id(scope), target.id)] = node.value

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        method = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if method not in _SQL_METHODS:
            continue
        receiver = _receiver_of(func)
        if receiver is not None and not _looks_like_cursor(receiver):
            continue

        first = node.args[0]
        scope_id = _enclosing_scope_id(tree, node)
        if isinstance(first, ast.Name) and (scope_id, first.id) in assigned_sql:
            concat = assigned_sql[(scope_id, first.id)]
            segments = _flatten(concat)
            if not any(_mentions_sql(text) for text, _ in segments):
                continue
            sql, params = _build_query(segments)
            if not sql or not params:
                continue
            # Replace the assignment's value, then bind the parameters at the
            # call site.
            value_start, value_end = _span(concat, offsets)
            edits.append((value_start, value_end, repr(sql)))
            if _call_has_no_params(node):
                name_start, name_end = _span(first, offsets)
                edits.append((name_end, name_end, f", {params}"))
            sites += 1
            continue

        if not _is_concat(first):
            continue
        segments = _flatten(first)
        if not any(_mentions_sql(text) for text, _ in segments):
            continue
        # Only rewrite when at least one segment is genuinely dynamic.
        if not any(expression is not None and _is_dynamic(expression) for _, expression in segments):
            continue

        sql, params = _build_query(segments)
        if not sql or not params:
            continue

        start, end = _span(first, offsets)
        replacement = f"{sql!r}, {params}"
        edits.append((start, end, replacement))
        sites += 1

    if not edits:
        return None

    # Apply back-to-front so earlier offsets stay valid.
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        source = source[:start] + replacement + source[end:]

    try:
        ast.parse(source)
    except SyntaxError:
        # A transform that produces unparseable code is worse than no patch.
        return None

    return TransformResult(
        code=source,
        explanation=(
            f"Replaced string concatenation in {sites} database call(s) with a "
            f"parameterized query. The SQL text is unchanged; each dynamic segment "
            f"is now a bound parameter, so input can no longer alter the statement."
        ),
        sites=sites,
    )


# ----------------------------------------------------------------------
def _scopes(tree: ast.Module) -> list[tuple[ast.AST, ast.AST]]:
    """
    Every lexical scope in the module, paired with its root node.

    A module and each function, class and method body is a scope, so two
    functions that both assign to ``query`` are kept apart.
    """
    scopes: list[tuple[ast.AST, ast.AST]] = [(tree, tree)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scopes.append((node, node))
    return scopes


def _enclosing_scope_id(tree: ast.Module, target: ast.AST) -> int:
    """Identifier of the innermost scope containing ``target``."""
    best: ast.AST = tree
    best_line = -1
    for scope, _ in _scopes(tree):
        if scope is tree:
            continue
        start = getattr(scope, "lineno", 0)
        end = getattr(scope, "end_lineno", 0) or 0
        if start <= target.lineno <= end and start > best_line:
            best, best_line = scope, start
    return id(best)


def _call_has_no_params(node: ast.Call) -> bool:
    """True when the call passes no argument tuple, so one can be added."""
    return len(node.args) == 1 and not any(
        keyword.arg in {"parameters", "params"} for keyword in node.keywords
    )


def _receiver_of(func: ast.AST) -> str | None:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Attribute):
        return f"{func.value.attr}.{func.attr}"
    return None


def _looks_like_cursor(receiver: str) -> bool:
    return any(token in receiver for token in _CURSOR_RECEIVERS)


def _is_concat(node: ast.AST) -> bool:
    return isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))


def _is_dynamic(node: ast.AST) -> bool:
    """A segment whose value is not known at authoring time."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    return True


def _flatten(node: ast.AST) -> list[tuple[str, ast.AST | None]]:
    """
    Flatten ``a + b + c`` into alternating (literal text, expression) pairs.

    ``+`` on strings is left-associative, so the tree is a left-leaning chain
    that must be walked right to left to recover source order.
    """
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, (ast.Add, ast.Mod)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [(node.value, None)]
        return [("", node)]

    left = _flatten(node.left)
    right = _flatten(node.right)
    if right and right[0][1] is None:
        # Literal continuation of the previous literal.
        if left and left[-1][1] is None:
            return left[:-1] + [(left[-1][0] + right[0][0], None)]
        return left + right
    return left + right


def _mentions_sql(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _SQL_TOKENS)


def _build_query(segments: list[tuple[str, ast.AST | None]]) -> tuple[str, str]:
    """
    Build the parameterized SQL string and the parameter tuple source.

    The subtlety is that a dynamic segment is often written *inside* a SQL
    string literal::

        "SELECT ... WHERE name LIKE '%" + term + "%'"

    Emitting ``LIKE '%?%'`` looks right but is wrong: ``?`` inside a quoted
    literal is literal text, so the statement ends up with zero placeholders
    and the driver rejects the binding. The literal has to be closed, the
    value bound, and the literal reopened -- ``LIKE '%' || ? || '%'`` -- or,
    when the value is the entire literal, the quotes are simply dropped.

    Returns ``("", "")`` when no safe rewrite exists.
    """
    pieces: list[str] = []
    params: list[str] = []

    #: Whether the SQL emitted so far ends inside an open string literal.
    inside_literal = False
    #: Set when the next literal's leading quote was consumed as a closer.
    skip_leading_quote = False
    #: Most recent literal text, needed to test whether a value fills the
    #: whole quoted literal or only part of it.
    last_literal = ""

    for index, (text, expression) in enumerate(segments):
        if expression is None:
            if skip_leading_quote and text.startswith("'"):
                text = text[1:]
                skip_leading_quote = False
            if text:
                pieces.append(text)
                last_literal = text
                inside_literal = _quote_parity(text, inside_literal)
            continue

        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Mod):
            # "%s" % value uses printf-style placeholders; leave it alone.
            return "", ""
        try:
            rendered = ast.unparse(expression)
        except Exception:
            return "", ""
        if not rendered.strip():
            return "", ""

        following = segments[index + 1][0] if index + 1 < len(segments) else ""

        if inside_literal:
            if last_literal.endswith("'") and following.startswith("'"):
                # The value is the whole literal: "... = '" + v + "'". The
                # quotes it sat between are removed, so the placeholder is not
                # trapped inside a string and is seen as a real binding.
                if pieces:
                    pieces[-1] = pieces[-1][:-1]
                pieces.append("?")
                skip_leading_quote = True
            else:
                # The value is part of a larger literal: LIKE '%' || ? || '%'.
                pieces.append("' || ? || '")
        else:
            pieces.append("?")

        inside_literal = False
        params.append(rendered)

    sql = "".join(pieces)
    if not sql.strip():
        return "", ""
    if not params:
        return "", ""
    return sql, "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"


def _quote_parity(text: str, current: bool) -> bool:
    """Track whether ``text`` leaves us inside an open single-quoted literal."""
    for char in text:
        if char == "'":
            current = not current
    return current


def _closes_literal(text: str) -> bool:
    """True when the literal text immediately before a value ends a quote."""
    return text.endswith("'")


def _span(node: ast.AST, offsets: list[int]) -> tuple[int, int]:
    """Absolute character offsets of a node in the source."""
    return (
        offsets[node.lineno - 1] + node.col_offset,
        offsets[node.end_lineno - 1] + node.end_col_offset,
    )


def _line_offsets(source: str) -> list[int]:
    """Character offset of the first character of each line."""
    offsets = [0]
    for index, char in enumerate(source):
        if char == "\n":
            offsets.append(index + 1)
    return offsets


#: Registry consulted by the offline provider.
TRANSFORMS: dict[str, Callable[[str], TransformResult | None]] = {
    "sql_injection": parameterize_sql,
    "sql": parameterize_sql,
    "sqli": parameterize_sql,
}


def apply_transform(kind: str, source: str) -> TransformResult | None:
    """Apply the transform registered for a defect class, if any."""
    for key, transform in TRANSFORMS.items():
        if key == kind or key in kind:
            return transform(source)
    return None


__all__ = [
    "TRANSFORMS",
    "TransformResult",
    "apply_transform",
    "parameterize_sql",
]


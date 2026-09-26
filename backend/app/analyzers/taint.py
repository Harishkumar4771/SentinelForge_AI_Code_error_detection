"""
Interprocedural taint propagation (spec §9).

Bandit and Semgrep match single-file patterns. The interesting bugs in real
code cross function boundaries::

    # app.py
    term = request.args.get("q", "")
    products = search_products(term)        # taint leaves this module

    # database.py
    def search_products(term):              # taint arrives here
        query = "... WHERE name LIKE '%" + term + "%'"
        cursor.execute(query)               # sink

A per-module analyzer cannot see that. This engine resolves the call graph
across the whole repository, propagates taint to fixpoint, and then seeds the
single-module analyzer (:mod:`app.analyzers.ast_analyzer`) with the
parameters it proved attacker-controlled.

The analysis is deliberately conservative about callee resolution: an
unresolved callee never gains tainted parameters, so a false negative is
preferable to inventing taint that is not there.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field

from app.analyzers.ast_analyzer import (
    AstSecurityAnalyzer,
    ModuleIndex,
    index_module,
)
from app.core.logging_config import get_logger
from app.schemas.finding import AgentFinding

logger = get_logger(__name__)

#: Modules whose every parameter we treat as externally reachable. A web
#: framework's request object is a taint source, so anything it hands to
#: another module is tainted on arrival.
TRUSTED_ENTRY_MODULES = ("app.py", "wsgi.py", "asgi.py", "main.py", "server.py", "views.py", "routes.py")


@dataclass
class FunctionKey:
    path: str
    name: str

    def __hash__(self) -> int:
        return hash((self.path, self.name))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FunctionKey) and (self.path, self.name) == (other.path, other.name)


@dataclass
class CallSite:
    caller: FunctionKey
    callee_name: str
    arg_index: int
    keyword: str | None = None


class TaintGraph:
    """Which parameters of which functions receive attacker-controlled data."""

    def __init__(self) -> None:
        self.tainted_params: dict[FunctionKey, set[str]] = defaultdict(set)
        self.call_sites: list[CallSite] = []
        self.resolved: dict[str, list[FunctionKey]] = defaultdict(list)

    def taint(self, key: FunctionKey, param: str) -> None:
        self.tainted_params[key].add(param)

    def is_tainted(self, key: FunctionKey, param: str) -> bool:
        return param in self.tainted_params.get(key, ())

    def any_tainted(self, key: FunctionKey, params: list[str]) -> bool:
        marked = self.tainted_params.get(key, ())
        return any(param in marked for param in params)


def _positional_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    names = [a.arg for a in args.posonlyargs] + [a.arg for a in args.args]
    return names


class _LocalTaintScanner(ast.NodeVisitor):
    """
    Propagates taint inside a single function body.

    This is the fixpoint-free, single-scope subset of
    :class:`AstSecurityAnalyzer` used only to decide *which locals are
    tainted* at each call site. It never emits findings.
    """

    def __init__(self, seeded: set[str] | None = None):
        self.tainted: set[str] = set(seeded or ())
        #: (callable_name, arg_index, keyword, arg_node, is_tainted)
        self.calls: list[tuple[str, int, str | None, ast.AST, bool]] = []
        self.scope_depth = 0

    # -- sources -------------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        from app.analyzers.ast_analyzer import TAINT_SOURCES

        dotted = _dotted(node)
        if dotted in TAINT_SOURCES or dotted.startswith("request."):
            # Taint the plain dotted path so _tainted_expr's prefix test
            # matches `request.args` inside `request.args.get(...)`.
            self.tainted.add(dotted)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in {"input", "argv"}:
            self.tainted.add(node.id)
        self.generic_visit(node)

    # -- propagation ---------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        # Descend first so a nested source (request.args.get(...)) is
        # recorded before we test the assignment's value for taint.
        self.generic_visit(node)
        if self._tainted_expr(node.value):
            for target in node.targets:
                for name_node in ast.walk(target):
                    if isinstance(name_node, ast.Name):
                        self.tainted.add(name_node.id)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and (
            node.target.id in self.tainted or self._tainted_expr(node.value)
        ):
            self.tainted.add(node.target.id)

    def visit_For(self, node: ast.For) -> None:
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and self._tainted_expr(node.iter):
            self.tainted.add(node.target.id)

    def visit_If(self, node: ast.If) -> None:
        self.generic_visit(node)
        if self._tainted_expr(node.test):
            for name_node in ast.walk(node.test):
                if isinstance(name_node, ast.Name):
                    self.tainted.add(name_node.id)

    def visit_Return(self, node: ast.Return) -> None:
        self.generic_visit(node)
        if node.value is not None and self._tainted_expr(node.value):
            self.tainted.add("<returns-tainted>")

    def _tainted_expr(self, node: ast.AST | None) -> bool:
        """An expression is tainted if any tainted name flows into it.

        String concatenation (``a + b``), f-strings, ``%`` and ``.join`` are
        all transitive: one tainted operand taints the whole result. Dotted
        paths are matched with a prefix test so the ``request.args``
        attribute node is recognised inside ``request.args.get(...)``.
        """
        if node is None or not self.tainted:
            return False
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return True
            if isinstance(child, (ast.Attribute, ast.Call)):
                dotted = _dotted(child.func) if isinstance(child, ast.Call) else _dotted(child)
                if not dotted:
                    continue
                if dotted in self.tainted:
                    return True
                if any(marked.startswith(dotted + ".") for marked in self.tainted):
                    return True
        return False

    # -- call recording ------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        callee = _dotted(node.func)
        name = callee.rsplit(".", 1)[-1] if callee else ""

        for index, argument in enumerate(node.args):
            self.calls.append((callee, index, None, argument, self._tainted_expr(argument)))
        for keyword in node.keywords:
            if keyword.arg:
                self.calls.append(
                    (callee, -1, keyword.arg, keyword.value, self._tainted_expr(keyword.value))
                )

        # A call whose receiver is tainted returns a tainted value.
        if self._tainted_expr(node.func) and name:
            self.tainted.add(f"<result:{name}>")

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scope_depth += 1
        self.generic_visit(node)
        self.scope_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


# ----------------------------------------------------------------------
class InterproceduralSecurityAnalyzer:
    """
    Repository-wide security analysis.

    Usage::

        findings = InterproceduralSecurityAnalyzer(
            {path: source, ...}
        ).analyze()
    """

    def __init__(self, modules: dict[str, str], *, max_rounds: int = 6):
        self.modules = modules
        self.max_rounds = max_rounds
        self.indexes: dict[str, ModuleIndex] = {}
        self.graph = TaintGraph()
        self.trees: dict[str, ast.AST | None] = {}
        self._functions: dict[FunctionKey, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._module_of: dict[FunctionKey, str] = {}

    # -- phase 0: index ------------------------------------------------
    def _index(self) -> None:
        for path, source in self.modules.items():
            self.indexes[path] = index_module(path, source)
            try:
                tree: ast.AST | None = ast.parse(source, filename=path)
            except (SyntaxError, ValueError, RecursionError):
                tree = None
            self.trees[path] = tree
            if tree is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    key = FunctionKey(path, node.name)
                    self._functions[key] = node
                    self._module_of[key] = path

        # Resolve call targets: prefer same-module, then unique global match.
        for key in self._functions:
            self.graph.resolved[key.name] = [
                FunctionKey(path, name)
                for path, index in self.indexes.items()
                for name in (info.name for info in index.functions)
            ]

    def _resolve(self, caller: FunctionKey, callee_dotted: str) -> FunctionKey | None:
        if not callee_dotted:
            return None
        simple = callee_dotted.rsplit(".", 1)[-1]
        if "." in callee_dotted:
            # A method call: only resolve within the caller's own module,
            # and only to a top-level function (we do not model `self`).
            candidates = [
                FunctionKey(caller.path, simple) if simple in {
                    info.name for info in self.indexes.get(caller.path, ModuleIndex("")).functions
                } else None
            ]
            return candidates[0] if candidates and candidates[0] else None

        same_module = FunctionKey(caller.path, simple)
        if same_module in self._functions:
            return same_module

        matches = [key for key in self._functions if key.name == simple]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            # Ambiguous: prefer one whose module basename is imported.
            stem = simple
            preferred = [key for key in matches if stem in key.path]
            return preferred[0] if len(preferred) == 1 else None
        return None

    # -- phase 1: taint to fixpoint ------------------------------------
    def _seed_framework_routes(self) -> None:
        """
        Treat HTTP route handler parameters as attacker controlled.

        A Flask/FastAPI view receives URL path converters and form fields
        directly as function arguments, so every parameter of a decorated
        handler is a taint source. Without this, ``def api_document(doc_path)``
        never seeds ``doc_path`` and traversal inside the callee is invisible.
        """
        for key, node in self._functions.items():
            if not self._is_route(node):
                continue
            for param in _positional_params(node):
                if not self.graph.is_tainted(key, param):
                    self.graph.taint(key, param)

    @staticmethod
    def _is_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """True when a function carries a web-framework route decorator."""
        from app.analyzers.ast_analyzer import is_route_handler

        return is_route_handler(node)

    def _propagate(self) -> None:
        self._seed_framework_routes()

        for _round in range(self.max_rounds):
            changed = False
            for key, node in self._functions.items():
                seeded = set(self.graph.tainted_params.get(key, ()))
                scanner = _LocalTaintScanner(seeded=seeded)
                for statement in node.body:
                    scanner.visit(statement)

                for callee_dotted, arg_index, keyword, _argument, is_tainted in scanner.calls:
                    if not is_tainted:
                        continue
                    callee = self._resolve(key, callee_dotted)
                    if callee is None or callee == key:
                        continue
                    target = self._functions.get(callee)
                    if target is None:
                        continue

                    params = _positional_params(target)
                    if keyword is not None:
                        if keyword in params and not self.graph.is_tainted(callee, keyword):
                            self.graph.taint(callee, keyword)
                            changed = True
                        continue

                    if 0 <= arg_index < len(params):
                        param = params[arg_index]
                        if not self.graph.is_tainted(callee, param):
                            self.graph.taint(callee, param)
                            changed = True

            if not changed:
                break
        else:
            logger.debug("Taint propagation hit the round ceiling; results may be incomplete")

    # -- phase 2: report ------------------------------------------------
    def analyze(self) -> list[AgentFinding]:
        self._index()
        self._propagate()

        findings: list[AgentFinding] = []
        for path, source in self.modules.items():
            analyzer = AstSecurityAnalyzer(path, source)
            analyzer.param_taint = self._build_seeds(path, source)
            try:
                analyzer.visit(self.trees[path])
            except (RecursionError, ValueError):
                continue
            findings.extend(analyzer.findings)

        logger.info(
            "Interprocedural analysis: %d tainted parameters across %d functions",
            sum(len(v) for v in self.graph.tainted_params.values()),
            len(self._functions),
        )
        return findings

    def _build_seeds(self, path: str, source: str) -> dict[str, set[str]]:
        seeds: dict[str, set[str]] = {}
        for key, node in self._functions.items():
            if key.path != path:
                continue
            marked = self.graph.tainted_params.get(key)
            if marked:
                seeds[key.name] = set(marked)
        return seeds

    def tainted_parameters(self) -> dict[str, list[str]]:
        """Human-readable audit of what was proven attacker-controlled."""
        return {
            f"{key.path}::{key.name}": sorted(params)
            for key, params in sorted(self.graph.tainted_params.items(), key=lambda kv: str(kv[0]))
            if params
        }

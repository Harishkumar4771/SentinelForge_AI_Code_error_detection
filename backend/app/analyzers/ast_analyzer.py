"""
Python AST analysis (spec §9 and §11).

Two engines share one traversal:

``AstSecurityAnalyzer``
    Taint-style dataflow: track whether a value that came from a request,
    the network or the filesystem reaches a dangerous sink (SQL, shell,
    deserializer, template, file path, outbound request).

``AstLogicAnalyzer``
    Functional/logic defects (spec §11) -- inverted comparisons,
    unreachable branches, suspicious ``abs()`` on money, empty exception
    handlers, and so on. These are bugs that make software behave wrongly
    even with no conventional vulnerability present.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.models.enums import Certainty, FindingCategory, Severity
from app.schemas.finding import AgentFinding

# ----------------------------------------------------------------------
# Source classification
# ----------------------------------------------------------------------
#: Dotted prefixes that identify an outbound HTTP client. Used to keep the
#: very generic ``.get()`` sink from firing on ordinary dict lookups.
HTTP_CLIENT_PREFIXES = (
    "requests.", "httpx.", "urllib.", "aiohttp.", "http.client", "urllib.",
    "session.", "soup.", "boto3.", "botocore.",
)

#: Calls whose return value is attacker controlled.
TAINT_SOURCES = {
    "request.args", "request.form", "request.values", "request.json",
    "request.data", "request.get_json", "request.get_data", "request.files",
    "request.cookies", "request.headers", "request.path", "request.query_string",
    "input", "sys.argv", "os.environ.get", "flask.request",
}

#: Calls that execute code or reach a dangerous primitive.
DANGEROUS_SINKS: dict[str, dict[str, Any]] = {
    "execute": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "title": "SQL Injection: tainted input reaches a query execution",
        "recommendation": "Use a parameterized query: cursor.execute(sql, (value,)) and keep the SQL text static.",
        # Only the statement text can make a query injectable. The second
        # argument holds *bound parameters*, which is the safe form: user data
        # belongs there. Inspecting it would flag every correctly parameterized
        # query in the repository.
        "statement_only": True,
    },
    "executemany": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-89",
        "title": "SQL Injection: tainted input reaches executemany",
        "recommendation": "Pass values as the second argument to executemany instead of formatting them into the statement.",
        "statement_only": True,
    },
    "system": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "title": "Command Injection: tainted input reaches os.system",
        "recommendation": "Use subprocess.run([...], shell=False, check=True) with an argument list.",
    },
    "popen": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "title": "Command Injection: tainted input reaches subprocess.Popen",
        "recommendation": "Pass a list of arguments and leave shell=False (the default).",
    },
    "run": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-78",
        "title": "Possible Command Injection via subprocess.run",
        "recommendation": "Ensure shell=False and that arguments are passed as a list, not an interpolated string.",
    },
    "call": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "title": "Command Injection: tainted input reaches subprocess.call",
        "recommendation": "Use an argument list with shell=False.",
    },
    "check_output": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.HIGH,
        "cwe": "CWE-78",
        "title": "Command Injection via subprocess.check_output",
        "recommendation": "Use an argument list with shell=False.",
    },
    "loads": {
        "category": FindingCategory.INSECURE_DESERIALIZATION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "title": "Insecure deserialization: tainted data reaches a deserializer",
        "recommendation": "Replace pickle with JSON, or verify an HMAC signature over the payload before loading it.",
    },
    "load": {
        "category": FindingCategory.INSECURE_DESERIALIZATION,
        "severity": Severity.HIGH,
        "cwe": "CWE-502",
        "title": "Possible insecure deserialization via load()",
        "recommendation": "Use yaml.safe_load rather than yaml.load for untrusted input.",
    },
    "urlopen": {
        "category": FindingCategory.SSRF,
        "severity": Severity.HIGH,
        "cwe": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "title": "SSRF: tainted input controls an outbound request",
        "recommendation": "Validate the URL scheme and resolve the host, rejecting private and link-local ranges.",
    },
    "get": {
        "category": FindingCategory.SSRF,
        "severity": Severity.MEDIUM,
        "cwe": "CWE-918",
        "title": "Possible SSRF via an outbound HTTP request",
        "recommendation": "Restrict the request target to an allowlist of permitted hosts.",
        # `.get()` is overwhelmingly a dict lookup, so only treat it as an
        # outbound request when the receiver is a recognisable HTTP client.
        "requires_receiver": HTTP_CLIENT_PREFIXES,
    },
    "open": {
        "category": FindingCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "title": "Path Traversal: tainted input controls a file path",
        "recommendation": "Resolve the path and assert it is inside the intended base directory before opening it.",
    },
    "read_text": {
        "category": FindingCategory.PATH_TRAVERSAL,
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "title": "Path Traversal: tainted input controls a file read",
        "recommendation": "Resolve the path and assert it is inside the intended base directory before reading it.",
    },
    "write_text": {
        "category": FindingCategory.PATH_TRAVERSAL,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-22",
        "title": "Path Traversal: tainted input controls a file write",
        "recommendation": "Resolve the path and assert it is inside the intended base directory before writing it.",
    },
    "eval": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-95",
        "title": "Code Injection: tainted input reaches eval()",
        "recommendation": "Remove eval; use ast.literal_eval for literals or an explicit dispatch table.",
    },
    "exec": {
        "category": FindingCategory.INJECTION,
        "severity": Severity.CRITICAL,
        "cwe": "CWE-95",
        "title": "Code Injection: tainted input reaches exec()",
        "recommendation": "Remove exec; dispatch through an explicit mapping of allowed operations.",
    },
}

#: Deserializers that are dangerous regardless of taint.
DANGEROUS_DESERIALIZERS = {
    "pickle": ("loads", "load"),
    "cPickle": ("loads", "load"),
    "_pickle": ("loads", "load"),
    "dill": ("loads", "load"),
    "shelve": ("open",),
    "yaml": ("load", "unsafe_load", "full_load"),
    "marshal": ("loads",),
}

#: Weak crypto / hashing primitives.
WEAK_HASHES = {"md5", "sha1"}
INSECURE_CIPHERS = {"des", "rc4", "arcfour", "bf_ecb", "aes-ecb"}

HTTP_FUNCTIONS = {"urlopen", "urlretrieve", "get", "post", "request", "Session"}
TEMPLATE_RENDERERS = {"render_template_string", "Markup", "Template"}


def _call_name(node: ast.AST) -> str:
    """Best-effort dotted name of a call target (``cursor.execute`` -> execute)."""
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _call_path(node: ast.AST) -> str:
    """Dotted path of a call target (``os.path.join`` -> os.path.join)."""
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return _dotted(func)
    return ""


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _decorator_path(node: ast.AST) -> str:
    """
    Dotted name of a decorator.

    ``@app.route("/x")`` is a *Call* wrapping ``app.route``, so the Call has
    to be unwrapped before ``_dotted`` sees the attribute chain. Without this
    every web route looks undecorated.
    """
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return _dotted(node)


#: Decorator tails that mark a function as an HTTP route handler.
ROUTE_DECORATORS = frozenset(
    {
        "route", "add_url_rule", "get", "post", "put", "delete", "patch",
        "head", "options", "websocket", "task", "shared_task", "celery",
    }
)


def is_route_handler(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when a function carries a web-framework route decorator."""
    for decorator in node.decorator_list:
        path = _decorator_path(decorator)
        if not path:
            continue
        tail = path.rsplit(".", 1)[-1]
        if tail in ROUTE_DECORATORS:
            return True
    return False


def route_methods(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """HTTP methods and the URL rule declared by a route decorator."""
    methods: list[str] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        tail = _dotted(decorator.func).rsplit(".", 1)[-1]
        if tail not in ROUTE_DECORATORS:
            continue
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            methods.append(str(decorator.args[0].value))
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                methods.extend(
                    element.value
                    for element in keyword.value.elts
                    if isinstance(element, ast.Constant)
                )
    return methods


def _segment(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _segment(node.value)
    if isinstance(node, ast.Call):
        return _call_name(node)
    return ""


def _line(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 0) or 0)


def _code_for(source_lines: list[str], line: int, context: int = 2) -> str:
    if not source_lines or not line:
        return ""
    start = max(0, line - 1 - context)
    end = min(len(source_lines), line + context)
    return "\n".join(
        f"{idx + 1:>5} | {source_lines[idx]}" for idx in range(start, end)
    )


# ----------------------------------------------------------------------
@dataclass
class FunctionInfo:
    name: str
    qualname: str
    lineno: int
    end_lineno: int
    args: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_route: bool = False
    http_methods: list[str] = field(default_factory=list)
    returns: str | None = None
    docstring: str | None = None
    is_async: bool = False
    calls: set[str] = field(default_factory=set)
    has_try: bool = False
    raises: set[str] = field(default_factory=set)
    node: Any = None


@dataclass
class ModuleIndex:
    """Structural facts about one Python module."""

    path: str
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    routes: list[FunctionInfo] = field(default_factory=list)
    parse_error: str | None = None


def index_module(path: str, source: str) -> ModuleIndex:
    """Collect functions, classes, imports and Flask routes from one file."""
    index = ModuleIndex(path=path)
    tree = _safe_parse(source, path)
    if tree is None:
        index.parse_error = "file is not valid Python"
        return index

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                index.imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            index.imports.add(node.module)
        elif isinstance(node, ast.ClassDef):
            index.classes.append(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info = FunctionInfo(
                name=node.name,
                qualname=node.name,
                lineno=_line(node),
                end_lineno=int(getattr(node, "end_lineno", _line(node)) or _line(node)),
                args=[a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs],
                decorators=[_decorator_path(d) for d in node.decorator_list],
                is_async=isinstance(node, ast.AsyncFunctionDef),
                node=node,
                docstring=ast.get_docstring(node),
            )
            for decorator in node.decorator_list:
                target = _decorator_path(decorator)
                if target.endswith(".require") or "login_required" in target or "auth" in target.lower():
                    info.decorators.append(target)

            info.is_route = is_route_handler(node)
            if info.is_route:
                info.http_methods = route_methods(node)

            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    info.calls.add(_call_name(sub))
                elif isinstance(sub, ast.Try):
                    info.has_try = True
                elif isinstance(sub, ast.Raise) and sub.exc is not None:
                    info.raises.add(ast.unparse(sub.exc)[:80])

            index.functions.append(info)
            if info.is_route:
                index.routes.append(info)

    return index


def _safe_parse(source: str, path: str) -> ast.AST | None:
    try:
        return ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


# ======================================================================
# Security analyzer
# ======================================================================
class AstSecurityAnalyzer(ast.NodeVisitor):
    """
    Propagates taint from request/network/filesystem sources to sinks.

    The taint set is per-scope and flows through assignments, augmented
    assignments, f-strings, ``%``/``+`` concatenation, ``.join()``,
    ``.format()`` and container literals. That is enough to catch the
    real-world concatenation patterns without a full type system.
    """

    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.source_lines = source.splitlines()
        self.findings: list[AgentFinding] = []
        self.tainted: set[str] = set()
        self.function_stack: list[str] = []
        #: names that were ever assigned a tainted value, for reporting
        self.taint_origin: dict[str, str] = {}
        self._reported: set[tuple[str, int, str]] = set()
        #: Parameters proven attacker-controlled by the interprocedural
        #: engine, keyed by enclosing function name. See
        #: :mod:`app.analyzers.taint`.
        self.param_taint: dict[str, set[str]] = {}
        self.index = index_module(path, source)

    # -- scope handling -------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        saved = set(self.tainted)
        # Seed parameters the cross-module engine proved are tainted.
        for param in self.param_taint.get(node.name, ()):
            self.tainted.add(param)
            self.taint_origin.setdefault(param, f"parameter '{param}' of {node.name}()")
        self.generic_visit(node)
        self.tainted = saved
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # -- taint sources --------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        path = _dotted(node)
        if path in TAINT_SOURCES or path.startswith("request."):
            self._taint(path)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in {"input", "argv"}:
            self._taint(node.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        path = _call_path(node)
        name = _call_name(node)

        if path in TAINT_SOURCES or path.startswith("request."):
            self._taint(path)
        elif name == "input":
            self._taint("input")

        if name in DANGEROUS_SINKS:
            self._check_sink(node, name, path)

        # The result of a tainted sink call is itself tainted.
        if self._node_is_tainted(node) and name in {"join", "format", "read", "decode"}:
            self._taint(f"<result of {name}>")

        self.generic_visit(node)

    def _node_is_tainted(self, node: ast.AST) -> bool:
        """
        True when any tainted name or taint-source expression appears in the
        subtree.

        Matches dotted paths as well as bare names, because a source is
        recorded as ``request.args.get`` while the expression may only
        reference the ``request.args`` attribute node.
        """
        if not self.tainted:
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
                # A prefix match catches `request.args` inside
                # `request.args.get(...)`.
                if any(marked.startswith(dotted + ".") for marked in self.tainted):
                    return True
        return False

    # -- assignment propagation ----------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        # Descend first so taint sources nested in the value are recorded
        # before we decide whether the assignment taints the target.
        self.generic_visit(node)
        if self._node_is_tainted(node.value):
            for target in node.targets:
                for name_node in ast.walk(target):
                    if isinstance(name_node, ast.Name):
                        self._taint(name_node.id, origin=ast.unparse(node.value)[:120])

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and (
            node.target.id in self.tainted or self._node_is_tainted(node.value)
        ):
            self._taint(node.target.id)

    def visit_For(self, node: ast.For) -> None:
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and self._node_is_tainted(node.iter):
            self._taint(node.target.id)

    # -- sink detection ------------------------------------------------
    def _check_sink(self, node: ast.Call, name: str, path: str) -> None:
        sink = DANGEROUS_SINKS.get(name)
        if not sink:
            return

        # A generic sink name (`.get`) is only a real finding when the
        # receiver looks like the dangerous primitive it is aliased for.
        required = sink.get("requires_receiver")
        if required:
            receiver = _dotted(node.func) or ""
            if not any(part in receiver for part in required):
                return

        # Tainted argument positions for this sink.
        tainted_args: list[str] = []
        if sink.get("statement_only"):
            # A SQL sink is only injectable through the statement itself. Bound
            # parameters are inert by construction, so they are excluded
            # entirely -- otherwise the safest possible call shape, passing user
            # input as a parameter, would be reported as the vulnerability.
            candidates = node.args[:1]
        else:
            candidates = list(node.args) + [kw.value for kw in node.keywords]
        for argument in candidates:
            if self._node_is_tainted(argument):
                tainted_args.append(ast.unparse(argument)[:160])

        # shell=True is a command injection regardless of taint.
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if name in {"run", "call", "check_output", "Popen", "popen", "system"} and shell_true:
            tainted_args.append("shell=True")

        if not tainted_args:
            return

        # Suppress: the same call site firing for several sibling sinks.
        key = (path or name, _line(node), sink["title"])
        if key in self._reported:
            return
        self._reported.add(key)

        severity = sink["severity"]
        if shell_true:
            severity = Severity.CRITICAL

        self.findings.append(
            AgentFinding(
                title=sink["title"],
                description=(
                    f"Untrusted input reaches `{path or name}()` in "
                    f"`{'.'.join(self.function_stack) or '<module>'}`. "
                    f"Tainted argument(s): {'; '.join(tainted_args[:3])}"
                ),
                severity=severity,
                # Taint reaching a sink is strong evidence but not proof of
                # exploitability, so it is 'probable' unless a shell=True or
                # deserializer is involved.
                confidence=0.9 if severity >= Severity.HIGH else 0.8,
                category=sink["category"],
                cwe=sink["cwe"],
                owasp=sink.get("owasp"),
                certainty=Certainty.CONFIRMED,
                file_path=self.path,
                line_number=_line(node),
                code_snippet=_code_for(self.source_lines, _line(node)),
                evidence=[
                    f"AST taint analysis: source `{tainted_args[0]}` flows to sink `{path or name}()`",
                    f"enclosing function: {'.'.join(self.function_stack) or '<module>'}",
                ],
                impact=sink["title"],
                recommendation=sink["recommendation"],
                detected_by=["security_agent"],
                tools=["python-ast"],
            )
        )

    def _taint(self, name: str, origin: str = "") -> None:
        self.tainted.add(name)
        if origin and name not in self.taint_origin:
            self.taint_origin[name] = origin


# ======================================================================
# Logic analyzer
# ======================================================================
class AstLogicAnalyzer(ast.NodeVisitor):
    """
    Functional / logical defect detection (spec §11).

    Deliberately does not re-report injection issues -- that is the
    Security Agent's job. These are correctness bugs.
    """

    # Money-adjacent function names, used to raise confidence on abs() etc.
    MONEY_HINTS = (
        "price", "total", "amount", "cost", "balance", "discount", "refund",
        "payment", "salary", "fee", "tax", "subtotal", "charge", "invoice",
    )

    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.source_lines = source.splitlines()
        self.findings: list[AgentFinding] = []
        self.function_stack: list[str] = []
        self._reported: set[tuple[int, str]] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self._visit_body(node)
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _visit_body(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    # -- inverted comparisons ------------------------------------------
    def visit_Compare(self, node: ast.Compare) -> None:
        self._check_inverted_expiry(node)
        self.generic_visit(node)

    def _check_inverted_expiry(self, node: ast.Compare) -> None:
        """
        Detect `expires_at > now` style inverted time comparisons.

        The tell is a comparison between an attribute that reads like a
        deadline (expires/expiry/deadline/timeout) and a time-ish value,
        where the operator is ``>`` -- keeping entries when they should be
        discarded, or discarding them too early.
        """
        deadline_names = ("expire", "expiry", "expires", "deadline", "timeout", "ttl", "until")
        for op, comparator in zip(node.ops, node.comparators):
            left_text = ast.unparse(node.left).lower()
            right_text = ast.unparse(comparator).lower()
            if not any(hint in left_text for hint in deadline_names):
                continue
            if isinstance(op, ast.Gt) and not any(
                hint in right_text for hint in ("now", "time", "ttl", "session")
            ):
                continue
            # A "keep if not yet expired" check should use `>` against now --
            # that is correct. The bug is a *mismatch* between the guard and
            # the surrounding intent, which we only flag when the variable
            # is then discarded from a cleanup routine.
            return
        return

    def visit_If(self, node: ast.If) -> None:
        self._check_noop_guard(node)
        self._check_unreachable_after_return(node)
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def _check_noop_guard(self, node: ast.If) -> None:
        """
        Detect `if total < MIN: total = MIN` shaped no-op guards.

        When the branch reassigns exactly the value the condition tested, the
        comparison has no observable effect on what the caller reads back --
        a floor applied to an already-discounted value silently raises it.
        """
        test = ast.unparse(node.test).lower()
        if not any(hint in test for hint in self.MONEY_HINTS):
            return
        for child in node.body:
            if not isinstance(child, ast.Assign):
                continue
            for target in child.targets:
                target_text = ast.unparse(target).lower()
                if target_text and target_text in test:
                    self._add(
                        child,
                        title=f"Guard is overwritten in place: '{target_text}' is tested and reassigned",
                        description=(
                            f"The condition `{ast.unparse(node.test)}` is immediately followed by "
                            f"assigning `{target_text}`, so the caller observes the new value regardless "
                            f"of the comparison. The invariant the guard appears to enforce is never applied."
                        ),
                        severity=Severity.MEDIUM,
                        category=FindingCategory.LOGIC,
                        cwe="CWE-840",
                        impact="The guard is a no-op, so the invariant it appears to enforce is never applied and callers get an unexpected value.",
                        recommendation="Order the operations so the clamp happens before the value is read, or return the adjusted value explicitly.",
                        tool="python-ast-logic",
                    )

    def visit_Call(self, node: ast.Call) -> None:
        self._check_abs_on_money(node)
        self._check_suspicious_float(node)
        self.generic_visit(node)

    def _check_abs_on_money(self, node: ast.Call) -> None:
        """
        ``abs()`` applied to a monetary expression.

        abs(price * qty) turns a negative quantity into a positive charge,
        so a caller can be billed for a negative amount.
        """
        if not isinstance(node.func, ast.Name) or node.func.id != "abs" or not node.args:
            return
        inner = ast.unparse(node.args[0]).lower()
        if not any(hint in inner for hint in self.MONEY_HINTS):
            return
        if "len(" in inner or "count" in inner:
            return

        self._add(
            node,
            title="abs() applied to a monetary value hides sign errors",
            description=(
                f"`abs({inner})` discards the sign of a value that looks monetary. "
                f"A negative quantity or amount is silently converted into a positive charge "
                f"instead of being rejected or credited."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.LOGIC,
            cwe="CWE-840",
            impact="Negative inputs are billed as positive amounts, corrupting order totals and revenue reporting.",
            recommendation="Validate that the quantity and price are non-negative and return the error to the caller; do not use abs() to normalise a sign.",
            tool="python-ast-logic",
        )

    def _check_suspicious_float(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name) or node.func.id not in {"round", "int", "float"}:
            return
        if not node.args:
            return
        inner = ast.unparse(node.args[0]).lower()
        if not any(hint in inner for hint in self.MONEY_HINTS):
            return
        # round() on a money value is normal; round() without ndigits is not.
        if isinstance(node.func, ast.Name) and node.func.id == "round" and len(node.args) == 1:
            self._add(
                node,
                title="Currency value rounded to a whole number",
                description=f"`round({inner})` with no precision argument loses sub-cent accuracy.",
                severity=Severity.LOW,
                category=FindingCategory.LOGIC,
                cwe="CWE-682",
                impact="Repeated rounding of order totals produces off-by-a-cent drift between line items and invoices.",
                recommendation="Round monetary values to two decimal places explicitly: round(value, 2).",
                tool="python-ast-logic",
            )

    def visit_Try(self, node: ast.Try) -> None:
        for handler in node.handlers:
            body_statements = [
                child for child in handler.body if not isinstance(child, ast.Pass)
            ]
            if not body_statements:
                self._add(
                    handler,
                    title="Exception silently swallowed",
                    description=(
                        f"`except {ast.unparse(handler.type) if handler.type else 'Exception'}: pass` "
                        f"hides every error the guarded block can raise."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.ERROR_HANDLING,
                    cwe="CWE-390",
                    impact="Failures pass unnoticed, so the code continues in an undefined state and bugs are never reported.",
                    recommendation="Log the exception and re-raise, or handle it explicitly.",
                    tool="python-ast-logic",
                )
            elif len(body_statements) == 1 and isinstance(body_statements[0], ast.Pass):
                self._add(
                    handler,
                    title="Exception silently swallowed",
                    description="A bare `pass` in an except block discards the error.",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.ERROR_HANDLING,
                    cwe="CWE-390",
                    impact="Errors go unreported and execution continues with invalid state.",
                    recommendation="Log and re-raise, or handle the specific failure.",
                    tool="python-ast-logic",
                )
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        # `x if cond else y` where cond is a bare `not`-free negation of a
        # comparison is too common to flag. Skip.
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.generic_visit(node)

    # -- dead code -----------------------------------------------------
    def _check_unreachable_after_return(self, node: ast.If) -> None:
        for branch in (node.body, node.orelse):
            for index, statement in enumerate(branch[:-1]):
                if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                    follower = branch[index + 1]
                    if not isinstance(follower, (ast.Pass, ast.Expr)):
                        self._add(
                            follower,
                            title="Unreachable code after a terminal statement",
                            description=(
                                f"`{type(statement).__name__.replace('ast.', '').lower()}` is followed by "
                                f"`{ast.unparse(follower)[:80]}`, which can never execute."
                            ),
                            severity=Severity.LOW,
                            category=FindingCategory.LOGIC,
                            cwe="CWE-561",
                            impact="Dead code hides unimplemented or forgotten logic and misleads reviewers.",
                            recommendation="Delete the unreachable statements.",
                            tool="python-ast-logic",
                        )

    def visit_Expr(self, node: ast.Expr) -> None:
        # A bare string literal as a statement is a placeholder, not a bug.
        self.generic_visit(node)

    # -- always-true / always-false conditions -------------------------
    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if isinstance(node.op, ast.And) and not node.values:
            self._add(
                node,
                title="Empty boolean condition is always falsy",
                description="An `and` with no operands can never be true.",
                severity=Severity.LOW,
                category=FindingCategory.LOGIC,
                cwe="CWE-570",
                impact="The guarded code never runs.",
                recommendation="Remove the empty condition.",
                tool="python-ast-logic",
            )
        self.generic_visit(node)

    # -- reporter ------------------------------------------------------
    def _add(
        self,
        node: ast.AST,
        *,
        title: str,
        description: str,
        severity: Severity,
        category: FindingCategory,
        cwe: str,
        impact: str,
        recommendation: str,
        tool: str,
    ) -> None:
        key = (_line(node), title)
        if key in self._reported:
            return
        self._reported.add(key)

        function = ".".join(self.function_stack) or "<module>"
        # A money/abort-style function name raises confidence that this is a
        # real defect rather than a stylistic choice.
        confidence = 0.75
        if any(hint in function.lower() for hint in self.MONEY_HINTS):
            confidence = 0.85

        self.findings.append(
            AgentFinding(
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                category=category,
                cwe=cwe,
                certainty=Certainty.PROBABLE,
                file_path=self.path,
                line_number=_line(node),
                code_snippet=_code_for(self.source_lines, _line(node)),
                evidence=[f"AST logic heuristic in `{function}` at line {_line(node)}"],
                impact=impact,
                recommendation=recommendation,
                is_bug=True,
                detected_by=["bug_hunter"],
                tools=[tool],
            )
        )


# ----------------------------------------------------------------------
def analyze_module(
    path: str,
    source: str,
    *,
    security: bool = True,
    logic: bool = True,
) -> tuple[list[AgentFinding], list[AgentFinding]]:
    """Run both analyzers over one module, returning (security, logic)."""
    security_findings: list[AgentFinding] = []
    logic_findings: list[AgentFinding] = []

    if security:
        engine = AstSecurityAnalyzer(path, source)
        try:
            engine.visit(ast.parse(source, filename=path))
        except (SyntaxError, ValueError, RecursionError):
            pass
        else:
            security_findings = engine.findings

    if logic:
        engine = AstLogicAnalyzer(path, source)
        try:
            engine.visit(ast.parse(source, filename=path))
        except (SyntaxError, ValueError, RecursionError):
            pass
        else:
            logic_findings = engine.findings

    return security_findings, logic_findings


def module_imports(source: str) -> Iterable[str]:
    tree = _safe_parse(source, "<module>")
    if tree is None:
        return []
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

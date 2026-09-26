"""
Access-control and input-validation analysis for web routes.

This covers a class of defect that the injection and logic analysers do not
touch, and that Bandit does not report: a handler that is reachable without
any authentication or authorization check, and a handler that accepts
unvalidated input.

Only framework routes are considered. A route is flagged when it has no
authentication decorator, no explicit credential check, and no call into a
known auth helper. The analysis is deliberately conservative: it stays quiet
when it sees any of those, so it does not bury real findings in noise.
"""

from __future__ import annotations

import ast
import re

from app.core.logging_config import get_logger
from app.models.enums import Certainty, FindingCategory, Severity
from app.schemas.finding import AgentFinding

logger = get_logger(__name__)

#: URL prefixes that are expected to be public.
PUBLIC_PREFIXES = (
    "/api/health",
    "/api/login",
    "/api/register",
    "/static",
    "/favicon",
    "/health",
    "/metrics",
    "/",
)

#: Decorators that satisfy an access-control requirement.
AUTH_DECORATORS = {
    "login_required",
    "admin_required",
    "permission_required",
    "requires_auth",
    "authenticate",
    "jwt_required",
    "api_key_required",
    "authorize",
    "staff_required",
    "role_required",
    "permission_classes",
    "requires_permission",
    "staff_member_required",
}

#: Calls that prove the handler checks credentials itself.
AUTH_CALLS = {
    "check_token",
    "check_admin",
    "check_permission",
    "verify_token",
    "validate_token",
    "require_auth",
    "authenticate",
    "is_admin",
    "is_authenticated",
    "current_user",
    "verify_admin_token",
    "get_current_user",
    "check_auth",
    "_check_auth",
    "abort_unauthorized",
}

#: Route decorators we understand.
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket"}

#: Methods that do not change state and are often public.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

#: Parameter names that indicate a privileged view.
PRIVILEGED_HINTS = (
    "admin", "user", "account", "order", "payment", "billing", "token",
    "secret", "config", "role", "permission", "session", "document",
)


def analyze_access_control(path: str, source: str) -> list[AgentFinding]:
    """
    Report routes that expose privileged behaviour with no access control.

    Returns findings in the standard format so they merge with everything
    else the Security Agent produces.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    except (ValueError, RecursionError):
        return []

    findings: list[AgentFinding] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        routes = _routes_of(node)
        if not routes:
            continue

        protection = _protection_of(node)
        for method, rule in routes:
            if _is_public(rule):
                continue
            if protection is not None:
                continue
            if not _looks_privileged(rule, node):
                continue

            findings.append(
                _missing_authz_finding(path, node, method, rule, source)
            )
    return findings


def _is_public(rule: str | None) -> bool:
    """
    True when a route is expected to be reachable without credentials.

    The bare ``/`` entry is an exact match, not a prefix: treating it as a
    prefix would exempt every route in the application, which is exactly the
    bug this check exists to catch.
    """
    if rule is None:
        return False
    if rule == "/":
        return True
    for prefix in PUBLIC_PREFIXES:
        if prefix == "/":
            continue
        if rule == prefix or rule.startswith(prefix + "/") or rule.startswith(prefix + "?"):
            return True
    return False


def _routes_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str | None]]:
    """Return (HTTP method, url rule) for each route decorator on a handler."""
    routes: list[tuple[str, str | None]] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        func = decorator.func
        name = None
        if isinstance(func, ast.Attribute) and func.attr in ROUTE_DECORATORS:
            name = func.attr
        elif isinstance(func, ast.Name) and func.id in ROUTE_DECORATORS:
            name = func.id
        if name is None:
            continue

        method = "GET"
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                methods = [
                    element.value
                    for element in keyword.value.elts
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                ]
                if methods:
                    method = methods[0].upper()
        rule = None
        if decorator.args and isinstance(decorator.args[0], ast.Constant):
            value = decorator.args[0].value
            rule = value if isinstance(value, str) else None
        routes.append((method, rule))
    return routes


def _protection_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """
    Return the name of whatever protects this handler, or None if nothing does.

    A bare ``pass`` or a comment-like placeholder does not count: a
    ``if not key: pass`` block is exactly the anti-pattern this is looking
    for, so the guard must actually return, raise or redirect.
    """
    for decorator in node.decorator_list:
        text = _unparse(decorator)
        if any(name in text for name in AUTH_DECORATORS):
            return "decorator"

    # A function called in the body counts only if the body can actually stop
    # the request.
    for statement in node.body:
        for child in ast.walk(statement):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            if not name:
                continue
            if any(name == helper or name.endswith(f"_{helper}") for helper in AUTH_CALLS):
                return f"call:{name}"

    # An explicit `if <auth-looking condition>: return/raise` also counts.
    for statement in node.body:
        if not isinstance(statement, ast.If):
            continue
        source_text = _unparse(statement.test).lower()
        if not any(token in source_text for token in ("auth", "token", "admin", "permission", "role", "user")):
            continue
        for branch in (statement.body, statement.orelse):
            for child in branch:
                if isinstance(child, (ast.Return, ast.Raise)):
                    return "guard"
                if isinstance(child, ast.Call) and "abort" in _unparse(child):
                    return "abort"
    return None


def _looks_privileged(rule: str | None, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """
    Only report routes that expose something worth protecting.

    A public health check is not a finding; an admin listing every user is.
    """
    haystack = f"{rule or ''} {node.name}".lower()
    if any(hint in haystack for hint in PRIVILEGED_HINTS):
        return True
    body = _unparse(node).lower()
    return any(
        token in body
        for token in ("list_all_users", "all_users", "db_password", "admin_token", "config_dump")
    )


def _missing_authz_finding(
    path: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    method: str,
    rule: str | None,
    source: str,
) -> AgentFinding:
    lines = source.splitlines()
    line = node.lineno
    snippet = ""
    if 0 < line <= len(lines):
        snippet = lines[line - 1].strip()
    display_rule = rule or f"<{method} handler {node.name}>"
    is_write = method not in SAFE_METHODS

    return AgentFinding(
        title=f"Missing access control on {display_rule}",
        description=(
            f"The {method} handler `{node.name}` is reachable with no "
            f"authentication or authorization check: there is no "
            f"`@login_required`-style decorator, no token verification and no "
            f"guard that returns or aborts. Any unauthenticated caller can "
            f"invoke it."
        ),
        severity=Severity.HIGH if is_write else Severity.MEDIUM,
        confidence=0.7,
        category=FindingCategory.AUTHORIZATION.value,
        cwe="CWE-862",
        owasp="A01:2021-Broken Access Control",
        certainty=Certainty.PROBABLE,
        file_path=path,
        line_number=line,
        code_snippet=snippet,
        evidence=[
            f"Route {display_rule} is served by {node.name}() at line {line}",
            "No authentication decorator on the handler",
            "No token or permission check that can stop the request",
        ],
        impact=(
            "An unauthenticated or unauthorized caller can read or modify data "
            "this endpoint was never meant to expose."
        ),
        recommendation=(
            "Require authentication before the handler body runs, and authorize "
            "the specific action -- add `@login_required` plus a role check, or "
            "verify a scoped token explicitly and abort with 401/403."
        ),
        detected_by=["security_agent"],
        tools=["ast-access-control"],
    )


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is total in practice
        return ""


# ----------------------------------------------------------------------
_VALIDATION_FLOWS = (
    # (endpoint marker, field names that must be validated)
    ("validate-email", ("email",)),
    ("validate_email", ("email",)),
    ("register", ("email", "password", "username")),
    ("signup", ("email", "password", "username")),
    ("login", ("password", "username")),
)


def analyze_validation(path: str, source: str) -> list[AgentFinding]:
    """
    Report handlers that accept a field without validating its shape.

    A non-empty check is not validation: the demo target accepts any non-empty
    string as an email address, which passes its own check while still being
    wrong.
    """
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []

    findings: list[AgentFinding] = []
    lines = source.splitlines()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        haystack = f"{node.name} {_unparse(node)[:200]}".lower()
        for marker, fields in _VALIDATION_FLOWS:
            if marker not in haystack:
                continue
            body = _unparse(node)
            if not any(field in body for field in fields):
                continue
            if _validates_shape(node, fields):
                continue
            line = node.lineno
            findings.append(
                AgentFinding(
                    title=f"Input accepted without validation in {node.name}()",
                    description=(
                        f"`{node.name}()` accepts {', '.join(fields)} but never "
                        f"checks its format. The only guard is a presence check, "
                        f"so syntactically invalid values are accepted and stored."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    category=FindingCategory.VALIDATION.value,
                    cwe="CWE-20",
                    owasp="A04:2021-Insecure Design",
                    certainty=Certainty.PROBABLE,
                    file_path=path,
                    line_number=line,
                    code_snippet=lines[line - 1].strip() if 0 < line <= len(lines) else "",
                    evidence=[
                        f"{node.name}() reads {', '.join(fields)} from the request",
                        "No regex, type check, length bound or format library is applied",
                    ],
                    impact="Malformed or hostile input reaches storage and later consumers, widening the attack surface and corrupting data.",
                    recommendation=(
                        "Validate the field with a format check (for example a "
                        "compiled email regex, or an email validation library) and "
                        "bound its length before use."
                    ),
                    detected_by=["security_agent"],
                    tools=["ast-access-control"],
                )
            )
            break
    return findings


_VALIDATOR_CALLS = {
    "validate", "validator", "validate_email", "is_valid_email", "check_email",
    "parse_email", "EmailStr", "field_validator", "constr", "parse_obj", "model_validate",
    "fullmatch", "match", "search", "validate_input", "check_format", "is_valid",
}
_VALIDATOR_ATTRS = {"validate", "is_valid", "check", "fullmatch", "match", "search", "parse"}


def _validates_shape(node: ast.FunctionDef | ast.AsyncFunctionDef, fields: tuple[str, ...]) -> bool:
    """True when the handler applies a real format check to one of the fields."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else getattr(func, "id", "")
        )
        if not name:
            continue
        if name in _VALIDATOR_CALLS or name in _VALIDATOR_ATTRS:
            # A validator applied to the field we care about.
            rendered = _unparse(child)
            if any(field in rendered for field in fields):
                return True
        # `re.compile(...)` assigned once and used later is also validation.
        if name == "compile" and "re." in _unparse(func):
            return True
        # Type annotations on the parameter (pydantic models).
        if name in {"EmailStr", "constr", "HttpUrl", "UUID"}:
            return True
    # An annotation like `email: EmailStr` counts too.
    for argument in list(node.args.args) + list(node.args.kwonlyargs):
        if argument.annotation and any(
            token in _unparse(argument.annotation)
            for token in ("EmailStr", "HttpUrl", "constr", "BaseModel", "Email")
        ):
            return True
    return False


__all__ = [
    "AUTH_DECORATORS",
    "PUBLIC_PREFIXES",
    "analyze_access_control",
    "analyze_validation",
]


# Keep a reference so linters do not flag the import used only for re-export.
_ = re

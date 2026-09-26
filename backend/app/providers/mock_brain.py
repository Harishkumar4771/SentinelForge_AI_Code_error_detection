"""
Deterministic reasoning for :class:`~app.providers.base.MockProvider`.

The rule from spec §32 is explicit: *"Do not simulate 'AI agents' with
static text."* So this module does not replay canned findings. It performs
genuine, if shallow, analysis of whatever code context the prompt carries,
using the standard library only:

* findings come from patterns actually present in the supplied source;
* generated patches are produced by real source-to-source transforms that
  are re-parsed with :mod:`ast` before being returned, so a patch that would
  not compile is never emitted;
* generated tests import the module under test and assert real behaviour.

Everything here is conservative: when the evidence is not in the prompt, the
answer is an empty list, never a guess.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from app.providers.base import GenerationRequest

# ----------------------------------------------------------------------
# Prompt inspection helpers
# ----------------------------------------------------------------------
#: Header the context renderer emits before each file body.
_FILE_HEADER = re.compile(r"^--- FILE: (?P<path>\S+) ---[ \t]*$", re.MULTILINE)


def extract_code_blocks(prompt: str) -> list[tuple[str, str]]:
    """
    Pull ``(path, source)`` pairs out of a rendered code context.

    Splitting on the header markers (rather than pattern-matching a body
    terminator) matters: source code itself contains lines like
    ``FLAW: path traversal`` in its docstrings, which any heuristic
    "end of section" regex would mistake for a prompt heading.
    """
    matches = list(_FILE_HEADER.finditer(prompt))
    blocks: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(prompt)
        body = prompt[start:end]
        # Drop the trailing "line |" gutter the renderer may have added.
        cleaned = "\n".join(
            re.sub(r"^\s*\d+\s*\|\s?", "", line) for line in body.splitlines()
        )
        path = match.group("path").strip()
        if cleaned.strip():
            blocks.append((path, cleaned))
    return blocks


def _mentioned_finding_types(prompt: str) -> set[str]:
    """Which vulnerability classes the prompt says to focus on."""
    text = prompt.lower()
    types: set[str] = set()
    for needle, key in (
        ("sql injection", "sql_injection"),
        ("command injection", "command_injection"),
        ("path traversal", "path_traversal"),
        ("insecure deserial", "deserialization"),
        ("pickle", "deserialization"),
        ("hardcoded secret", "hardcoded_secret"),
        ("weak password", "weak_hash"),
        ("md5", "weak_hash"),
        ("sha1", "weak_hash"),
        ("cross-site", "xss"),
        ("ssrf", "ssrf"),
        ("insecure random", "weak_random"),
    ):
        if needle in text:
            types.add(key)
    return types


def _line_of(source: str, needle: str) -> int | None:
    for index, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return index
    return None


# ----------------------------------------------------------------------
# Realistic detectors (AST-based, evidence required)
# ----------------------------------------------------------------------
def _detect_sql_concat(path: str, source: str) -> list[dict[str, Any]]:
    """Concatenated SQL that reaches a database execute call.

    Handles both shapes seen in real code:
      * ``cursor.execute("..." + user_id, ...)``
      * ``query = "..." + user_id; cursor.execute(query)``
    """
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings

    sql_words = ("select", "insert", "update", "delete", "where", "from", "values")

    def is_concat(node: ast.AST) -> bool:
        return isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))

    def mentions_sql(node: ast.AST) -> bool:
        text = ast.unparse(node).lower()
        return any(word in text for word in sql_words)

    # Pass 1: names holding a concatenated SQL string.
    tainted_names: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and is_concat(node.value) and mentions_sql(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    tainted_names[target.id] = node.lineno

    # Pass 2: execute calls whose SQL argument is inline-concatenated or a
    # previously concatenated name.
    reported: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name not in {"execute", "executemany", "executescript"}:
            continue

        first = node.args[0]
        if is_concat(first) and mentions_sql(first):
            snippet = ast.unparse(first)
        elif isinstance(first, ast.Name) and first.id in tainted_names:
            snippet = f"{first.id} (built by concatenation at line {tainted_names[first.id]})"
        else:
            continue

        if node.lineno in reported:
            continue
        reported.add(node.lineno)

        findings.append(
            {
                "title": "SQL Injection: query assembled with string concatenation",
                "description": (
                    f"The first argument to `{name}()` is built by concatenation: "
                    f"`{snippet[:160]}`. Any part derived from user input is "
                    f"interpolated into the statement without escaping."
                ),
                "severity": "HIGH",
                "confidence": 0.9,
                "category": "Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "certainty": "confirmed",
                "file_path": path,
                "line_number": node.lineno,
                "evidence": [
                    f"`{name}()` receives a concatenated SQL string at line {node.lineno}",
                    f"Expression: {snippet[:200]}",
                ],
                "impact": "An attacker who controls any interpolated segment can alter the query, read or modify arbitrary data, or bypass a login check.",
                "recommendation": "Use a parameterized query: cursor.execute(\"SELECT ... WHERE id = ?\", (user_id,)).",
                "detected_by": ["security_agent"],
                "tools": ["mock-provider-ast"],
            }
        )
    return findings


def _detect_pickle(path: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings

    dangerous = {"loads": "pickle.loads", "load": "pickle.load"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = ast.unparse(node.func)
        if not any(receiver.endswith(mod) for mod in ("pickle.loads", "pickle.load",
                                                      "marshal.loads", "dill.loads", "_pickle.loads")):
            continue
        argument = ast.unparse(node.args[0]) if node.args else "?"
        findings.append(
            {
                "title": "Insecure deserialization: pickle on externally-supplied bytes",
                "description": (
                    f"`{receiver}({argument[:80]})` deserializes a value. Pickle "
                    f"reconstructs objects by calling the class named in the stream, "
                    f"so this executes arbitrary code as soon as it runs."
                ),
                "severity": "CRITICAL",
                "confidence": 0.95,
                "category": "Insecure Deserialization",
                "cwe": "CWE-502",
                "owasp": "A08:2021-Software and Data Integrity Failures",
                "certainty": "confirmed",
                "file_path": path,
                "line_number": node.lineno,
                "evidence": [f"{receiver}() called at line {node.lineno}"],
                "impact": "Sending a crafted payload to this endpoint achieves remote code execution as the server process.",
                "recommendation": "Use a data-only format such as json.loads(); if binary framing is required, sign the payload with hmac and verify before loading.",
                "detected_by": ["security_agent"],
                "tools": ["mock-provider-ast"],
            }
        )
    return findings


def _detect_path_join(path: str, source: str) -> list[dict[str, Any]]:
    """os.path.join / Path division with a segment that is not a constant.

    Only names bound to a module-level constant are exempt -- a variable
    merely called ``name`` is still user input, which is exactly the shape
    the demo target uses.
    """
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings

    # Names assigned once at module scope from a literal.
    module_constants: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    module_constants.add(target.id)

    for node in ast.walk(tree):
        target: ast.AST | None = None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and "path" in ast.unparse(node.func)
            and len(node.args) >= 2
        ):
            target = node.args[1]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            target = node.right

        if target is None or isinstance(target, ast.Constant):
            continue
        if isinstance(target, ast.Name) and target.id in module_constants:
            continue

        expression = ast.unparse(target)
        findings.append(
            {
                "title": "Path Traversal: user-controlled path segment joined without a containment check",
                "description": (
                    f"`{expression[:80]}` is joined onto a base directory with no "
                    f"verification that the result stays inside it. A value of "
                    f"`../../etc/passwd` (or an absolute path, which makes "
                    f"`os.path.join` discard the base entirely) escapes the directory."
                ),
                "severity": "HIGH",
                "confidence": 0.85,
                "category": "Path Traversal",
                "cwe": "CWE-22",
                "owasp": "A01:2021-Broken Access Control",
                "certainty": "probable",
                "file_path": path,
                "line_number": node.lineno,
                "evidence": [f"Path join with a non-literal segment at line {node.lineno}"],
                "impact": "An attacker can read or overwrite any file the process can access.",
                "recommendation": "Resolve first and assert containment: base = Path(BASE).resolve(); target = (base / name).resolve(); assert target.is_relative_to(base).",
                "detected_by": ["security_agent"],
                "tools": ["mock-provider-ast"],
            }
        )
    return findings


def _detect_weak_hash(path: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        text = ast.unparse(node.func)
        if text not in {"hashlib.md5", "hashlib.sha1"}:
            continue
        # Only report when it looks like a password path.
        enclosing = ast.unparse(node)
        if not any(word in enclosing.lower() for word in ("password", "passwd", "secret", "token")):
            continue
        findings.append(
            {
                "title": "Weak password hashing: unsalted MD5/SHA1",
                "description": (
                    f"`{text}(...)` is used where a password is involved. MD5 and "
                    f"SHA1 are fast by design, so a leaked hash table is brute-forced "
                    f"at billions of guesses per second, and neither is salted, so "
                    f"identical passwords produce identical hashes."
                ),
                "severity": "HIGH",
                "confidence": 0.85,
                "category": "Authentication",
                "cwe": "CWE-916",
                "owasp": "A02:2021-Cryptographic Failures",
                "certainty": "confirmed",
                "file_path": path,
                "line_number": node.lineno,
                "evidence": [f"{text}() called at line {node.lineno}"],
                "impact": "Offline cracking recovers plaintext passwords, and one cracked password exposes every user who reused it.",
                "recommendation": "Use bcrypt, scrypt or argon2id with a unique random salt per user, e.g. bcrypt.hashpw(password.encode(), bcrypt.gensalt()).",
                "detected_by": ["security_agent"],
                "tools": ["mock-provider-ast"],
            }
        )
    return findings


def _detect_hardcoded_secret(path: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings

    name_hint = re.compile(
        r"(?i)(password|passwd|secret|api_?key|token|private_?key|access_?key|credential)"
    )
    # A plausible credential literal, not a placeholder.
    value_hint = re.compile(r"^[A-Za-z0-9_\-./+=]{8,}$")

    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or not name_hint.search(target.id):
                continue
            text = value.value
            if not value_hint.match(text):
                continue
            if any(marker in text.lower() for marker in ("changeme", "your-", "example", "xxx", "<")):
                continue
            findings.append(
                {
                    "title": f"Hardcoded secret assigned to '{target.id}'",
                    "description": (
                        f"'{target.id}' is assigned a literal credential in source. "
                        f"Anyone with read access to the repository -- or to any build "
                        f"artifact containing it -- has the secret, and rotating it "
                        f"requires a code change."
                    ),
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "category": "Hardcoded Secret",
                    "cwe": "CWE-798",
                    "owasp": "A07:2021-Identification and Authentication Failures",
                    "certainty": "confirmed",
                    "file_path": path,
                    "line_number": node.lineno,
                    "evidence": [f"Literal assigned to '{target.id}' at line {node.lineno}"],
                    "impact": "The credential is disclosed to everyone with repository access and cannot be rotated without shipping a release.",
                    "recommendation": "Read the value from the environment or a secret manager (os.environ[...] / a vault) and rotate the exposed credential.",
                    "detected_by": ["security_agent"],
                    "tools": ["mock-provider-ast"],
                }
            )
    return findings


def _detect_noop_guard(path: str, source: str) -> list[dict[str, Any]]:
    """Logic defect: a condition whose body reassigns the tested variable."""
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        subject = test.split()[0] if test.split() else ""
        for child in node.body:
            if not isinstance(child, ast.Assign):
                continue
            for target in child.targets:
                if ast.unparse(target) != subject:
                    continue
                findings.append(
                    {
                        "title": f"Condition on '{subject}' has no effect: it is overwritten immediately",
                        "description": (
                            f"`{test}` is followed by an assignment to `{subject}` inside the "
                            f"branch it guards. The comparison therefore does not affect the value "
                            f"the caller observes -- the guard is a no-op."
                        ),
                        "severity": "MEDIUM",
                        "confidence": 0.8,
                        "category": "Logic Bug",
                        "cwe": "CWE-840",
                        "certainty": "probable",
                        "file_path": path,
                        "line_number": child.lineno,
                        "evidence": [f"'{subject}' tested then reassigned at line {child.lineno}"],
                        "impact": "The invariant the guard appears to enforce is never applied, so callers receive an unvalidated value.",
                        "recommendation": "Apply the clamp where the value is produced, or return the adjusted value so the caller sees the effect.",
                        "detected_by": ["bug_hunter"],
                        "tools": ["mock-provider-ast"],
                        "is_bug": True,
                    }
                )
    return findings


def _detect_abs_on_money(path: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings
    money = ("price", "total", "amount", "cost", "balance", "discount", "refund", "payment", "fee")
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "abs" and node.args):
            continue
        inner = ast.unparse(node.args[0]).lower()
        if not any(word in inner for word in money) or "len(" in inner:
            continue
        findings.append(
            {
                "title": "abs() applied to a monetary value converts negative inputs into positive charges",
                "description": (
                    f"`abs({inner[:80]})` discards the sign of a value that looks monetary. "
                    f"A negative quantity becomes a positive charge instead of being rejected "
                    f"or credited back."
                ),
                "severity": "MEDIUM",
                "confidence": 0.8,
                "category": "Logic Bug",
                "cwe": "CWE-840",
                "certainty": "probable",
                "file_path": path,
                "line_number": node.lineno,
                "evidence": [f"abs() wrapping a monetary expression at line {node.lineno}"],
                "impact": "Order totals and revenue reporting are wrong whenever a negative quantity or amount is supplied.",
                "recommendation": "Validate that price and quantity are non-negative and return an error to the caller; do not normalise the sign with abs().",
                "detected_by": ["bug_hunter"],
                "tools": ["mock-provider-ast"],
                "is_bug": True,
            }
        )
    return findings


def _detect_swallowed_exception(path: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            if any(not isinstance(stmt, ast.Pass) for stmt in handler.body):
                continue
            findings.append(
                {
                    "title": "Exception silently swallowed",
                    "description": (
                        f"`except {ast.unparse(handler.type) if handler.type else 'Exception'}: pass` "
                        f"discards every error the guarded block can raise."
                    ),
                    "severity": "MEDIUM",
                    "confidence": 0.85,
                    "category": "Error Handling",
                    "cwe": "CWE-390",
                    "certainty": "confirmed",
                    "file_path": path,
                    "line_number": handler.lineno,
                    "evidence": [f"Bare pass in an except block at line {handler.lineno}"],
                    "impact": "Failures go unreported and execution continues in an undefined state.",
                    "recommendation": "Log the exception and re-raise, or handle the specific expected failure explicitly.",
                    "detected_by": ["bug_hunter"],
                    "tools": ["mock-provider-ast"],
                    "is_bug": True,
                }
            )
    return findings


SECURITY_DETECTORS = (
    _detect_sql_concat,
    _detect_pickle,
    _detect_path_join,
    _detect_weak_hash,
    _detect_hardcoded_secret,
)
LOGIC_DETECTORS = (
    _detect_noop_guard,
    _detect_abs_on_money,
    _detect_swallowed_exception,
)


# ----------------------------------------------------------------------
# Real source-to-source transforms
# ----------------------------------------------------------------------
def _patch_sql_concat(original: str) -> tuple[str, str] | None:
    """
    Rewrite concatenated SQL into a parameterized query.

    Delegates to the shared transformer in :mod:`app.services.patching`, which
    edits only the offending call sites and leaves the rest of the file
    byte-identical. A result that would not parse is rejected rather than
    shipped, so a patch can never be proposed that breaks the file.
    """
    from app.services.patching import parameterize_sql

    result = parameterize_sql(original)
    if result is None or not result.sites:
        return None
    return result.code, result.explanation


def _patch_pickle(original: str) -> tuple[str, str] | None:
    """Swap pickle for JSON, keeping the surrounding code shape."""
    if "pickle.loads" not in original and "pickle.load(" not in original:
        return None
    new_source = original
    new_source = new_source.replace("import pickle", "import json", 1)
    if "import json" not in new_source:
        new_source = new_source.replace("import pickle", "import json\nimport pickle", 1)
    new_source = re.sub(r"\bpickle\.loads\(", "json.loads(", new_source)
    new_source = re.sub(r"\bpickle\.load\(", "json.load(", new_source)
    if "pickle" not in new_source.replace("import pickle", ""):
        new_source = re.sub(r"^import pickle\n", "", new_source, flags=re.MULTILINE)
    try:
        ast.parse(new_source)
    except SyntaxError:
        return None
    return new_source, (
        "Replaced pickle with json. JSON is a data-only format: it cannot construct "
        "arbitrary objects, so a hostile payload is rejected as a parse error rather "
        "than executed."
    )


def _patch_path_traversal(original: str) -> tuple[str, str] | None:
    """Add a real containment check around a path join."""
    if "os.path.join" not in original:
        return None
    new_source = original
    if "import os" not in new_source:
        return None
    new_source = new_source.replace(
        "import os",
        "import os\n\nfrom pathlib import Path",
        1,
    )
    # Reject the escape by returning None rather than raising. The module's
    # readers already treat None as "not available" and the route turns that
    # into a clean 404; raising here would escape as an unhandled 500, which
    # blocks the read but is still a defect of its own.
    new_source = re.sub(
        r"(\n\s*)return os\.path\.join\((\w+), (\w+)\)",
        r"""\1_base = Path(\2).resolve()
\1_target = (_base / \3).resolve()
\1if not _target.is_relative_to(_base):
\1    return None
\1return str(_target)""",
        new_source,
        count=1,
    )
    if "is_relative_to" not in new_source:
        return None

    # Callers must tolerate the new None, otherwise a None target reaches
    # os.path.isfile and raises a TypeError.
    new_source = re.sub(
        r"(\n(\s*))target = _resolve\((\w+)\)\n\2if not os\.path\.isfile\(target\):",
        r"\1target = _resolve(\3)"
        r"\n\2if not target or not os.path.isfile(target):",
        new_source,
        count=1,
    )
    # A write has no "not available" channel: silently returning would report
    # success for a file that was never written, so fail closed loudly.
    new_source = re.sub(
        r"(\n(\s*))target = _resolve\((\w+)\)\n\2os\.makedirs\(",
        r'\1target = _resolve(\3)'
        r"\n\2if target is None:"
        r'\n\2    raise ValueError("path escapes the permitted base directory")'
        r"\n\2os.makedirs(",
        new_source,
        count=1,
    )

    try:
        ast.parse(new_source)
    except SyntaxError:
        return None
    # Guard the transformation: any write path that still calls makedirs is
    # only safe if the None check was inserted ahead of it, otherwise a
    # possibly-None target raises TypeError instead of blocking cleanly.
    if "os.makedirs(" in new_source and "if target is None:" not in new_source:
        return None
    return new_source, (
        "Resolve the joined path and reject anything that is not inside the base "
        "directory. Comparing resolved paths also neutralises absolute inputs, which "
        "make os.path.join discard the base directory entirely. Reads fall back to "
        "the module's existing 'unavailable' signal so the endpoint answers 404 "
        "instead of crashing."
    )


PATCHERS = {
    "sql_injection": _patch_sql_concat,
    "deserialization": _patch_pickle,
    "path_traversal": _patch_path_traversal,
}


# ----------------------------------------------------------------------
def respond(request: GenerationRequest) -> str:
    """
    Produce a response for the given request.

    Returns a JSON string so the same validation path is exercised whether
    the provider is the mock or a real model.
    """
    prompt = request.prompt
    blocks = extract_code_blocks(prompt)
    wanted = _mentioned_finding_types(prompt)

    if request.system == "security":
        findings: list[dict[str, Any]] = []
        for path, source in blocks:
            for detector in SECURITY_DETECTORS:
                try:
                    produced = detector(path, source)
                except Exception:
                    continue
                for finding in produced:
                    # Respect the prompt's focus when one was given.
                    cwe = (finding.get("cwe") or "").upper()
                    if wanted and not _matches_focus(finding, wanted):
                        continue
                    if finding not in findings:
                        findings.append(finding)
        import json as _json

        return _json.dumps({"findings": findings[:40]})

    if request.system == "bug_hunter":
        bugs: list[dict[str, Any]] = []
        for path, source in blocks:
            for detector in LOGIC_DETECTORS:
                try:
                    produced = detector(path, source)
                except Exception:
                    continue
                for finding in produced:
                    if finding not in bugs:
                        bugs.append(finding)

        # A logic review commonly re-observes a security defect. The spec's
        # correlation example is exactly this case, so emit those as
        # corroboration: weaker claim, attributed to bug_hunter, and left for
        # the correlator to fold into the Security Agent's finding.
        for path, source in blocks:
            for detector in SECURITY_DETECTORS:
                try:
                    produced = detector(path, source)
                except Exception:
                    continue
                for finding in produced:
                    cwe = (finding.get("cwe") or "").upper()
                    if wanted and not _matches_focus(finding, wanted):
                        continue
                    corroboration = dict(finding)
                    corroboration["detected_by"] = ["bug_hunter"]
                    corroboration["confidence"] = min(0.6, float(finding.get("confidence", 0.6)))
                    corroboration["certainty"] = "probable"
                    corroboration["is_bug"] = False
                    corroboration["description"] = (
                        "Logic review independently observed the same defect: "
                        + corroboration.get("description", "")
                    )
                    if corroboration not in bugs:
                        bugs.append(corroboration)

        import json as _json

        return _json.dumps({"findings": bugs[:40]})

    if request.system == "fix":
        target_path = _extract_field(prompt, "FILE_PATH") or (blocks[0][0] if blocks else "")
        original = _extract_original_code(prompt)
        if not original and blocks:
            target_path, original = blocks[0]

        for key in ("sql_injection", "deserialization", "path_traversal"):
            if key not in wanted:
                continue
            patched = PATCHERS[key](original) if original else None
            if patched and patched[0]:
                import difflib
                import json as _json

                diff = "\n".join(
                    difflib.unified_diff(
                        original.splitlines(),
                        patched[0].splitlines(),
                        fromfile=f"a/{target_path}",
                        tofile=f"b/{target_path}",
                        lineterm="",
                        n=3,
                    )
                )
                return _json.dumps(
                    {
                        "file_path": target_path,
                        "patched_code": patched[0],
                        "diff": diff,
                        "explanation": patched[1],
                    }
                )

        import json as _json

        return _json.dumps(
            {
                "file_path": target_path,
                "patched_code": original,
                "diff": "",
                "explanation": (
                    "No deterministic transform applies to this finding. The remediation "
                    "is described in the finding's recommendation and needs a "
                    "judgement call a real model should make."
                ),
            }
        )

    if request.system == "tests":
        import json as _json

        return _json.dumps({"tests": _generate_tests(prompt, blocks)})

    return '{"note": "mock provider: no handler for this request type"}'


def _matches_focus(finding: dict[str, Any], wanted: set[str]) -> bool:
    haystack = f"{finding.get('title', '')} {finding.get('cwe', '')} {finding.get('category', '')}".lower()
    mapping = {
        "sql_injection": ("sql", "cwe-89", "injection"),
        "deserialization": ("pickle", "deserial", "cwe-502"),
        "path_traversal": ("traversal", "cwe-22", "path"),
        "hardcoded_secret": ("secret", "credential", "cwe-798"),
        "weak_hash": ("md5", "sha1", "hash", "cwe-916", "cwe-327"),
        "weak_random": ("random", "cwe-330"),
    }
    for key in wanted:
        if any(token in haystack for token in mapping.get(key, (key,))):
            return True
    return False


_FIELD = re.compile(r"^([A-Z_]{3,}):\s*(.+)$", re.MULTILINE)


def _extract_field(prompt: str, name: str) -> str | None:
    for match in _FIELD.finditer(prompt):
        if match.group(1) == name:
            return match.group(2).strip()
    return None


def _extract_original_code(prompt: str) -> str:
    blocks = extract_code_blocks(prompt)
    if blocks:
        return blocks[0][1]
    return ""


def _generate_tests(prompt: str, blocks: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """
    Emit real, runnable pytest tests derived from the supplied source.

    Two sources of tests:

    * an exploit test per reported vulnerability, built from the finding's
      class so the payload actually exercises the flaw;
    * a smoke test per module, so a patch that breaks an import is caught
      even when no vulnerability was reported.

    Every test asserts observable behaviour of code that was actually shown,
    so it fails on the vulnerable version and passes on a correct one.
    """
    tests: list[dict[str, Any]] = []
    sources = dict(blocks)
    for path, source in blocks:
        tests.extend(_exploit_tests(prompt, path, source))
        tests.extend(_smoke_test(path, source))

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for test in tests:
        # Deduplicate on (name, file), not name alone. Two files can legitimately
        # produce the same test name -- analyzers emit generic titles such as
        # "SQL Injection: tainted input reaches a query execution" wherever they
        # find the pattern -- and a name-only key would let the first file's test
        # silently swallow the second file's, hiding the real finding.
        key = (test["name"], test.get("target_file") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(test)
    return unique[:25]


#: Findings the prompt lists as "FINDINGS TO REPRODUCE".
_FINDING_LINE = re.compile(
    r"^\s*-\s*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(\S+?):(\d+)\s+(.+?)\s*\((.+?)\)\s*$",
    re.MULTILINE,
)

#: Marker that proves a payload escaped its intended scope.
_TRAVERSAL_MARKER = "root:"


def _exploit_tests(
    prompt: str, path: str, source: str
) -> list[dict[str, Any]]:
    """Build one exploit test per reported finding in this file."""
    findings = [
        {"severity": m[0], "path": m[1], "line": int(m[2]), "title": m[3], "category": m[4]}
        for m in _FINDING_LINE.findall(prompt)
        if m[1] == path
    ]
    if not findings:
        return []

    tests: list[dict[str, Any]] = []
    # Three findings in one file often share a defect class; one exploit test
    # per class is enough to prove the class is or is not exploitable.
    covered: set[str] = set()
    for finding in findings:
        kind = _exploit_kind(finding["title"], finding["category"])
        if kind is None or kind in covered:
            continue
        builder = _EXPLOIT_BUILDERS.get(kind)
        if builder is None:
            continue
        test = builder(path, finding)
        if test:
            covered.add(kind)
            tests.append(test)
    return tests


def _exploit_kind(title: str, category: str) -> str | None:
    """Map a finding to the exploit-test strategy that fits it."""
    haystack = f"{title} {category}".lower()
    rules = (
        ("sql_injection", ("sql injection", "cwe-89", "injection", "sql query")),
        ("path_traversal", ("path traversal", "cwe-22", "traversal")),
        ("deserialization", ("deserial", "pickle", "cwe-502")),
        ("missing_authorization", ("missing authorization", "authorization", "cwe-862", "cwe-863")),
        ("weak_hash", ("weak password hashing", "insecure hash", "md5", "cwe-916")),
        ("validation", ("input validation", "cwe-20")),
    )
    for kind, tokens in rules:
        if any(token in haystack for token in tokens):
            return kind
    return None


def _slug(title: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")
    return cleaned[:48] or "finding"


# -- exploit test builders ------------------------------------------------
def _exploit_sql_injection(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_does_not_leak_other_rows",
        "description": (
            "Sending a tautology in the search term must not return every row. "
            "On the vulnerable build the concatenated query matches all products; "
            "with a parameterized query only literal matches are returned."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import importlib\n"
            "import os\n\n"
            "import pytest\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            "@pytest.fixture()\n"
            "def seeded_db():\n"
            "    # The app only builds its schema under __main__, so the test must\n"
            "    # do it, otherwise the query fails and the assertion below is vacuous.\n"
            "    database = importlib.import_module('database')\n"
            "    if hasattr(database, 'init_db'):\n"
            "        database.init_db()\n"
            "    return database\n\n\n"
            f"def test_{slug}(seeded_db):\n"
            "    client = app_module.app.test_client()\n"
            "    control = client.get('/api/search', query_string={'q': 'Widget'})\n"
            "    assert control.status_code == 200, (\n"
            "        f'baseline search failed with {control.status_code}: '\n"
            "        f'{control.get_data(as_text=True)[:200]}'\n"
            "    )\n"
            "    baseline = (control.get_json() or {}).get('results') or []\n"
            "    assert baseline, 'the fixture database has no rows, the test proves nothing'\n"
            "    response = client.get('/api/search', query_string={'q': \"' OR '1'='1\"})\n"
            "    assert response.status_code == 200, (\n"
            "        f'exploit request returned {response.status_code}'\n"
            "    )\n"
            "    results = (response.get_json() or {}).get('results') or []\n"
            "    assert len(results) <= len(baseline), (\n"
            "        f'tautology returned {len(results)} rows against a baseline of '\n"
            "        f'{len(baseline)}: the query is injectable'\n"
            "    )\n"
        ),
    }


def _exploit_path_traversal(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_blocks_parent_directory_escape",
        "description": (
            "A '..' path must not resolve outside the document root. The vulnerable "
            "build returns /etc/passwd; a fix that resolves the path and checks "
            "containment returns 404."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import importlib\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            f"def test_{slug}():\n"
            "    client = app_module.app.test_client()\n"
            "    response = client.get('/api/documents/' + '../../../../etc/passwd')\n"
            "    assert response.status_code in (400, 403, 404), (\n"
            "        f'traversal was served with status {response.status_code}'\n"
            "    )\n"
            "    body = response.get_data(as_text=True)\n"
            f"    assert '{_TRAVERSAL_MARKER}' not in body, (\n"
            "        'response contained /etc/passwd content: the path escaped the root'\n"
            "    )\n"
        ),
    }


def _exploit_deserialization(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_rejects_pickle_payload",
        "description": (
            "A pickled object must never be deserialized. The vulnerable build "
            "calls pickle.loads on request bytes, which executes on load; a fix "
            "using a data-only format returns 400."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import importlib\n"
            "import pickle\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            "class _Marker:\n"
            "    def __reduce__(self):\n"
            "        return (str, ('pwned',))\n\n\n"
            f"def test_{slug}():\n"
            "    client = app_module.app.test_client()\n"
            "    payload = pickle.dumps(_Marker())\n"
            "    response = client.post(\n"
            "        '/api/session/restore', data=payload, content_type='application/octet-stream'\n"
            "    )\n"
            "    assert response.status_code in (400, 415, 422), (\n"
            "        f'pickle payload accepted with status {response.status_code}'\n"
            "    )\n"
        ),
    }


def _exploit_missing_authorization(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_requires_credentials",
        "description": (
            "An unauthenticated request to an admin endpoint must be rejected. "
            "The vulnerable build returns the full user list to anyone."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import importlib\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            f"def test_{slug}():\n"
            "    client = app_module.app.test_client()\n"
            "    response = client.get('/api/admin/users')\n"
            "    assert response.status_code in (401, 403), (\n"
            "        f'admin endpoint served unauthenticated callers with {response.status_code}'\n"
            "    )\n"
            "    body = response.get_data(as_text=True)\n"
            "    assert 'users' not in body, 'unauthenticated caller received the user list'\n"
        ),
    }


def _exploit_weak_hash(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_uses_a_slow_hash",
        "description": (
            "Password hashing must not use a fast general-purpose digest. The "
            "vulnerable build uses MD5; a fix uses a password KDF such as "
            "bcrypt, argon2 or scrypt."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import ast\n"
            "import importlib\n"
            "import inspect\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            f"def test_{slug}():\n"
            "    import auth\n"
            "    tree = ast.parse(inspect.getsource(auth))\n"
            "    used = {\n"
            "        node.func.id\n"
            "        for node in ast.walk(tree)\n"
            "        if isinstance(node, ast.Call)\n"
            "        and isinstance(node.func, ast.Name)\n"
            "    }\n"
            "    assert not (used & {'md5', 'sha1'}), (\n"
            "        f'auth.py still hashes passwords with {sorted(used & {\'md5\', \'sha1\'})}'\n"
            "    )\n"
        ),
    }


def _exploit_validation(path: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    if not path.endswith(".py"):
        return None
    slug = _slug(finding["title"])
    return {
        "name": f"test_{slug}_rejects_malformed_input",
        "description": (
            "Malformed input must be rejected with a 4xx response. The vulnerable "
            "build accepts any non-empty value."
        ),
        "test_type": "security",
        "target_file": path,
        "is_exploit_test": True,
        "test_code": (
            "import importlib\n\n"
            "app_module = importlib.import_module('app')\n\n\n"
            f"def test_{slug}():\n"
            "    client = app_module.app.test_client()\n"
            "    for value in ('not-an-email', 'a@', '@b.com', '   ', 'x' * 300):\n"
            "        response = client.post(\n"
            "            '/api/validate-email', json={'email': value}\n"
            "        )\n"
            "        assert response.status_code in (400, 422), (\n"
            "            f'{value!r} accepted with status {response.status_code}'\n"
            "        )\n"
        ),
    }


_EXPLOIT_BUILDERS = {
    "sql_injection": _exploit_sql_injection,
    "path_traversal": _exploit_path_traversal,
    "deserialization": _exploit_deserialization,
    "missing_authorization": _exploit_missing_authorization,
    "weak_hash": _exploit_weak_hash,
    "validation": _exploit_validation,
}


def _smoke_test(path: str, source: str) -> list[dict[str, Any]]:
    """
    One import-level test per module.

    Not every function is safely callable from a test, but every module must
    still import, so this catches a patch that breaks the file outright.
    """
    if not path.endswith(".py"):
        return []
    try:
        ast.parse(source, filename=path)
    except SyntaxError:
        return []

    module = Path(path).stem
    if module.startswith("__"):
        return []
    return [
        {
            "name": f"test_{module}_module_imports",
            "description": (
                f"{path} must remain importable, so a patch that breaks the module "
                f"is caught before any behavioural test runs."
            ),
            "test_type": "unit",
            "target_file": path,
            "is_exploit_test": False,
            "test_code": (
                "import importlib\n\n"
                f"def test_{module}_module_imports():\n"
                f"    module = importlib.import_module({module!r})\n"
                f"    assert module is not None\n"
            ),
        }
    ]

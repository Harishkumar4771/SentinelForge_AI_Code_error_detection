"""
File storage helpers for the vulnerable demo app.

FLAW: path traversal (CWE-22). The caller-supplied name is joined onto a
base directory without verifying the result stays inside it, so
`../../../../etc/passwd` escapes the document store.
"""

import os

DOCUMENT_ROOT = "/tmp/vulnerable_app_documents"

# A real deployment creates its storage directory on startup. Without this the
# traversal below cannot resolve an intermediate path and the flaw would be
# inert, so the demo would not actually demonstrate anything.
os.makedirs(DOCUMENT_ROOT, exist_ok=True)


def _resolve(name):
    """
    FLAW: no containment check.

    os.path.join discards the base directory entirely when `name` is an
    absolute path, and happily walks out of it for `../` segments.
    """
    return os.path.join(DOCUMENT_ROOT, name)


def read_user_document(doc_path):
    """FLAW: path traversal on read. Returns file contents from anywhere."""
    target = _resolve(doc_path)
    if not os.path.isfile(target):
        return None
    with open(target, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def write_user_document(name, content):
    """
    FLAW: path traversal on write.

    An attacker can write to any path the process can reach, e.g.
    name="../../home/user/.ssh/authorized_keys".
    """
    target = _resolve(name)
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(content)
    return target


def list_documents():
    """FLAW: no filtering -- the listing includes dotfiles and system paths."""
    if not os.path.isdir(DOCUMENT_ROOT):
        return []
    return os.listdir(DOCUMENT_ROOT)

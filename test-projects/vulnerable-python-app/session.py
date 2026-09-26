"""
Session handling for the vulnerable demo app.

FLAW: insecure deserialization (CWE-502). Client-supplied bytes are handed
straight to pickle.loads, which is remote code execution, not merely a
parsing bug. This is the most severe class present in the demo target.
"""

import pickle

SESSION_TTL = 3600


def serialize_session(data):
    return pickle.dumps(data)


def deserialize_session(raw):
    """
    FLAW: arbitrary code execution.

    `raw` is whatever the HTTP client sent in the request body. A payload
    such as `cos\nsystem\n(S'touch /tmp/pwned'\ntR.` executes during
    unpickling, before any application logic runs. The fix is a data-only
    format (JSON) with an explicit schema.
    """
    if not raw:
        return {}
    return pickle.loads(raw)


def cleanup_sessions(store):
    """
    FLAW (logic): the expiry comparison is inverted, so sessions are
    deleted precisely when they are still valid and kept forever once
    they have expired.
    """
    cleaned = {}
    for key, (value, expires_at) in store.items():
        if expires_at > SESSION_TTL:
            cleaned[key] = (value, expires_at)
    return cleaned

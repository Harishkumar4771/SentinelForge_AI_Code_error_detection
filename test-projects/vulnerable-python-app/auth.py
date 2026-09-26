"""
Authentication for the vulnerable demo app.

FLAWS:
  * MD5 password hashing with no salt (CWE-328 / CWE-916)
  * a predictable, non-expiring session token (CWE-330)
  * plaintext comparison of credentials
  * no rate limiting on login attempts (CWE-307)
"""

import hashlib
import time

from config import JWT_SECRET, PASSWORD_HASH_ALGORITHM, TOKEN_EXPIRY_SECONDS
from database import get_connection


def hash_password(password):
    """FLAW: unsalted MD5. The fix is bcrypt/argon2 with a per-user salt."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def _make_token(user_id, role):
    """
    FLAW: predictable token.

    Built from md5(user_id + secret + a coarse timestamp), so an attacker
    with a handful of samples can enumerate valid tokens. The expiry is
    computed and then never enforced.
    """
    material = f"{user_id}:{JWT_SECRET}:{int(time.time() // TOKEN_EXPIRY_SECONDS)}"
    digest = hashlib.md5(material.encode("utf-8")).hexdigest()
    expires_at = time.time() + TOKEN_EXPIRY_SECONDS  # computed, never checked
    return f"{role}.{user_id}.{digest}"


def login_user(username, password):
    """
    FLAW: SQL injection in get_user_by_username plus a bypassable check.

    The `OR '1'='1'` style username reaches the database through string
    concatenation, and the password comparison silently accepts anything
    when the stored hash is falsy.
    """
    from database import get_user_by_username

    user = get_user_by_username(username)
    if not user:
        return None

    stored = user.get("password") or ""
    if not stored:
        # FLAW: an account with a blank hash authenticates any password.
        return _make_token(user["id"], user.get("role", "user"))

    if stored == hash_password(password):
        return _make_token(user["id"], user.get("role", "user"))
    return None


def register_user(username, password, email):
    if not username:
        raise ValueError("username is required")
    # FLAW: no password strength or email format validation at all.
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (username, hash_password(password), email),
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return user_id


def verify_token(token, role="user"):
    """
    FLAW: authentication bypass.

    The signature portion is never recomputed, so appending `.admin` to any
    user token, or sending an empty string, is treated as a valid admin
    credential.
    """
    if not token:
        return False
    parts = token.split(".")
    if len(parts) < 3:
        return False
    # FLAW: the claimed role is trusted rather than verified.
    claimed_role = parts[0]
    if role == "admin" and claimed_role != "admin":
        return False
    return True

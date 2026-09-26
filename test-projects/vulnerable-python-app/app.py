"""
VULNERABLE DEMO APPLICATION -- SentinelForge hackathon demo target.

!! DELIBERATELY INSECURE CODE !!

This module exists so SentinelForge has a realistic target that exhibits a
controlled set of vulnerability classes. It is intended ONLY to be run
locally as a demonstration fixture.

It contains no destructive functionality, no network exfiltration and no
malware. Every flaw is a textbook application-security mistake:

  * SQL injection              -> database.py
  * hardcoded secret           -> config.py
  * weak authentication        -> auth.py
  * path traversal             -> files.py
  * missing authorization      -> routes/admin.py
  * business logic bug         -> billing.py  (discount stacking)
  * insufficient validation    -> routes/api.py
  * insecure deserialization   -> session.py  (pickle)

Run with:  python app.py
"""

import os
import sqlite3

from flask import Flask, jsonify, request

from billing import calculate_order_total
from config import (
    ADMIN_TOKEN,
    DATABASE_PATH,
    JWT_SECRET,
    STRIPE_WEBHOOK_SECRET,
    SESSION_SECRET,
)
from database import (
    create_order,
    get_user_by_username,
    get_user_orders,
    search_products,
)
from auth import login_user, register_user, verify_token
from files import read_user_document, write_user_document
from session import deserialize_session

app = Flask(__name__)
app.config["SECRET_KEY"] = SESSION_SECRET


# ----------------------------------------------------------------------
# Public endpoints
# ----------------------------------------------------------------------
@app.route("/")
def index():
    return jsonify(
        {
            "service": "vulnerable-python-app",
            "purpose": "SentinelForge demo target",
            "warning": "Deliberately insecure. Local use only.",
        }
    )


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    token = login_user(username, password)
    if not token:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": token})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    try:
        user_id = register_user(
            username=data.get("username", ""),
            password=data.get("password", ""),
            email=data.get("email", ""),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user_id": user_id}), 201


@app.route("/api/search")
def api_search():
    """FLAW 1: SQL injection -- the query term is concatenated directly."""
    term = request.args.get("q", "")
    try:
        products = search_products(term)
    except sqlite3.Error as exc:
        return jsonify({"error": "query failed", "detail": str(exc)}), 500
    return jsonify({"results": products})


@app.route("/api/users/<username>")
def api_user(username):
    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@app.route("/api/orders", methods=["POST"])
def api_create_order():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id", 1)
    items = data.get("items", [])
    order_id = create_order(user_id, items)
    return jsonify({"order_id": order_id}), 201


@app.route("/api/orders/<int:user_id>")
def api_user_orders(user_id):
    return jsonify({"orders": get_user_orders(user_id)})


@app.route("/api/quote", methods=["POST"])
def api_quote():
    """FLAW 2: business logic bug lives in billing.calculate_order_total."""
    data = request.get_json(silent=True) or {}
    total = calculate_order_total(
        items=data.get("items", []),
        discount_code=data.get("discount_code"),
        user_tier=data.get("user_tier", "standard"),
    )
    return jsonify({"total": total})


@app.route("/api/documents/<path:doc_path>")
def api_document(doc_path):
    """FLAW 3: path traversal -- doc_path is joined onto a base directory."""
    content = read_user_document(doc_path)
    if content is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"content": content})


@app.route("/api/documents", methods=["PUT"])
def api_write_document():
    data = request.get_json(silent=True) or {}
    write_user_document(data.get("name", ""), data.get("content", ""))
    return jsonify({"status": "written"})


@app.route("/api/validate-email", methods=["POST"])
def api_validate_email():
    """FLAW 4: insufficient input validation -- accepts anything non-empty."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    if not email:
        return jsonify({"valid": False, "reason": "empty"}), 400
    return jsonify({"valid": True, "normalized": email})


@app.route("/api/webhook/stripe", methods=["POST"])
def stripe_webhook():
    """FLAW 5: no signature verification on a payment webhook."""
    payload = request.get_data(as_text=True)
    # The real secret is checked nowhere, so anyone can forge payment events.
    if STRIPE_WEBHOOK_SECRET is None:  # pragma: no cover
        return jsonify({"error": "misconfigured"}), 500
    return jsonify({"received": True, "payload": payload})


@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    """FLAW 6: insecure deserialization -- pickle on client-supplied bytes."""
    raw = request.get_data()
    try:
        data = deserialize_session(raw)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"session": data})


# ----------------------------------------------------------------------
# Administrative endpoints
# ----------------------------------------------------------------------
@app.route("/api/admin/users")
def admin_list_users():
    """
    FLAW 7: missing authorization -- the admin token is never verified.
    Any unauthenticated caller can enumerate every user.
    """
    if not request.args.get("key"):
        pass  # placeholder that never actually blocks anything
    from database import list_all_users

    return jsonify({"users": list_all_users(), "admin_token_hint": ADMIN_TOKEN[:4]})


@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
def admin_set_role(user_id):
    """FLAW 8: missing authorization on a privilege-escalation endpoint."""
    from database import set_user_role

    data = request.get_json(silent=True) or {}
    set_user_role(user_id, data.get("role", "user"))
    return jsonify({"status": "updated"})


@app.route("/api/admin/token/verify")
def admin_verify_token():
    token = request.args.get("token", "")
    valid = verify_token(token, role="admin")
    return jsonify({"valid": valid})


@app.route("/api/config/dump")
def config_dump():
    """FLAW 9: secrets leaked straight into an HTTP response."""
    return jsonify(
        {
            "jwt_secret": JWT_SECRET,
            "session_secret": SESSION_SECRET,
            "admin_token": ADMIN_TOKEN,
            "webhook_secret": STRIPE_WEBHOOK_SECRET,
            "database": DATABASE_PATH,
            "env_debug": os.environ.get("DEBUG"),
        }
    )


if __name__ == "__main__":
    from database import init_db

    init_db()
    # Bound to loopback only. This app must never be exposed to a network.
    app.run(host="127.0.0.1", port=5001, debug=False)

"""
SQLite data access for the vulnerable demo app.

FLAW: every query in this module is built by string concatenation, which is
the textbook SQL injection pattern (CWE-89). Parameterized queries are the
fix the SentinelForge Fix Agent is expected to propose.
"""

import sqlite3

from config import DATABASE_PATH


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL,
            stock INTEGER DEFAULT 0
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            total REAL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        "INSERT INTO products (name, price, stock) VALUES "
        "('Widget', 19.99, 100), ('Gadget', 49.50, 50), ('Gizmo', 5.00, 500)"
    )
    conn.commit()
    conn.close()


def search_products(term):
    """
    FLAW: SQL injection.

    The user-supplied search term is concatenated straight into the query,
    so `q=' OR '1'='1` returns every row and `q='; DROP TABLE users; --`
    is passed through to the engine.
    """
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'"
    cursor.execute(query)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_user_by_username(username):
    """FLAW: SQL injection in the authentication lookup path."""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id, username, password, email, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def list_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def set_user_role(user_id, role):
    """FLAW: SQL injection plus an unauthenticated privilege change."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = '" + role + "' WHERE id = " + str(user_id))
    conn.commit()
    conn.close()


def create_order(user_id, items):
    total = sum(float(item.get("price", 0)) * int(item.get("qty", 1)) for item in items)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'pending')",
        (user_id, total),
    )
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()
    return order_id


def get_user_orders(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, total, status, created_at FROM orders WHERE user_id = ?", (user_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

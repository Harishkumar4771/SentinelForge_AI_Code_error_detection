"""
Application configuration for the vulnerable demo app.

FLAW: hardcoded secrets committed to version control (CWE-798).
Every value here is a plaintext credential.
"""

# --- FLAW: hardcoded credentials, straight from source control ---
JWT_SECRET = "s3cr3t-jwt-signing-key-do-not-use-9f2a1c"
SESSION_SECRET = "flask-session-secret-4b7e2d"
ADMIN_TOKEN = "adm_live_7f3c9a2e1b8d4056"
STRIPE_WEBHOOK_SECRET = "whsec_9a8b7c6d5e4f3a2b1c0d9e8f"
DB_PASSWORD = "rootpassword123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DATABASE_PATH = "/tmp/vulnerable_app.db"
TOKEN_EXPIRY_SECONDS = 3600
MAX_UPLOAD_SIZE = 5 * 1024 * 1024

# --- FLAW: insecure cryptography (CWE-327) ---
# MD5 with no salt is used for password hashing.
PASSWORD_HASH_ALGORITHM = "md5"
SESSION_SIGNING_ALGORITHM = "HS256"

# --- FLAW: permissive CORS ---
ALLOWED_ORIGINS = ["*"]

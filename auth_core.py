"""SQLite-backed account operations for DataSniff's Streamlit authentication."""
import os
import re
import sqlite3
import time
from pathlib import Path

import bcrypt

DB_PATH = Path(os.environ.get("DATASNIFF_DB_PATH", Path(__file__).resolve().parent / "datasniff.sqlite3"))
MAX_ATTEMPTS = 5
LOCK_SECONDS = 15 * 60
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def connect(db_path=None):
    con = sqlite3.connect(db_path or DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_auth_db(db_path=None):
    with connect(db_path) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS auth_attempts (
            email TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0
        )""")


def validate_registration(full_name, email, password, confirmation, accepted_terms):
    name = (full_name or "").strip()
    email = (email or "").strip().lower()
    if not name or len(name) > 120:
        return "Enter your name (up to 120 characters)."
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return "Enter a valid email address."
    if len(password or "") < 12 or len(password) > 64:
        return "Use a password between 12 and 64 characters."
    if not any(c.islower() for c in password) or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
        return "Include at least one uppercase letter, one lowercase letter, and one number."
    if len(password.encode("utf-8")) > 72:
        return "Password is too long for the secure password hash. Use 72 UTF-8 bytes or fewer."
    if password != confirmation:
        return "Passwords do not match."
    if not accepted_terms:
        return "Accept the terms to create an account."
    return None


def register(full_name, email, password, db_path=None):
    email = email.strip().lower()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    try:
        with connect(db_path) as con:
            con.execute("INSERT INTO accounts(full_name,email,password_hash) VALUES(?,?,?)", (full_name.strip(), email, hashed))
        return True
    except sqlite3.IntegrityError:
        return False


def authenticate(email, password, db_path=None, now=None):
    """Return an account dict on success, otherwise None; errors never reveal account existence."""
    email = (email or "").strip().lower()
    now = time.time() if now is None else now
    with connect(db_path) as con:
        attempt = con.execute("SELECT failures,locked_until FROM auth_attempts WHERE email=?", (email,)).fetchone()
        if attempt and attempt["locked_until"] > now:
            return None
        row = con.execute("SELECT id,full_name,email,password_hash FROM accounts WHERE email=?", (email,)).fetchone()
        valid = False
        if row:
            try:
                valid = bcrypt.checkpw((password or "").encode("utf-8"), bytes(row["password_hash"]))
            except (ValueError, TypeError):
                valid = False
        if valid:
            con.execute("DELETE FROM auth_attempts WHERE email=?", (email,))
            return {"id": row["id"], "full_name": row["full_name"], "email": row["email"]}
        failures = (attempt["failures"] if attempt and attempt["locked_until"] <= now else 0) + 1
        until = now + LOCK_SECONDS if failures >= MAX_ATTEMPTS else 0
        con.execute("INSERT INTO auth_attempts(email,failures,locked_until) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET failures=excluded.failures,locked_until=excluded.locked_until", (email, failures, until))
    return None

"""
database.py — All database interactions.
==========================================

We use SQLite via Python's built-in sqlite3 module.
SQLite is a single-file database — no separate server to install.
The file (vault.db) is created automatically on first run.

WHAT THE DATABASE STORES:
  ┌──────────────────────────────────────────────────────┐
  │ Table: users                                         │
  │   id          TEXT  — UUID primary key               │
  │   email       TEXT  — login identifier (plaintext)   │
  │   auth_hash   BLOB  — PBKDF2 hash, NOT the password  │
  │   auth_salt   BLOB  — random salt for auth hash      │
  │   enc_salt    BLOB  — random salt for enc key        │
  │   created_at  TEXT  — timestamp                      │
  ├──────────────────────────────────────────────────────┤
  │ Table: credentials                                   │
  │   id           TEXT — UUID primary key               │
  │   user_id      TEXT — foreign key → users.id         │
  │   site_name    TEXT — AES-GCM encrypted              │
  │   username     TEXT — AES-GCM encrypted              │
  │   password_enc TEXT — AES-GCM encrypted              │
  │   created_at   TEXT — timestamp                      │
  └──────────────────────────────────────────────────────┘

  Notice: credentials stores ONLY encrypted values for site, username,
  and password. Even if someone dumps the database, they see gibberish.
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / 'vault.db'


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # lets us access columns by name
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Create tables if they don't already exist."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                email       TEXT UNIQUE NOT NULL,
                auth_hash   BLOB NOT NULL,
                auth_salt   BLOB NOT NULL,
                enc_salt    BLOB NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                site_name    TEXT NOT NULL,
                username     TEXT NOT NULL,
                password_enc TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)


# ─── USER OPERATIONS ─────────────────────────────────────────────────────────

def create_user(email: str, auth_hash: bytes, auth_salt: bytes, enc_salt: bytes) -> str:
    """Insert a new user. Returns the new user's UUID."""
    user_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO users (id, email, auth_hash, auth_salt, enc_salt) VALUES (?, ?, ?, ?, ?)",
            (user_id, email.lower(), auth_hash, auth_salt, enc_salt)
        )
    return user_id


def get_user_by_email(email: str) -> sqlite3.Row | None:
    """Fetch a user row by email. Returns None if not found."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower(),)
        ).fetchone()


# ─── CREDENTIAL OPERATIONS ───────────────────────────────────────────────────

def add_credential(user_id: str, site_name_enc: str, username_enc: str, password_enc: str) -> str:
    """Store an encrypted credential. Returns the new credential's UUID."""
    cred_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO credentials (id, user_id, site_name, username, password_enc) VALUES (?, ?, ?, ?, ?)",
            (cred_id, user_id, site_name_enc, username_enc, password_enc)
        )
    return cred_id


def get_credentials(user_id: str) -> list[sqlite3.Row]:
    """Return all credentials for a user (all still encrypted)."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ).fetchall()


def get_credential_by_id(cred_id: str, user_id: str) -> sqlite3.Row | None:
    """Fetch a single credential — user_id check prevents accessing other users' data."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE id = ? AND user_id = ?",
            (cred_id, user_id)
        ).fetchone()


def delete_credential(cred_id: str, user_id: str) -> bool:
    """Delete a credential. user_id check ensures you can only delete your own."""
    with _connect() as conn:
        cursor = conn.execute(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?",
            (cred_id, user_id)
        )
        return cursor.rowcount > 0
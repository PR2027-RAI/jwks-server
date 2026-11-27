import sqlite3
from contextlib import contextmanager

DB_FILE = "totally_not_my_privateKeys.db"


@contextmanager
def get_connection():
    """Open and safely close a database connection."""
    conn = sqlite3.connect(DB_FILE)

    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create the required database tables."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


def store_key(encrypted_key, expiry):
    """Store an encrypted private key in the database."""
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypted_key, expiry)
        )
        return cursor.lastrowid


def count_keys(now):
    """Count valid and expired private keys."""
    with get_connection() as conn:
        valid_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp > ?",
            (now,)
        ).fetchone()[0]

        expired_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?",
            (now,)
        ).fetchone()[0]

    return valid_count, expired_count


def get_valid_keys(now):
    """Retrieve all unexpired keys."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()


def get_signing_key(now, use_expired=False):
    """Retrieve a valid or expired key for JWT signing."""
    with get_connection() as conn:
        if use_expired:
            return conn.execute(
                """
                SELECT kid, key, exp FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC LIMIT 1
                """,
                (now,)
            ).fetchone()

        return conn.execute(
            """
            SELECT kid, key, exp FROM keys
            WHERE exp > ?
            ORDER BY exp DESC LIMIT 1
            """,
            (now,)
        ).fetchone()


def create_user(username, email, password_hash):
    """Store a new registered user in the database."""
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash)
        )
        return cursor.lastrowid


def log_auth_request(request_ip, username):
    """Record an authentication request in the database."""
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        user_id = user[0] if user else None

        conn.execute(
            """
            INSERT INTO auth_logs (request_ip, user_id)
            VALUES (?, ?)
            """,
            (request_ip, user_id)
        )

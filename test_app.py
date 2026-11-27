import importlib
import sqlite3
import time
import uuid

import jwt
import pytest

import database
import security
import rate_limiter

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag


@pytest.fixture
def server(tmp_path, monkeypatch):
    """Create an isolated application for testing."""
    monkeypatch.setenv("NOT_MY_KEY", "temporary-test-key")
    monkeypatch.setattr(
        database, "DB_FILE", str(tmp_path / "test.db")
    )

    rate_limiter.request_history.clear()

    module = importlib.import_module("app")
    module = importlib.reload(module)
    module.app.config["TESTING"] = True

    yield module

    rate_limiter.request_history.clear()


@pytest.fixture
def client(server):
    """Create a Flask test client."""
    return server.app.test_client()


def get_keys():
    """Retrieve stored keys for testing."""
    with database.get_connection() as conn:
        return conn.execute(
            "SELECT kid, key, exp FROM keys"
        ).fetchall()


def test_jwks(client):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    keys = response.get_json()["keys"]
    assert len(keys) >= 1

    for key in keys:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "kid" in key
        assert "n" in key
        assert "e" in key


def test_valid_auth(client):
    response = client.post("/auth")

    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)

    keys = client.get(
        "/.well-known/jwks.json"
    ).get_json()["keys"]

    key = next(
        key for key in keys
        if key["kid"] == header["kid"]
    )

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"]
    )

    assert header["alg"] == "RS256"
    assert payload["sub"] == "fake-user"
    assert payload["exp"] > payload["iat"]


def test_expired_auth(client):
    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)

    row = next(
        row for row in get_keys()
        if str(row[0]) == header["kid"]
    )

    private_key = serialization.load_pem_private_key(
        security.decrypt_private_key(row[1]),
        password=None
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            private_key.public_key(),
            algorithms=["RS256"]
        )


def test_expired_key_not_in_jwks(client):
    response = client.get("/.well-known/jwks.json")

    kids = [
        key["kid"]
        for key in response.get_json()["keys"]
    ]

    now = int(time.time())

    for kid, key, exp in get_keys():
        if exp <= now:
            assert str(kid) not in kids
        else:
            assert str(kid) in kids


def test_database_exists(server):
    assert len(get_keys()) >= 2


@pytest.mark.parametrize(
    "table, expected",
    [
        ("keys", ["kid", "key", "exp"]),
        (
            "users",
            [
                "id",
                "username",
                "password_hash",
                "email",
                "date_registered",
                "last_login"
            ]
        ),
        (
            "auth_logs",
            [
                "id",
                "request_ip",
                "request_timestamp",
                "user_id"
            ]
        )
    ]
)
def test_database_schema(server, table, expected):
    with database.get_connection() as conn:
        columns = conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()

    assert [column[1] for column in columns] == expected


def test_stored_private_keys(server):
    for kid, key_bytes, exp in get_keys():
        assert b"-----BEGIN PRIVATE KEY-----" not in key_bytes

        decrypted = security.decrypt_private_key(key_bytes)

        private_key = serialization.load_pem_private_key(
            decrypted,
            password=None
        )

        assert private_key.key_size == 2048


def test_encryption_roundtrip(server):
    original = b"Test private key"

    encrypted = security.encrypt_private_key(original)

    assert encrypted != original
    assert security.decrypt_private_key(encrypted) == original


def test_unique_encryption_nonce(server):
    original = b"Test private key"

    first = security.encrypt_private_key(original)
    second = security.encrypt_private_key(original)

    assert first[:12] != second[:12]
    assert first != second


def test_modified_ciphertext(server):
    encrypted = security.encrypt_private_key(b"Test data")

    modified = encrypted[:-1] + bytes([encrypted[-1] ^ 1])

    with pytest.raises(InvalidTag):
        security.decrypt_private_key(modified)


def test_missing_encryption_key(server, monkeypatch):
    monkeypatch.delenv("NOT_MY_KEY")

    with pytest.raises(ValueError):
        security.get_encryption_key()


def test_register(client):
    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "test@example.com"
        }
    )

    assert response.status_code == 201

    password = response.get_json()["password"]

    assert uuid.UUID(password).version == 4

    with database.get_connection() as conn:
        user = conn.execute(
            """
            SELECT username, email, password_hash
            FROM users WHERE username = ?
            """,
            ("testuser",)
        ).fetchone()

    assert user[0] == "testuser"
    assert user[1] == "test@example.com"
    assert user[2] != password
    assert user[2].startswith("$argon2id$")
    assert security.password_hasher.verify(user[2], password)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"email": "test@example.com"},
        {"username": "testuser"},
        {"username": "", "email": "test@example.com"},
        {"username": "testuser", "email": ""},
        {"username": 123, "email": "test@example.com"}
    ]
)
def test_invalid_registration(client, data):
    response = client.post("/register", json=data)

    assert response.status_code == 400


def test_invalid_json(client):
    response = client.post(
        "/register",
        data="invalid",
        content_type="application/json"
    )

    assert response.status_code == 400


def test_duplicate_username(client):
    client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "first@example.com"
        }
    )

    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "second@example.com"
        }
    )

    assert response.status_code == 409


def test_duplicate_email(client):
    client.post(
        "/register",
        json={
            "username": "firstuser",
            "email": "test@example.com"
        }
    )

    response = client.post(
        "/register",
        json={
            "username": "seconduser",
            "email": "test@example.com"
        }
    )

    assert response.status_code == 409


def test_auth_logging(client):
    client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "test@example.com"
        }
    )

    response = client.post(
        "/auth",
        json={"username": "testuser"}
    )

    assert response.status_code == 200

    with database.get_connection() as conn:
        log = conn.execute(
            """
            SELECT request_ip, request_timestamp, user_id
            FROM auth_logs
            """
        ).fetchone()

        user_id = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            ("testuser",)
        ).fetchone()[0]

    assert log[0] == "127.0.0.1"
    assert log[1] is not None
    assert log[2] == user_id


def test_auth_without_username(client):
    response = client.post("/auth")

    assert response.status_code == 200

    with database.get_connection() as conn:
        log = conn.execute(
            "SELECT user_id FROM auth_logs"
        ).fetchone()

    assert log[0] is None


def test_rate_limiting(client, monkeypatch):
    monkeypatch.setattr(
        rate_limiter.time, "monotonic", lambda: 100.0
    )

    for i in range(10):
        response = client.post("/auth")
        assert response.status_code == 200

    response = client.post("/auth")

    assert response.status_code == 429

    with database.get_connection() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM auth_logs"
        ).fetchone()[0]

    assert count == 10


def test_rate_limit_reset(server, monkeypatch):
    monkeypatch.setattr(
        rate_limiter.time, "monotonic", lambda: 100.0
    )

    for i in range(10):
        assert not rate_limiter.is_rate_limited("127.0.0.1")

    assert rate_limiter.is_rate_limited("127.0.0.1")

    monkeypatch.setattr(
        rate_limiter.time, "monotonic", lambda: 101.1
    )

    assert not rate_limiter.is_rate_limited("127.0.0.1")


def test_separate_ip_limits(server):
    for i in range(10):
        assert not rate_limiter.is_rate_limited("192.0.2.1")

    assert rate_limiter.is_rate_limited("192.0.2.1")
    assert not rate_limiter.is_rate_limited("192.0.2.2")


def test_no_signing_key(client):
    with database.get_connection() as conn:
        conn.execute("DELETE FROM keys")

    response = client.post("/auth")

    assert response.status_code == 500


def raise_database_error(*args, **kwargs):
    raise sqlite3.OperationalError("Test database error")


def test_jwks_database_error(client, server, monkeypatch):
    monkeypatch.setattr(
        server, "get_valid_keys", raise_database_error
    )

    assert client.get(
        "/.well-known/jwks.json"
    ).status_code == 500


def test_auth_database_error(client, server, monkeypatch):
    monkeypatch.setattr(
        server, "get_signing_key", raise_database_error
    )

    assert client.post("/auth").status_code == 500


def test_logging_database_error(client, server, monkeypatch):
    monkeypatch.setattr(
        server, "log_auth_request", raise_database_error
    )

    assert client.post("/auth").status_code == 500


def test_register_database_error(client, server, monkeypatch):
    monkeypatch.setattr(
        server, "create_user", raise_database_error
    )

    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "test@example.com"
        }
    )

    assert response.status_code == 500


def test_wrong_methods(client):
    assert client.get("/auth").status_code == 405
    assert client.get("/register").status_code == 405
    assert client.post(
        "/.well-known/jwks.json"
    ).status_code == 405


def test_key_generation(server):
    assert server.generate_key().key_size == 2048


def test_base64_conversion(server):
    assert server.int_to_base64(65537) == "AQAB"

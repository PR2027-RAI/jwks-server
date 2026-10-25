
import sqlite3
import time

import jwt
import pytest
import app

from cryptography.hazmat.primitives import serialization


client = app.app.test_client()


def get_keys():
    with sqlite3.connect(app.DB_FILE) as conn:
        return conn.execute(
            "SELECT kid, key, exp FROM keys"
        ).fetchall()


def test_jwks():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert len(data["keys"]) >= 1

    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "kid" in key
        assert "n" in key
        assert "e" in key


def test_valid_auth():
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    assert header["alg"] == "RS256"
    assert payload["exp"] > payload["iat"]

    rows = get_keys()
    valid_kids = [
        str(kid) for kid, key, exp in rows
        if exp > int(time.time())
    ]

    assert header["kid"] in valid_kids


def test_expired_auth():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    assert payload["exp"] <= payload["iat"]

    rows = get_keys()
    expired_kids = [
        str(kid) for kid, key, exp in rows
        if exp <= int(time.time())
    ]

    assert header["kid"] in expired_kids


def test_expired_key_not_in_jwks():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    kids = [key["kid"] for key in data["keys"]]

    rows = get_keys()
    now = int(time.time())

    for kid, key, exp in rows:
        if exp <= now:
            assert str(kid) not in kids
        else:
            assert str(kid) in kids


def test_database_exists():
    rows = get_keys()
    assert len(rows) >= 2


def test_database_schema():
    with sqlite3.connect(app.DB_FILE) as conn:
        columns = conn.execute(
            "PRAGMA table_info(keys)"
        ).fetchall()

    names = [column[1] for column in columns]

    assert names == ["kid", "key", "exp"]


def test_stored_private_keys():
    rows = get_keys()

    for kid, key_bytes, exp in rows:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None
        )
        assert private_key.key_size >= 2048


def test_jwt_signature():
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)

    rows = get_keys()

    for kid, key_bytes, exp in rows:
        if str(kid) == header["kid"]:
            private_key = serialization.load_pem_private_key(
                key_bytes,
                password=None
            )

            public_key = private_key.public_key()

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"]
            )

            assert payload["sub"] == "fake-user"
            return

    pytest.fail("Matching key not found")


def test_wrong_methods():
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_key_generation():
    private_key = app.generate_key()
    assert private_key.key_size == 2048


def test_base64_conversion():
    assert app.int_to_base64(65537) == "AQAB"

import base64
import time
import sqlite3

import jwt
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from database import (
    init_db,
    store_key,
    count_keys,
    get_valid_keys,
    get_signing_key,
    create_user,
    log_auth_request
)
from security import (
    encrypt_private_key,
    decrypt_private_key,
    generate_password,
    hash_password
)
from rate_limiter import is_rate_limited

app = Flask(__name__)

init_db()


def generate_key():
    """Generate a 2048-bit RSA private key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key


def int_to_base64(value):
    """Convert an integer into URL-safe Base64."""
    value = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def save_key(private_key, expiry):
    """Encrypt and store a private key in the database."""
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_key = encrypt_private_key(key_bytes)

    return store_key(encrypted_key, expiry)


def setup_keys():
    """Create valid and expired RSA keys when needed."""
    now = int(time.time())

    valid_count, expired_count = count_keys(now)

    if valid_count == 0:
        save_key(generate_key(), now + 7200)

    if expired_count == 0:
        save_key(generate_key(), now - 3600)


setup_keys()


def make_jwk(private_key, kid):
    """Convert an RSA public key into JWK format."""
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e)
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all valid public keys."""
    keys = []
    now = int(time.time())

    try:
        rows = get_valid_keys(now)
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500

    for kid, key_bytes in rows:
        private_key = serialization.load_pem_private_key(
            decrypt_private_key(key_bytes),
            password=None
        )

        keys.append(make_jwk(private_key, str(kid)))

    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Generate a signed JWT and log the authentication request."""
    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "Too many requests"}), 429

    use_expired = "expired" in request.args
    now = int(time.time())

    try:
        row = get_signing_key(now, use_expired)
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500

    if row is None:
        return jsonify({"error": "No matching key found"}), 500

    kid, key_bytes, expiration = row

    private_key = serialization.load_pem_private_key(
        decrypt_private_key(key_bytes),
        password=None
    )

    payload = {
        "sub": "fake-user",
        "iat": now,
        "exp": expiration
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    data = request.get_json(silent=True)
    username = data.get("username") if isinstance(data, dict) else None

    if not isinstance(username, str):
        username = None

    try:
        log_auth_request(request.remote_addr, username)
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500

    return token, 200, {"Content-Type": "text/plain"}


@app.route("/register", methods=["POST"])
def register():
    """Register a new user with a generated password."""
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    username = data.get("username")
    email = data.get("email")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "Username is required"}), 400

    if not isinstance(email, str) or not email.strip():
        return jsonify({"error": "Email is required"}), 400

    password = generate_password()
    password_hash = hash_password(password)

    try:
        create_user(username.strip(), email.strip(), password_hash)
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    except sqlite3.Error:
        return jsonify({"error": "Database error"}), 500

    return jsonify({"password": password}), 201


if __name__ == "__main__":
    app.run(port=8080)

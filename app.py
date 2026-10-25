
from flask import Flask, jsonify, request
import jwt
import time
import uuid
import base64
import sqlite3

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        conn.commit()


init_db()


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key


def int_to_base64(value):
    value = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")



def save_key(private_key, expiry):
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (key_bytes, expiry)
        )
        conn.commit()
        return cursor.lastrowid


def setup_keys():
    now = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
        valid_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp > ?",
            (now,)
        ).fetchone()[0]

        expired_count = conn.execute(
            "SELECT COUNT(*) FROM keys WHERE exp <= ?",
            (now,)
        ).fetchone()[0]

    if valid_count == 0:
        save_key(generate_key(), now + 7200)

    if expired_count == 0:
        save_key(generate_key(), now - 3600)


setup_keys()



def make_jwk(private_key, kid):
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
    keys = []
    now = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?",
            (now,)
        ).fetchall()

    for kid, key_bytes in rows:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None
        )
        keys.append(make_jwk(private_key, str(kid)))

    return jsonify({"keys": keys}), 200




@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args
    now = int(time.time())

    with sqlite3.connect(DB_FILE) as conn:
        if use_expired:
            row = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()

    if row is None:
        return jsonify({"error": "No matching key found"}), 500

    kid, key_bytes, expiration = row

    private_key = serialization.load_pem_private_key(
        key_bytes,
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

    return token, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(port=8080)

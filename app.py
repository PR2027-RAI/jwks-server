from flask import Flask, jsonify, request
import jwt
import time
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key


def int_to_base64(value):
    value = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


valid_private_key = generate_key()
expired_private_key = generate_key()

valid_kid = str(uuid.uuid4())
expired_kid = str(uuid.uuid4())

valid_expiry = int(time.time()) + 3600
expired_expiry = int(time.time()) - 3600


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

    if valid_expiry > int(time.time()):
        keys.append(make_jwk(valid_private_key, valid_kid))

    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args

    if use_expired:
        private_key = expired_private_key
        kid = expired_kid
        expiration = expired_expiry
    else:
        private_key = valid_private_key
        kid = valid_kid
        expiration = int(time.time()) + 3600

    payload = {
        "sub": "fake-user",
        "iat": int(time.time()),
        "exp": expiration
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid}
    )

    return token, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(port=8080)
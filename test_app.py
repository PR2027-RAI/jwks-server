import jwt
import app


client = app.app.test_client()


def test_jwks():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == app.valid_kid
    assert data["keys"][0]["kty"] == "RSA"


def test_valid_auth():
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert header["kid"] == app.valid_kid
    assert payload["exp"] > payload["iat"]


def test_expired_auth():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.data.decode()
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert header["kid"] == app.expired_kid
    assert payload["exp"] < payload["iat"]


def test_expired_key_not_in_jwks():
    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert app.valid_kid in kids
    assert app.expired_kid not in kids


def test_wrong_methods():
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405
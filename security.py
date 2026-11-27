import os
import uuid
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher


password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)


def get_encryption_key():
    """Derive an AES-256 key from the environment variable."""
    secret = os.environ.get("NOT_MY_KEY")

    if not secret:
        raise ValueError("NOT_MY_KEY environment variable is missing")

    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_private_key(key_bytes):
    """Encrypt a private key using AES-GCM."""
    aes = AESGCM(get_encryption_key())
    nonce = os.urandom(12)
    encrypted_key = aes.encrypt(nonce, key_bytes, None)

    return nonce + encrypted_key


def decrypt_private_key(encrypted_data):
    """Decrypt a private key using AES-GCM."""
    aes = AESGCM(get_encryption_key())
    nonce = encrypted_data[:12]
    encrypted_key = encrypted_data[12:]

    return aes.decrypt(nonce, encrypted_key, None)


def generate_password():
    """Generate a random UUIDv4 password."""
    return str(uuid.uuid4())


def hash_password(password):
    """Hash a password using Argon2."""
    return password_hasher.hash(password)

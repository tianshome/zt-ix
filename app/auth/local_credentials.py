"""Local credential hashing and verification helpers."""

from __future__ import annotations

import hashlib
import hmac
import os

_PASSWORD_SCHEME = "pbkdf2_sha256"
_DEFAULT_DK_LEN = 32
_SALT_BYTES = 16


class LocalPasswordPolicyError(ValueError):
    """Raised when password input does not meet local policy."""


def normalize_login_username(username: str) -> str:
    normalized = username.strip().lower()
    if not normalized:
        raise ValueError("username is required")
    return normalized


def validate_password_policy(*, password: str, min_length: int) -> None:
    if len(password) < min_length:
        raise LocalPasswordPolicyError(f"password must be at least {min_length} characters")


def hash_password(
    *,
    password: str,
    min_length: int,
    iterations: int,
) -> str:
    validate_password_policy(password=password, min_length=min_length)

    salt = os.urandom(_SALT_BYTES)
    digest = _pbkdf2_sha256(password=password, salt=salt, iterations=iterations)
    return f"{_PASSWORD_SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(*, password: str, encoded_hash: str) -> bool:
    parts = encoded_hash.split("$")
    if len(parts) != 4:
        return False

    algorithm, iterations_raw, salt_raw, expected_raw = parts
    if algorithm != _PASSWORD_SCHEME:
        return False

    try:
        iterations = int(iterations_raw)
        if iterations <= 0:
            return False
        salt = bytes.fromhex(salt_raw)
        expected_digest = bytes.fromhex(expected_raw)
    except ValueError:
        return False

    if not expected_digest:
        return False

    actual_digest = _pbkdf2_sha256(
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=len(expected_digest),
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def _pbkdf2_sha256(
    *,
    password: str,
    salt: bytes,
    iterations: int,
    dklen: int = _DEFAULT_DK_LEN,
) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=dklen,
    )

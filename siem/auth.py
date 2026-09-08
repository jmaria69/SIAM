"""Autenticacion local para el acceso al SOC real."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import pyotp

SESSION_COOKIE = "siem_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return f"scrypt${n}${r}${p}${encode(salt)}${encode(digest)}"


def verify_password(password: str, encoded: str | None) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = (encoded or "").split("$")
        if algorithm != "scrypt":
            return False
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        digest = hashlib.scrypt(
            password.encode(), salt=decode(salt_text), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(digest, decode(digest_text))
    except (ValueError, TypeError):
        return False


def verify_totp(code: str, secret: str | None) -> bool:
    return bool(secret and pyotp.TOTP(secret).verify(code.strip(), valid_window=1))


def create_session(username: str, secret: str) -> str:
    payload = {"sub": username, "exp": int(time.time()) + SESSION_TTL_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{body}.{encoded_signature}"


def session_username(token: str | None, secret: str | None) -> str | None:
    if not token or not secret or "." not in token:
        return None
    body, encoded_signature = token.split(".", 1)
    expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    try:
        signature = base64.urlsafe_b64decode(encoded_signature + "=" * (-len(encoded_signature) % 4))
        payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    if not hmac.compare_digest(signature, expected) or int(payload.get("exp", 0)) < int(time.time()):
        return None
    return str(payload.get("sub")) if payload.get("sub") else None

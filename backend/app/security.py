"""Passwords, tokens, sessions and TOTP."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .clock import clock
from .config import get_settings

_hasher = PasswordHasher()

# A real hash of a random value, so that "unknown email" and "wrong password"
# take the same time and cannot be told apart.
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))

SESSION_COOKIE = "ss_session"
MFA_COOKIE = "ss_mfa"
CSRF_COOKIE = "ss_csrf"
OIDC_COOKIE = "ss_oidc"

TOTP_ISSUER = "secure-share"


# ---------------------------------------------------------------- passwords


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and bool(password_hash)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if password.lower() == password or password.upper() == password:
        problems.append("both upper and lower case letters")
    if not any(c.isdigit() for c in password):
        problems.append("at least one digit")
    return problems


# ---------------------------------------------------------------- opaque tokens


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------- signed cookies (JWT)


def _encode(payload: dict, minutes: int) -> str:
    now = clock.now()
    body = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    return jwt.encode(body, get_settings().session_secret, algorithm="HS256")


def _decode(token: str, purpose: str) -> dict | None:
    try:
        data = jwt.decode(
            token,
            get_settings().session_secret,
            algorithms=["HS256"],
            options={"verify_exp": False},
        )
    except jwt.PyJWTError:
        return None
    if data.get("purpose") != purpose:
        return None
    if data.get("exp", 0) < clock.now().timestamp():
        return None
    return data


def make_session(user: dict, mfa: bool, method: str) -> str:
    return _encode(
        {
            "purpose": "session",
            "sub": user["id"],
            "ver": user.get("token_version", 0),
            "mfa": mfa,
            "method": method,
        },
        minutes=get_settings().session_hours * 60,
    )


def read_session(token: str) -> dict | None:
    return _decode(token, "session")


def make_mfa_challenge(user: dict, method: str) -> str:
    return _encode({"purpose": "mfa", "sub": user["id"], "method": method}, minutes=5)


def read_mfa_challenge(token: str) -> dict | None:
    return _decode(token, "mfa")


def make_oidc_state(state: str, nonce: str, verifier: str) -> str:
    return _encode({"purpose": "oidc", "state": state, "nonce": nonce, "verifier": verifier}, 10)


def read_oidc_state(token: str) -> dict | None:
    return _decode(token, "oidc")


# ---------------------------------------------------------------- TOTP


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=TOTP_ISSUER)


def totp_match_step(secret: str, code: str) -> int | None:
    """Return the matching 30-second time-step (allowing one step of clock drift), or None."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now = clock.now()
    current = int(now.timestamp()) // 30
    for step in (current, current - 1, current + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None

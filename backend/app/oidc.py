"""Google OpenID Connect: authorization code flow with PKCE, nonce and ID-token verification."""

from __future__ import annotations

import httpx
import jwt

from .config import get_settings

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - URL, not a secret
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

_jwks = jwt.PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True)


class OIDCError(Exception):
    pass


def redirect_uri() -> str:
    return f"{get_settings().app_url}/api/auth/google/callback"


def exchange_code(code: str, verifier: str, nonce: str) -> dict:
    s = get_settings()
    try:
        resp = httpx.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": s.google_client_id,
                "client_secret": s.google_client_secret,
                "redirect_uri": redirect_uri(),
                "grant_type": "authorization_code",
                "code_verifier": verifier,
            },
            timeout=10,
        )
        resp.raise_for_status()
        id_token = resp.json()["id_token"]
        return verify_id_token(id_token, nonce, _jwks.get_signing_key_from_jwt(id_token).key)
    except (httpx.HTTPError, KeyError, jwt.PyJWTError) as err:
        raise OIDCError(str(err)) from err


def verify_id_token(id_token: str, nonce: str, key) -> dict:
    claims = jwt.decode(
        id_token,
        key,
        algorithms=["RS256"],
        audience=get_settings().google_client_id,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise OIDCError("unexpected issuer")
    if claims.get("nonce") != nonce:
        raise OIDCError("nonce mismatch")
    if not claims.get("email_verified"):
        raise OIDCError("email not verified")
    claims["email"] = claims["email"].lower()
    return claims

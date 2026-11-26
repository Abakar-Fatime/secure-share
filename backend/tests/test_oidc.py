import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import oidc, store
from app.config import get_settings
from app.security import make_oidc_state
from tests.conftest import make_user

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def google(monkeypatch):
    monkeypatch.setenv("SS_GOOGLE_CLIENT_ID", "client-123")
    monkeypatch.setenv("SS_GOOGLE_CLIENT_SECRET", "secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def id_token(**overrides):
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": "client-123",
        "sub": "g-1",
        "email": "Member@Example.com",
        "email_verified": True,
        "nonce": "n1",
        "iat": now,
        "exp": now + 300,
        **overrides,
    }
    return jwt.encode(claims, KEY, algorithm="RS256")


def test_valid_token(google):
    claims = oidc.verify_id_token(id_token(), "n1", KEY.public_key())
    assert claims["email"] == "member@example.com"


@pytest.mark.parametrize(
    "overrides,nonce",
    [
        ({"aud": "someone-else"}, "n1"),
        ({}, "wrong-nonce"),
        ({"email_verified": False}, "n1"),
        ({"iss": "https://evil.example"}, "n1"),
        ({"exp": int(time.time()) - 10}, "n1"),
    ],
)
def test_invalid_tokens(google, overrides, nonce):
    with pytest.raises((oidc.OIDCError, jwt.PyJWTError)):
        oidc.verify_id_token(id_token(**overrides), nonce, KEY.public_key())


def test_login_redirect_uses_pkce(google, client):
    r = client.get("/api/auth/google/login", follow_redirects=False)
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(oidc.GOOGLE_AUTH_URL)
    assert "code_challenge_method=S256" in loc and "nonce=" in loc


def _callback(client, monkeypatch, claims):
    monkeypatch.setattr(oidc, "exchange_code", lambda code, verifier, nonce: claims)
    client.cookies.set("ss_oidc", make_oidc_state("st", "n1", "v"))
    return client.get(
        "/api/auth/google/callback", params={"code": "c", "state": "st"}, follow_redirects=False
    )


def test_callback_links_existing_account(google, client, monkeypatch):
    user = make_user()
    r = _callback(client, monkeypatch, {"sub": "g-1", "email": user["email"]})
    assert r.headers["location"].endswith("/files")
    assert client.get("/api/auth/me").json()["google_linked"] is True
    assert store.get_user_by_google_sub("g-1")["id"] == user["id"]


def test_callback_requires_existing_account(google, client, monkeypatch):
    r = _callback(client, monkeypatch, {"sub": "g-2", "email": "stranger@example.com"})
    assert "error=sso_no_account" in r.headers["location"]


def test_callback_with_mfa_asks_for_code(google, client, monkeypatch):
    user = make_user(mfa=True)
    r = _callback(client, monkeypatch, {"sub": "g-1", "email": user["email"]})
    assert r.headers["location"].endswith("/login?mfa=1")
    assert client.get("/api/auth/me").status_code == 401


def test_callback_rejects_bad_state(google, client, monkeypatch):
    monkeypatch.setattr(oidc, "exchange_code", lambda *a: {"sub": "x", "email": "x@x.com"})
    client.cookies.set("ss_oidc", make_oidc_state("st", "n1", "v"))
    r = client.get(
        "/api/auth/google/callback", params={"code": "c", "state": "other"}, follow_redirects=False
    )
    assert "error=sso_state" in r.headers["location"]

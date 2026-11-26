from datetime import timedelta

import pyotp

from app import store
from app.clock import clock
from tests.conftest import PASSWORD, login, make_user, totp_now


def test_login_success_sets_session(client):
    user = make_user()
    r = login(client, user)
    assert r.json()["user"]["email"] == user["email"]
    me = client.get("/api/auth/me").json()
    assert me["role"] == "member"
    assert me["session_mfa"] is False


def test_wrong_password_and_unknown_email_look_the_same(client):
    make_user()
    a = client.post("/api/auth/login", json={"email": "member@example.com", "password": "nope"})
    b = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "nope"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_lockout_after_repeated_failures_and_alert(client):
    user = make_user()
    for _ in range(5):
        r = client.post("/api/auth/login", json={"email": user["email"], "password": "bad"})
        assert r.status_code == 401
    # Even the right password is refused while locked.
    r = client.post("/api/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.status_code == 429
    rules = {a["rule"] for a in store.list_alerts()}
    assert "brute_force" in rules
    # The lock lifts after the lock window.
    clock.freeze(clock.now() + timedelta(minutes=16))
    login(client, user)


def test_password_spray_alert(client):
    for i in range(5):
        client.post(
            "/api/auth/login",
            json={"email": f"user{i}@example.com", "password": "Summer2026!"},
            headers={"x-demo-ip": "203.0.113.9"},
        )
    alerts = store.list_alerts()
    assert any(a["rule"] == "password_spray" and a["subject"] == "203.0.113.9" for a in alerts)


def test_csrf_header_required(client):
    make_user()
    client.get("/api/health")
    r = client.post(
        "/api/auth/login",
        json={"email": "member@example.com", "password": PASSWORD},
        headers={"x-csrf-token": "forged"},
    )
    assert r.status_code == 403


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_mfa_enrolment_and_login(client):
    user = make_user()
    login(client, user)
    setup = client.post("/api/auth/mfa/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    secret = setup["secret"]
    bad = client.post("/api/auth/mfa/enable", json={"code": "000000"})
    assert bad.status_code == 400
    ok = client.post("/api/auth/mfa/enable", json={"code": pyotp.TOTP(secret).at(clock.now())})
    assert ok.status_code == 200
    assert client.get("/api/auth/me").json()["session_mfa"] is True

    # Next sign-in needs the code.
    client.post("/api/auth/logout")
    clock.freeze(clock.now() + timedelta(seconds=60))
    r = client.post("/api/auth/login", json={"email": user["email"], "password": PASSWORD})
    assert r.json() == {"mfa_required": True}
    assert client.get("/api/auth/me").status_code == 401  # no session yet
    r = client.post("/api/auth/mfa/verify", json={"code": pyotp.TOTP(secret).at(clock.now())})
    assert r.status_code == 200


def test_totp_code_cannot_be_replayed(client, make_client):
    user = make_user(mfa=True)
    login(client, user)
    code = totp_now(user["secret"])
    other = make_client()
    other.post("/api/auth/login", json={"email": user["email"], "password": PASSWORD})
    r = other.post("/api/auth/mfa/verify", json={"code": code})
    assert r.status_code == 401


def test_mfa_challenge_expires(client):
    user = make_user(mfa=True)
    client.post("/api/auth/login", json={"email": user["email"], "password": PASSWORD})
    clock.freeze(clock.now() + timedelta(minutes=6))
    r = client.post("/api/auth/mfa/verify", json={"code": totp_now(user["secret"])})
    assert r.status_code == 401


def test_admin_pages_require_mfa(client, make_client):
    admin = make_user("admin@example.com", "admin")
    login(client, admin)
    assert client.get("/api/admin/users").status_code == 403
    admin_mfa = make_user("admin2@example.com", "admin", mfa=True)
    c2 = make_client()
    login(c2, admin_mfa)
    assert c2.get("/api/admin/users").status_code == 200


def test_role_change_ends_existing_sessions(client, make_client):
    admin = make_user("admin@example.com", "admin", mfa=True)
    member = make_user()
    login(client, member)
    a = make_client()
    login(a, admin)
    r = a.patch(f"/api/admin/users/{member['id']}", json={"role": "viewer"})
    assert r.status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_session_expires(client):
    user = make_user()
    login(client, user)
    clock.freeze(clock.now() + timedelta(hours=9))
    assert client.get("/api/auth/me").status_code == 401


def test_change_password_rules_and_other_sessions_end(client, make_client):
    user = make_user()
    login(client, user)
    other = make_client()
    login(other, user)
    weak = client.post(
        "/api/auth/password", json={"current_password": PASSWORD, "new_password": "short"}
    )
    assert weak.status_code == 422
    ok = client.post(
        "/api/auth/password",
        json={"current_password": PASSWORD, "new_password": "A-Much-Better-Pass9"},
    )
    assert ok.status_code == 200
    assert client.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_invite_flow(client, make_client):
    admin = make_user("admin@example.com", "admin", mfa=True)
    login(client, admin)
    r = client.post(
        "/api/admin/users",
        json={"email": "New@Example.com", "name": "New Person", "role": "viewer"},
    )
    assert r.status_code == 201
    token = r.json()["invite_url"].rsplit("/", 1)[-1]
    dup = client.post(
        "/api/admin/users", json={"email": "new@example.com", "name": "x", "role": "viewer"}
    )
    assert dup.status_code == 409

    guest = make_client()
    weak = guest.post("/api/auth/invite/accept", json={"token": token, "password": "weak"})
    assert weak.status_code == 422
    ok = guest.post(
        "/api/auth/invite/accept", json={"token": token, "password": "Strong-Enough-123"}
    )
    assert ok.status_code == 200
    assert guest.get("/api/auth/me").json()["role"] == "viewer"
    again = make_client().post(
        "/api/auth/invite/accept", json={"token": token, "password": "Strong-Enough-123"}
    )
    assert again.status_code == 400


def test_disabled_user_cannot_sign_in(client, make_client):
    admin = make_user("admin@example.com", "admin", mfa=True)
    member = make_user()
    login(client, admin)
    client.patch(f"/api/admin/users/{member['id']}", json={"status": "disabled"})
    r = make_client().post("/api/auth/login", json={"email": member["email"], "password": PASSWORD})
    assert r.status_code == 401


def test_admin_cannot_demote_self(client):
    admin = make_user("admin@example.com", "admin", mfa=True)
    login(client, admin)
    r = client.patch(f"/api/admin/users/{admin['id']}", json={"role": "member"})
    assert r.status_code == 400


def test_mfa_disable_rules(client, make_client):
    member = make_user(mfa=True)
    login(client, member)
    clock.freeze(clock.now() + timedelta(seconds=60))
    r = client.post("/api/auth/mfa/disable", json={"code": totp_now(member["secret"])})
    assert r.status_code == 200
    admin = make_user("admin@example.com", "admin", mfa=True)
    a = make_client()
    login(a, admin)
    clock.freeze(clock.now() + timedelta(seconds=60))
    r = a.post("/api/auth/mfa/disable", json={"code": totp_now(admin["secret"])})
    assert r.status_code == 400


def test_google_not_configured(client):
    assert client.get("/api/auth/config").json() == {"google_enabled": False}
    assert client.get("/api/auth/google/login", follow_redirects=False).status_code == 404


def test_direct_origin_calls_are_rejected(monkeypatch, make_client):
    from app.config import get_settings

    monkeypatch.setenv("SS_ORIGIN_SECRET", "from-cloudfront")
    get_settings.cache_clear()
    try:
        c = make_client()
        assert c.get("/api/health").status_code == 403
        ok = c.get("/api/health", headers={"x-origin-verify": "from-cloudfront"})
        assert ok.status_code == 200
    finally:
        monkeypatch.delenv("SS_ORIGIN_SECRET")
        get_settings.cache_clear()


def test_cloudfront_headers_used_for_ip_and_country(monkeypatch, client):
    from app.config import get_settings

    monkeypatch.setenv("SS_BEHIND_CLOUDFRONT", "true")
    monkeypatch.setenv("SS_TRUST_DEMO_HEADERS", "false")
    get_settings.cache_clear()
    try:
        user = make_user()
        r = client.post(
            "/api/auth/login",
            json={"email": user["email"], "password": PASSWORD},
            headers={
                "cloudfront-viewer-address": "102.64.3.7:53122",
                "cloudfront-viewer-country": "TD",
            },
        )
        assert r.status_code == 200
        events = store.events_for_actor(user["id"], clock.now() - timedelta(minutes=1))
        assert (events[0]["ip"], events[0]["country"]) == ("102.64.3.7", "TD")
    finally:
        get_settings.cache_clear()


def test_production_refuses_default_secret(monkeypatch):
    import pytest

    from app.config import get_settings

    monkeypatch.setenv("SS_ENVIRONMENT", "production")
    monkeypatch.delenv("SS_SESSION_SECRET")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        get_settings()
    monkeypatch.undo()
    get_settings.cache_clear()

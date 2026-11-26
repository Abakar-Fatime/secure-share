from app import cli, store
from app.clock import clock
from app.lambda_handler import handler


def test_create_admin_returns_working_invite(client):
    url = cli.create_admin("Boss@Example.com", "Boss")
    assert url.startswith("http://testserver/invite/")
    user = store.get_user_by_email("boss@example.com")
    assert user["role"] == "admin" and user["status"] == "invited"
    r = client.post(
        "/api/auth/invite/accept",
        json={"token": url.rsplit("/", 1)[-1], "password": "Very-Strong-Pass-1"},
    )
    assert r.status_code == 200


def test_lambda_admin_bootstrap():
    out = handler({"ss_cli": "create-admin", "email": "a@b.td", "name": "A"}, None)
    assert "/invite/" in out["invite_url"]


def test_seed_demo_creates_data_and_alerts():
    now = clock.now()
    cli.seed_demo(days=7)
    clock.freeze(now)
    assert len(store.list_users()) == 6
    rules = {a["rule"] for a in store.list_alerts()}
    assert {"brute_force", "impossible_travel", "download_burst"} <= rules
    admin = store.get_user_by_email("admin@demo.td")
    assert admin["mfa_enabled"] is True

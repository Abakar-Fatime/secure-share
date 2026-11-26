from datetime import timedelta

from app import store
from app.clock import clock
from tests.conftest import login, make_user, upload


def _admin(make_client):
    c = make_client()
    login(c, make_user("admin@example.com", "admin", mfa=True))
    return c


def test_members_cannot_use_admin_api(client):
    login(client, make_user())
    for path in ("/api/admin/users", "/api/admin/audit", "/api/admin/alerts", "/api/admin/summary"):
        assert client.get(path).status_code == 403


def test_audit_log_and_filters(client, make_client):
    member = make_user()
    login(client, member)
    upload(client)
    client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "x"})
    admin = _admin(make_client)
    events = admin.get("/api/admin/audit").json()["events"]
    actions = {e["action"] for e in events}
    assert {"auth.login", "file.upload"} <= actions
    fails = admin.get("/api/admin/audit", params={"outcome": "failure"}).json()["events"]
    assert all(e["outcome"] == "failure" for e in fails)
    mine = admin.get("/api/admin/audit", params={"actor": "member@"}).json()["events"]
    assert mine and all(e["actor_email"] == "member@example.com" for e in mine)
    uploads = admin.get("/api/admin/audit", params={"action": "file."}).json()["events"]
    assert {e["action"] for e in uploads} == {"file.upload"}


def test_alert_lifecycle_and_summary(client, make_client):
    member = make_user()
    login(client, member, country="TD")
    clock.freeze(clock.now() + timedelta(minutes=30))
    login(client, member, country="BR")
    admin = _admin(make_client)
    alerts = admin.get("/api/admin/alerts", params={"status": "open"}).json()
    travel = next(a for a in alerts if a["rule"] == "impossible_travel")
    assert travel["severity"] == "high"
    summary = admin.get("/api/admin/summary").json()
    assert summary["totals"]["open_alerts"] >= 1
    assert summary["series"]["logins"][-1] >= 3
    r = admin.post(f"/api/admin/alerts/{travel['id']}/resolve")
    assert r.json()["status"] == "resolved"
    open_ids = [a["id"] for a in admin.get("/api/admin/alerts", params={"status": "open"}).json()]
    assert travel["id"] not in open_ids
    assert admin.post("/api/admin/alerts/nope/resolve").status_code == 404


def test_my_activity(client):
    login(client, make_user())
    upload(client)
    actions = [e["action"] for e in client.get("/api/me/activity").json()]
    assert "file.upload" in actions and "auth.login" in actions


def test_reset_mfa_and_resend_invite(client, make_client):
    member = make_user(mfa=True)
    admin = _admin(make_client)
    r = admin.patch(f"/api/admin/users/{member['id']}", json={"reset_mfa": True})
    assert r.json()["mfa_enabled"] is False
    invited = admin.post(
        "/api/admin/users", json={"email": "n@example.com", "name": "N", "role": "member"}
    ).json()
    again = admin.post(f"/api/admin/users/{invited['user']['id']}/invite")
    assert again.status_code == 200 and "/invite/" in again.json()["invite_url"]
    assert admin.post(f"/api/admin/users/{member['id']}/invite").status_code == 400
    users = admin.get("/api/admin/users").json()
    assert {u["email"] for u in users} == {
        "admin@example.com",
        "member@example.com",
        "n@example.com",
    }
    assert store.get_user(member["id"])["totp_secret"] is None

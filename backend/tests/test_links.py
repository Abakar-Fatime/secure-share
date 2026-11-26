from datetime import timedelta

from app import store
from app.clock import clock
from tests.conftest import login, make_user, upload


def _link(client, **body):
    login(client, make_user())
    f = upload(client)
    r = client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 24, **body})
    assert r.status_code == 201, r.text
    link = r.json()
    return f, link, link["url"].rsplit("/", 1)[-1]


def test_link_info_and_download(client, make_client):
    f, link, token = _link(client)
    anon = make_client()
    info = anon.get(f"/api/public/links/{token}").json()
    assert info["file_name"] == f["name"] and info["password_required"] is False
    r = anon.post(f"/api/public/links/{token}/download", json={})
    assert r.status_code == 200 and "X-Amz-Signature" in r.json()["url"]
    links = client.get(f"/api/files/{f['id']}/links").json()
    assert links[0]["download_count"] == 1


def test_token_is_not_stored(client):
    _, link, token = _link(client)
    stored = store.get_link(link["id"])
    assert token not in str(stored)


def test_unknown_token(client):
    assert client.get("/api/public/links/not-a-real-token").status_code == 404


def test_link_expires(client, make_client):
    _, _, token = _link(client, expires_in_hours=1)
    clock.freeze(clock.now() + timedelta(hours=2))
    assert make_client().get(f"/api/public/links/{token}").status_code == 410


def test_max_link_lifetime(client):
    login(client, make_user())
    f = upload(client)
    r = client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 10_000})
    assert r.status_code == 422


def test_download_limit(client, make_client):
    f, _, token = _link(client, max_downloads=2)
    anon = make_client()
    assert anon.get(f"/api/public/links/{token}").json()["downloads_remaining"] == 2
    for _ in range(2):
        assert anon.post(f"/api/public/links/{token}/download", json={}).status_code == 200
    assert anon.post(f"/api/public/links/{token}/download", json={}).status_code == 410
    states = [x["state"] for x in client.get(f"/api/files/{f['id']}/links").json()]
    assert states == ["used_up"]


def test_password_protected_link_locks_after_guessing(client, make_client):
    f, link, token = _link(client, password="open-sesame")
    anon = make_client()
    assert anon.get(f"/api/public/links/{token}").json()["password_required"] is True
    assert anon.post(f"/api/public/links/{token}/download", json={}).status_code == 401
    for _ in range(4):
        anon.post(f"/api/public/links/{token}/download", json={"password": "guess"})
    # Locked now, even with the right password.
    r = anon.post(f"/api/public/links/{token}/download", json={"password": "open-sesame"})
    assert r.status_code == 410
    assert any(a["rule"] == "link_password_guessing" for a in store.list_alerts())
    assert client.get(f"/api/files/{f['id']}/links").json()[0]["state"] == "locked"


def test_correct_password(client, make_client):
    _, _, token = _link(client, password="open-sesame")
    r = make_client().post(f"/api/public/links/{token}/download", json={"password": "open-sesame"})
    assert r.status_code == 200


def test_revoke(client, make_client):
    f, link, token = _link(client)
    assert client.delete(f"/api/links/{link['id']}").json()["state"] == "revoked"
    assert make_client().get(f"/api/public/links/{token}").status_code == 410


def test_cannot_revoke_someone_elses_link(client, make_client):
    _, link, _ = _link(client)
    other = make_client()
    login(other, make_user("other@example.com"))
    assert other.delete(f"/api/links/{link['id']}").status_code == 404


def test_mass_link_creation_alert(client):
    login(client, make_user())
    f = upload(client)
    for _ in range(10):
        client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 1})
    assert any(a["rule"] == "mass_link_creation" for a in store.list_alerts())

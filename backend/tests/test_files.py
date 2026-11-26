from datetime import timedelta

from app import store
from app.clock import clock
from app.routers.files import clean_name, content_disposition
from tests.conftest import login, make_user, upload


def test_upload_and_list(client):
    login(client, make_user())
    f = upload(client)
    assert f["status"] == "ready"
    listing = client.get("/api/files").json()
    assert [x["id"] for x in listing["owned"]] == [f["id"]]


def test_upload_size_limit(client):
    login(client, make_user())
    r = client.post("/api/files/upload-url", json={"name": "big.bin", "size": 2 * 1024 * 1024})
    assert r.status_code == 413


def test_presigned_post_restricts_size_and_key(client):
    login(client, make_user())
    r = client.post("/api/files/upload-url", json={"name": "a.txt", "size": 5}).json()
    fields = r["upload"]["fields"]
    assert fields["key"].startswith("files/")
    assert "policy" in fields


def test_complete_requires_object_in_s3(client):
    login(client, make_user())
    r = client.post("/api/files/upload-url", json={"name": "a.txt", "size": 5}).json()
    assert client.post(f"/api/files/{r['file']['id']}/complete").status_code == 400


def test_viewer_cannot_upload(client):
    login(client, make_user("v@example.com", "viewer"))
    r = client.post("/api/files/upload-url", json={"name": "a.txt", "size": 5})
    assert r.status_code == 403


def test_other_user_cannot_see_or_download(client, make_client):
    login(client, make_user())
    f = upload(client)
    other = make_client()
    login(other, make_user("other@example.com"))
    assert other.get(f"/api/files/{f['id']}/download").status_code == 404
    assert other.get("/api/files").json() == {"owned": [], "shared_with_me": []}


def test_owner_download_is_presigned_and_audited(client):
    login(client, make_user())
    f = upload(client)
    r = client.get(f"/api/files/{f['id']}/download").json()
    assert "X-Amz-Signature" in r["url"] and r["expires_in"] == 60
    events = store.events_for_day(clock.now().date().isoformat())
    assert any(e["action"] == "file.download" and e["target_id"] == f["id"] for e in events)


def test_grant_lets_viewer_download_and_revoke_removes(client, make_client):
    login(client, make_user())
    f = upload(client)
    viewer = make_user("viewer@example.com", "viewer")
    r = client.post(f"/api/files/{f['id']}/grants", json={"email": viewer["email"]})
    assert r.status_code == 201
    v = make_client()
    login(v, viewer)
    assert [x["id"] for x in v.get("/api/files").json()["shared_with_me"]] == [f["id"]]
    assert v.get(f"/api/files/{f['id']}/download").status_code == 200
    assert len(client.get(f"/api/files/{f['id']}/grants").json()) == 1
    client.delete(f"/api/files/{f['id']}/grants/{viewer['id']}")
    assert v.get(f"/api/files/{f['id']}/download").status_code == 404


def test_grant_to_unknown_or_self(client):
    login(client, make_user())
    f = upload(client)
    assert (
        client.post(
            f"/api/files/{f['id']}/grants", json={"email": "nobody@example.com"}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/files/{f['id']}/grants", json={"email": "member@example.com"}
        ).status_code
        == 400
    )


def test_delete_revokes_links(client, make_client):
    login(client, make_user())
    f = upload(client)
    link = client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 2}).json()
    assert client.delete(f"/api/files/{f['id']}").status_code == 200
    token = link["url"].rsplit("/", 1)[-1]
    assert make_client().get(f"/api/public/links/{token}").status_code == 410
    assert client.get("/api/files").json()["owned"] == []


def test_admin_can_manage_any_file(client, make_client):
    login(client, make_user())
    f = upload(client)
    admin = make_client()
    login(admin, make_user("admin@example.com", "admin", mfa=True))
    assert admin.get(f"/api/files/{f['id']}/links").status_code == 200


def test_mass_deletion_alert(client):
    login(client, make_user())
    for i in range(15):
        f = upload(client, name=f"f{i}.txt", content=b"x")
        client.delete(f"/api/files/{f['id']}")
        clock.freeze(clock.now() + timedelta(seconds=30))
    assert any(a["rule"] == "mass_deletion" for a in store.list_alerts())


def test_download_burst_alert(client):
    login(client, make_user())
    f = upload(client)
    for _ in range(20):
        client.get(f"/api/files/{f['id']}/download")
        clock.freeze(clock.now() + timedelta(seconds=20))
    alerts = [a for a in store.list_alerts() if a["rule"] == "download_burst"]
    assert len(alerts) == 1  # de-duplicated within the window


def test_clean_name():
    assert clean_name("../../etc/passwd") == "passwd"
    assert clean_name('a"b;c.pdf') == "a_b_c.pdf"
    assert clean_name("...") == "file"


def test_content_disposition_handles_unicode():
    header = content_disposition("rapport_tchad_été.pdf")
    assert 'filename="rapport_tchad_t.pdf"' in header
    assert "filename*=UTF-8''rapport_tchad_%C3%A9t%C3%A9.pdf" in header

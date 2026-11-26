import os

os.environ.update(
    {
        "SS_ENVIRONMENT": "test",
        "SS_APP_URL": "http://testserver",
        "SS_SESSION_SECRET": "test-secret-for-unit-tests-only-0123456789abcdef",
        "SS_TABLE_NAME": "secure-share-test",
        "SS_BUCKET_NAME": "secure-share-test-files",
        "SS_AWS_REGION": "ap-northeast-1",
        "SS_TRUST_DEMO_HEADERS": "true",
        "SS_MAX_UPLOAD_BYTES": "1048576",
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "ap-northeast-1",
    }
)

from datetime import UTC, datetime  # noqa: E402

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from moto import mock_aws  # noqa: E402

from app import store  # noqa: E402
from app.aws import create_local_resources, reset_clients, s3_client  # noqa: E402
from app.clock import clock  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.security import CSRF_COOKIE, hash_password  # noqa: E402

PASSWORD = "Correct-Horse-42"
START = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def aws():
    get_settings.cache_clear()
    with mock_aws():
        reset_clients()
        create_local_resources()
        clock.freeze(START)
        yield
        clock.unfreeze()
        reset_clients()


class Client(TestClient):
    """TestClient that sends the CSRF header automatically, like the real frontend."""

    def request(self, method, url, *args, **kwargs):
        if CSRF_COOKIE not in self.cookies:
            super().request("GET", "/api/health")
        headers = dict(kwargs.pop("headers", None) or {})
        headers.setdefault("x-csrf-token", self.cookies.get(CSRF_COOKIE, ""))
        return super().request(method, url, *args, headers=headers, **kwargs)


@pytest.fixture
def make_client():
    from app.main import create_app

    def factory() -> Client:
        return Client(create_app())

    return factory


@pytest.fixture
def client(make_client):
    return make_client()


def make_user(email="member@example.com", role="member", mfa=False, name="Test User"):
    user = store.create_user(email, name, role, password_hash=hash_password(PASSWORD))
    secret = None
    if mfa:
        secret = pyotp.random_base32()
        store.update_user(user["id"], mfa_enabled=True, totp_secret=secret)
    return {**store.get_user(user["id"]), "secret": secret}


def totp_now(secret: str) -> str:
    return pyotp.TOTP(secret).at(clock.now())


def login(client, user, country="TD", ip="196.1.1.1"):
    headers = {"x-demo-country": country, "x-demo-ip": ip}
    r = client.post(
        "/api/auth/login", json={"email": user["email"], "password": PASSWORD}, headers=headers
    )
    assert r.status_code == 200, r.text
    if r.json()["mfa_required"]:
        r = client.post(
            "/api/auth/mfa/verify", json={"code": totp_now(user["secret"])}, headers=headers
        )
        assert r.status_code == 200, r.text
    return r


def upload(client, name="report.pdf", content=b"%PDF-1.4 hello"):
    r = client.post(
        "/api/files/upload-url",
        json={"name": name, "size": len(content), "content_type": "application/pdf"},
    )
    assert r.status_code == 201, r.text
    f = r.json()["file"]
    # The browser would POST to S3 with the presigned form; here we write the object directly.
    stored = store.get_file(f["id"])
    s3_client().put_object(Bucket=get_settings().bucket_name, Key=stored["s3_key"], Body=content)
    r = client.post(f"/api/files/{f['id']}/complete")
    assert r.status_code == 200, r.text
    return r.json()

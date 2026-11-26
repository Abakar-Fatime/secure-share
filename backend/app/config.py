from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables prefixed with SS_."""

    model_config = SettingsConfigDict(env_prefix="SS_", env_file=".env", extra="ignore")

    environment: str = "local"
    app_url: str = "http://localhost:5173"

    # Secrets. In AWS these come from SSM Parameter Store via Lambda environment.
    session_secret: str = "change-me-local-only-session-secret-0123456789"  # noqa: S105

    # AWS resources
    aws_region: str = "ap-northeast-1"
    aws_endpoint_url: str | None = None  # set for local moto server
    # Host the *browser* uses for S3 presigned URLs (differs from aws_endpoint_url in Docker).
    s3_presign_endpoint_url: str | None = None
    table_name: str = "secure-share"
    bucket_name: str = "secure-share-files"

    # Limits and policy
    max_upload_bytes: int = 50 * 1024 * 1024
    session_hours: int = 8
    max_link_hours: int = 720
    login_max_failures: int = 5
    login_lock_minutes: int = 15
    link_max_password_failures: int = 5
    presign_seconds: int = 60

    # Cookies
    cookie_secure: bool = False

    # Google SSO (optional)
    google_client_id: str | None = None
    google_client_secret: str | None = None

    # Behind CloudFront: read the viewer IP/country from headers CloudFront sets itself.
    behind_cloudfront: bool = False
    # Shared secret CloudFront adds to every origin request, so the API rejects
    # anyone calling API Gateway directly (and forging CloudFront's headers).
    origin_secret: str | None = None

    # Only for local demos and tests: accept X-Demo-Country / X-Demo-IP headers.
    trust_demo_headers: bool = False

    @property
    def google_enabled(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)


LOCAL_SECRET = Settings.model_fields["session_secret"].default


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.environment == "production" and (
        s.session_secret == LOCAL_SECRET or len(s.session_secret) < 32
    ):
        raise RuntimeError("SS_SESSION_SECRET must be set to a long random value in production")
    return s

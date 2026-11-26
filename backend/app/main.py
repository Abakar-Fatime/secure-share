"""FastAPI application."""

from __future__ import annotations

import logging
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .deps import csrf_ok, set_cookie
from .routers import admin, auth, files, public
from .security import CSRF_COOKIE, new_token

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(
        title="secure-share API",
        version="1.0.0",
        docs_url="/api/docs" if s.environment != "production" else None,
        openapi_url="/api/openapi.json" if s.environment != "production" else None,
    )

    @app.middleware("http")
    async def csrf_and_headers(request: Request, call_next):
        if s.origin_secret and not secrets.compare_digest(
            request.headers.get("x-origin-verify", ""), s.origin_secret
        ):
            return JSONResponse({"detail": "Forbidden"}, status_code=403)
        # Double-submit cookie: state-changing requests must echo the CSRF cookie in a header.
        # A malicious site can make the browser send cookies, but cannot read them.
        if (
            request.method not in SAFE_METHODS
            and request.url.path.startswith("/api/")
            and not csrf_ok(request)
        ):
            return JSONResponse({"detail": "Missing or invalid CSRF token"}, status_code=403)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if CSRF_COOKIE not in request.cookies:
            set_cookie(response, CSRF_COOKIE, new_token(), 7 * 24 * 3600, http_only=False)
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    for r in (auth.router, files.router, public.router, admin.router):
        app.include_router(r)
    return app


app = create_app()

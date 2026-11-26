"""Shared request dependencies: who is calling, from where, and are they allowed."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, Response, status

from . import store
from .audit import RequestInfo
from .config import get_settings
from .security import CSRF_COOKIE, SESSION_COOKIE, read_session

ROLES = ("admin", "member", "viewer")


def request_info(request: Request) -> RequestInfo:
    s = get_settings()
    ip = request.client.host if request.client else "unknown"
    country = None
    if s.behind_cloudfront:
        # CloudFront sets these itself; a client cannot forge them.
        viewer = request.headers.get("cloudfront-viewer-address")
        if viewer:
            ip = viewer.rsplit(":", 1)[0].strip("[]")
        country = request.headers.get("cloudfront-viewer-country")
    if s.trust_demo_headers:
        ip = request.headers.get("x-demo-ip", ip)
        country = request.headers.get("x-demo-country", country)
    return RequestInfo(ip=ip, country=country, user_agent=request.headers.get("user-agent", ""))


def set_cookie(response: Response, name: str, value: str, max_age: int, http_only: bool = True):
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=http_only,
        secure=get_settings().cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=get_settings().cookie_secure, samesite="lax")


def session_data(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    return read_session(token) if token else None


def current_user(request: Request) -> dict:
    data = session_data(request)
    if not data:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    user = store.get_user(data["sub"])
    if (
        not user
        or user["status"] != "active"
        or int(user.get("token_version", 0)) != int(data.get("ver", -1))
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session is no longer valid")
    user["_session"] = data
    return user


def require_role(*roles: str):
    def checker(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role does not allow this")
        return user

    return checker


def require_admin(user: dict = Depends(require_role("admin"))) -> dict:
    """Admins must have passed two-step verification in this session."""
    if not user["_session"].get("mfa"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Admin pages need two-step verification. Enable it in your account settings.",
        )
    return user


def csrf_ok(request: Request) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("x-csrf-token")
    return bool(cookie and header and cookie == header)

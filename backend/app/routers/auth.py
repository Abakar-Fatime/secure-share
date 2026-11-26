"""Sign-in, two-step verification, invites and Google SSO."""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from .. import oidc, store
from ..audit import RequestInfo, record
from ..clock import clock, parse_iso
from ..config import get_settings
from ..deps import clear_cookie, current_user, request_info, set_cookie
from ..schemas import AcceptInviteIn, ChangePasswordIn, CodeIn, LoginIn
from ..security import (
    MFA_COOKIE,
    OIDC_COOKIE,
    SESSION_COOKIE,
    hash_password,
    make_mfa_challenge,
    make_oidc_state,
    make_session,
    new_totp_secret,
    password_problems,
    read_mfa_challenge,
    read_oidc_state,
    token_hash,
    totp_match_step,
    totp_uri,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "Email or password is incorrect"


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "status": user["status"],
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "google_linked": bool(user.get("google_linked")),
        "created_at": user["created_at"],
        "last_login_at": user.get("last_login_at"),
    }


def _is_locked(email: str, user: dict | None) -> bool:
    s = get_settings()
    since = clock.now() - timedelta(minutes=s.login_lock_minutes)
    if user and user.get("last_login_at"):
        since = max(since, parse_iso(user["last_login_at"]))
    return store.login_failures_since(email, since) >= s.login_max_failures


def _start_session(response: Response, user: dict, mfa: bool, method: str, info: RequestInfo):
    s = get_settings()
    set_cookie(response, SESSION_COOKIE, make_session(user, mfa, method), s.session_hours * 3600)
    clear_cookie(response, MFA_COOKIE)
    store.update_user(user["id"], last_login_at=clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    record(
        info,
        "auth.google_login" if method == "google" else "auth.login",
        actor=user,
        details={"mfa": mfa, "method": method},
    )


@router.get("/config")
def auth_config():
    return {"google_enabled": get_settings().google_enabled}


@router.post("/login")
def login(body: LoginIn, response: Response, info: RequestInfo = Depends(request_info)):
    email = body.email.lower()
    user = store.get_user_by_email(email)
    if _is_locked(email, user):
        record(
            info, "auth.login", "failure", actor=user, details={"email": email, "reason": "locked"}
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again in a few minutes.",
        )
    ok = verify_password(user.get("password_hash") if user else None, body.password)
    if not ok or not user or user["status"] != "active":
        store.record_login_failure(email, info.ip)
        record(
            info,
            "auth.login",
            "failure",
            actor=user,
            details={"email": email, "reason": "password"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_LOGIN_ERROR)
    if user.get("mfa_enabled"):
        set_cookie(response, MFA_COOKIE, make_mfa_challenge(user, "password"), 300)
        return {"mfa_required": True}
    _start_session(response, user, mfa=False, method="password", info=info)
    return {"mfa_required": False, "user": public_user(user)}


@router.post("/mfa/verify")
def mfa_verify(
    body: CodeIn, request: Request, response: Response, info: RequestInfo = Depends(request_info)
):
    challenge = read_mfa_challenge(request.cookies.get(MFA_COOKIE, ""))
    if not challenge:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired. Start again.")
    user = store.get_user(challenge["sub"])
    if not user or user["status"] != "active" or not user.get("totp_secret"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in expired. Start again.")
    if _is_locked(user["email"], user):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts.")
    step = totp_match_step(user["totp_secret"], body.code)
    if step is None or not store.use_totp_step(user["id"], step):
        store.record_login_failure(user["email"], info.ip)
        record(info, "auth.mfa", "failure", actor=user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not valid")
    _start_session(response, user, mfa=True, method=challenge["method"], info=info)
    return {"user": public_user(user)}


@router.post("/logout")
def logout(request: Request, response: Response, info: RequestInfo = Depends(request_info)):
    try:
        user = current_user(request)
        record(info, "auth.logout", actor=user)
    except HTTPException:
        pass
    clear_cookie(response, SESSION_COOKIE)
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return {**public_user(user), "session_mfa": bool(user["_session"].get("mfa"))}


@router.post("/password")
def change_password(
    body: ChangePasswordIn,
    response: Response,
    user: dict = Depends(current_user),
    info: RequestInfo = Depends(request_info),
):
    if not verify_password(user.get("password_hash"), body.current_password):
        record(info, "auth.password_change", "failure", actor=user)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(422, "Password needs " + ", ".join(problems))
    store.update_user(user["id"], password_hash=hash_password(body.new_password))
    store.bump_token_version(user["id"])  # signs out every other session
    fresh = store.get_user(user["id"])
    set_cookie(
        response,
        SESSION_COOKIE,
        make_session(fresh, bool(user["_session"].get("mfa")), user["_session"]["method"]),
        get_settings().session_hours * 3600,
    )
    record(info, "auth.password_change", actor=user)
    return {"ok": True}


# ---------------------------------------------------------------- TOTP enrolment


@router.post("/mfa/setup")
def mfa_setup(user: dict = Depends(current_user)):
    if user.get("mfa_enabled"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step verification is already on")
    secret = new_totp_secret()
    store.update_user(user["id"], totp_pending_secret=secret)
    return {"secret": secret, "otpauth_uri": totp_uri(secret, user["email"])}


@router.post("/mfa/enable")
def mfa_enable(
    body: CodeIn,
    response: Response,
    user: dict = Depends(current_user),
    info: RequestInfo = Depends(request_info),
):
    secret = user.get("totp_pending_secret")
    if not secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start setup first")
    step = totp_match_step(secret, body.code)
    if step is None:
        record(info, "mfa.enable", "failure", actor=user)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid")
    updated = store.update_user(
        user["id"],
        totp_secret=secret,
        totp_pending_secret=None,
        mfa_enabled=True,
        totp_last_step=step,
    )
    # This session has now proven the second factor.
    set_cookie(
        response,
        SESSION_COOKIE,
        make_session(updated, True, user["_session"]["method"]),
        get_settings().session_hours * 3600,
    )
    record(info, "mfa.enable", actor=user)
    return {"ok": True}


@router.post("/mfa/disable")
def mfa_disable(
    body: CodeIn, user: dict = Depends(current_user), info: RequestInfo = Depends(request_info)
):
    if not user.get("mfa_enabled"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-step verification is off")
    if user["role"] == "admin":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Admins must keep two-step verification on"
        )
    step = totp_match_step(user["totp_secret"], body.code)
    if step is None or not store.use_totp_step(user["id"], step):
        record(info, "mfa.disable", "failure", actor=user)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid")
    store.update_user(user["id"], totp_secret=None, mfa_enabled=False)
    store.bump_token_version(user["id"])
    record(info, "mfa.disable", actor=user)
    return {"ok": True}


# ---------------------------------------------------------------- invites


@router.post("/invite/accept")
def accept_invite(
    body: AcceptInviteIn, response: Response, info: RequestInfo = Depends(request_info)
):
    problems = password_problems(body.password)
    if problems:
        raise HTTPException(422, "Password needs " + ", ".join(problems))
    invite = store.consume_invite(token_hash(body.token))
    if not invite:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This invite link is invalid or expired")
    fields = {"password_hash": hash_password(body.password), "status": "active"}
    if body.name:
        fields["name"] = body.name
    user = store.update_user(invite["user_id"], **fields)
    record(info, "user.invite_accept", actor=user)
    _start_session(response, user, mfa=False, method="password", info=info)
    return {"user": public_user(user)}


# ---------------------------------------------------------------- Google SSO


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


@router.get("/google/login")
def google_login():
    s = get_settings()
    if not s.google_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Google sign-in is not configured")
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()
    params = {
        "client_id": s.google_client_id,
        "redirect_uri": oidc.redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    resp = RedirectResponse(f"{oidc.GOOGLE_AUTH_URL}?{urlencode(params)}", status_code=302)
    set_cookie(resp, OIDC_COOKIE, make_oidc_state(state, nonce, verifier), 600)
    return resp


@router.get("/google/callback")
def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    info: RequestInfo = Depends(request_info),
):
    s = get_settings()
    saved = read_oidc_state(request.cookies.get(OIDC_COOKIE, ""))
    if not saved or not code or not state or not secrets.compare_digest(saved["state"], state):
        return RedirectResponse(f"{s.app_url}/login?error=sso_state", status_code=302)
    try:
        claims = oidc.exchange_code(code, saved["verifier"], saved["nonce"])
    except oidc.OIDCError:
        return RedirectResponse(f"{s.app_url}/login?error=sso_failed", status_code=302)

    user = store.get_user_by_google_sub(claims["sub"])
    if not user:
        # Invite-only: Google can only sign in to an account an admin already created.
        user = store.get_user_by_email(claims["email"])
        if user:
            store.link_google(user["id"], claims["sub"])
            if user["status"] == "invited":
                user = store.update_user(user["id"], status="active")
    if not user or user["status"] != "active":
        record(info, "auth.google_login", "failure", details={"email": claims["email"]})
        return RedirectResponse(f"{s.app_url}/login?error=sso_no_account", status_code=302)

    if user.get("mfa_enabled"):
        resp = RedirectResponse(f"{s.app_url}/login?mfa=1", status_code=302)
        set_cookie(resp, MFA_COOKIE, make_mfa_challenge(user, "google"), 300)
    else:
        resp = RedirectResponse(f"{s.app_url}/files", status_code=302)
        _start_session(resp, user, mfa=False, method="google", info=info)
    clear_cookie(resp, OIDC_COOKIE)
    return resp

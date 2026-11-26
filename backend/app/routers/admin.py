"""Admin area: people, audit log, alerts and the security dashboard."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import store
from ..audit import RequestInfo, record
from ..clock import clock, iso
from ..config import get_settings
from ..deps import current_user, request_info, require_admin
from ..schemas import InviteIn, UserUpdateIn
from ..security import new_token, token_hash
from .auth import public_user

router = APIRouter(prefix="/api", tags=["admin"])

EVENT_FIELDS = (
    "id",
    "at",
    "action",
    "outcome",
    "actor_id",
    "actor_email",
    "ip",
    "country",
    "target_type",
    "target_id",
    "details",
)


def event_view(e: dict) -> dict:
    return {k: e.get(k) for k in EVENT_FIELDS}


def _invite_url(user_id: str) -> str:
    token = new_token()
    store.create_invite(user_id, token_hash(token))
    return f"{get_settings().app_url}/invite/{token}"


# ---------------------------------------------------------------- people


@router.get("/admin/users")
def users(_: dict = Depends(require_admin)):
    return [public_user(u) for u in store.list_users()]


@router.post("/admin/users", status_code=201)
def invite(
    body: InviteIn, admin: dict = Depends(require_admin), info: RequestInfo = Depends(request_info)
):
    try:
        user = store.create_user(body.email, body.name, body.role, status="invited")
    except store.ConflictError as err:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Someone with that email already exists"
        ) from err
    record(
        info,
        "user.invite",
        actor=admin,
        target_type="user",
        target_id=user["id"],
        details={"email": user["email"], "role": body.role},
    )
    return {"user": public_user(user), "invite_url": _invite_url(user["id"])}


@router.post("/admin/users/{user_id}/invite")
def resend_invite(user_id: str, admin: dict = Depends(require_admin)):
    user = store.get_user(user_id)
    if not user or user["status"] != "invited":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This person has already joined")
    return {"invite_url": _invite_url(user_id)}


@router.patch("/admin/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdateIn,
    admin: dict = Depends(require_admin),
    info: RequestInfo = Depends(request_info),
):
    user = store.get_user(user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user_id == admin["id"] and (body.role not in (None, "admin") or body.status == "disabled"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot demote or disable yourself")
    fields: dict = {}
    if body.role and body.role != user["role"]:
        fields["role"] = body.role
    if body.status and body.status != user["status"] and user["status"] != "invited":
        fields["status"] = body.status
    if body.reset_mfa:
        fields.update(mfa_enabled=False, totp_secret=None)
    if not fields:
        return public_user(user)
    updated = store.update_user(user_id, **fields)
    store.bump_token_version(user_id)  # their open sessions end immediately
    record(
        info,
        "user.update",
        actor=admin,
        target_type="user",
        target_id=user_id,
        details={k: v for k, v in fields.items() if k != "totp_secret"},
    )
    return public_user(updated)


# ---------------------------------------------------------------- audit log


@router.get("/admin/audit")
def audit_log(
    day: date | None = None,
    action: str | None = Query(default=None, max_length=50),
    actor: str | None = Query(default=None, max_length=200),
    outcome: str | None = Query(default=None, pattern="^(success|failure)$"),
    _: dict = Depends(require_admin),
):
    day_s = (day or clock.now().date()).isoformat()
    events = store.events_for_day(day_s)
    if action:
        events = [e for e in events if e["action"].startswith(action)]
    if actor:
        needle = actor.lower()
        events = [
            e
            for e in events
            if needle in (e.get("actor_email") or "")
            or needle in str((e.get("details") or {}).get("email", ""))
        ]
    if outcome:
        events = [e for e in events if e.get("outcome") == outcome]
    return {"day": day_s, "events": [event_view(e) for e in events[:500]]}


@router.get("/me/activity")
def my_activity(user: dict = Depends(current_user)):
    events = store.events_for_actor(user["id"], clock.now() - timedelta(days=30), limit=50)
    return [event_view(e) for e in events]


# ---------------------------------------------------------------- alerts & dashboard


@router.get("/admin/alerts")
def alerts(
    status_filter: str | None = Query(default=None, alias="status", pattern="^(open|resolved)$"),
    _: dict = Depends(require_admin),
):
    items = store.list_alerts(200)
    if status_filter:
        items = [a for a in items if a["status"] == status_filter]
    return items


@router.post("/admin/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: str, admin: dict = Depends(require_admin), info: RequestInfo = Depends(request_info)
):
    if not store.get_alert(alert_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    updated = store.update_alert(
        alert_id, status="resolved", resolved_by=admin["email"], resolved_at=iso(clock.now())
    )
    record(info, "alert.resolve", actor=admin, target_type="alert", target_id=alert_id)
    return updated


@router.get("/admin/summary")
def summary(days: int = Query(default=14, ge=1, le=31), _: dict = Depends(require_admin)):
    today = clock.now().date()
    day_list = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    per_day: dict[str, Counter] = defaultdict(Counter)
    actions: Counter = Counter()
    countries: Counter = Counter()
    users_active: Counter = Counter()
    for d in day_list:
        for e in store.events_for_day(d):
            key = e["action"] if e.get("outcome") == "success" else f"{e['action']}:failure"
            per_day[d][key] += 1
            actions[key] += 1
            if e.get("country"):
                countries[e["country"]] += 1
            if e.get("actor_email"):
                users_active[e["actor_email"]] += 1
    alerts_all = store.list_alerts(200)
    open_alerts = [a for a in alerts_all if a["status"] == "open"]
    return {
        "days": day_list,
        "series": {
            "logins": [
                per_day[d]["auth.login"] + per_day[d]["auth.google_login"] for d in day_list
            ],
            "failed_logins": [
                per_day[d]["auth.login:failure"] + per_day[d]["auth.mfa:failure"] for d in day_list
            ],
            "uploads": [per_day[d]["file.upload"] for d in day_list],
            "downloads": [
                per_day[d]["file.download"] + per_day[d]["link.download"] for d in day_list
            ],
        },
        "totals": {
            "events": sum(actions.values()),
            "failed_logins": actions["auth.login:failure"] + actions["auth.mfa:failure"],
            "external_downloads": actions["link.download"],
            "open_alerts": len(open_alerts),
            "high_alerts": sum(1 for a in open_alerts if a["severity"] == "high"),
        },
        "top_users": users_active.most_common(5),
        "countries": countries.most_common(8),
        "alerts_by_rule": Counter(a["rule"] for a in alerts_all).most_common(),
    }

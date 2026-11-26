"""Anonymous access through an external share link."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from .. import store
from ..audit import RequestInfo, record
from ..clock import clock, iso
from ..config import get_settings
from ..deps import request_info
from ..schemas import PublicDownloadIn
from ..security import token_hash, verify_password
from .files import presigned_download

router = APIRouter(prefix="/api/public", tags=["public"])

GONE = "This link is no longer available"


def _usable(token: str) -> tuple[dict, dict]:
    link = store.get_link_by_token_hash(token_hash(token))
    if not link:
        raise HTTPException(status.HTTP_404_NOT_FOUND, GONE)
    exhausted = link.get("max_downloads") and link["download_count"] >= link["max_downloads"]
    if link["revoked"] or link.get("locked") or exhausted or link["expires_at"] <= iso(clock.now()):
        raise HTTPException(status.HTTP_410_GONE, GONE)
    f = store.get_file(link["file_id"])
    if not f or f["status"] != "ready":
        raise HTTPException(status.HTTP_410_GONE, GONE)
    return link, f


@router.get("/links/{token}")
def link_info(token: str):
    link, f = _usable(token)
    remaining = None
    if link.get("max_downloads"):
        remaining = link["max_downloads"] - link["download_count"]
    return {
        "file_name": f["name"],
        "size": f["size"],
        "expires_at": link["expires_at"],
        "password_required": link["password_protected"],
        "downloads_remaining": remaining,
    }


@router.post("/links/{token}/download")
def link_download(token: str, body: PublicDownloadIn, info: RequestInfo = Depends(request_info)):
    s = get_settings()
    link, f = _usable(token)
    owner = {"owner_id": link["owner_id"], "file_id": f["id"]}
    if link["password_protected"] and not verify_password(
        link["password_hash"], body.password or ""
    ):
        failures = store.add_link_password_failure(link["id"])
        if failures >= s.link_max_password_failures:
            store.update_link(link["id"], locked=True)
        record(
            info,
            "link.password_failure",
            "failure",
            target_type="link",
            target_id=link["id"],
            details={**owner, "failures": failures},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong password")
    if store.count_link_download(link["id"]) is None:
        raise HTTPException(status.HTTP_410_GONE, GONE)
    record(info, "link.download", target_type="link", target_id=link["id"], details=owner)
    return {"url": presigned_download(f), "file_name": f["name"]}

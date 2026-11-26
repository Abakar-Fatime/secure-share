"""Uploads, downloads, internal sharing and external share links.

File bytes never pass through the API: the browser uploads to and downloads from S3
using short-lived presigned URLs that only the API can create after checking access.
"""

from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import quote

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status

from .. import store
from ..audit import RequestInfo, record
from ..aws import s3_client, s3_presign_client
from ..clock import clock, iso
from ..config import get_settings
from ..deps import current_user, request_info, require_role
from ..schemas import GrantIn, LinkIn, UploadIn
from ..security import hash_password, new_token, token_hash

router = APIRouter(prefix="/api", tags=["files"])

_UNSAFE = re.compile(r"[^\w.\- ()\[\]]+")


def clean_name(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _UNSAFE.sub("_", name).strip(" .")
    return name[:255] or "file"


def file_view(f: dict, user: dict) -> dict:
    return {
        "id": f["id"],
        "name": f["name"],
        "size": f["size"],
        "content_type": f["content_type"],
        "status": f["status"],
        "owner_id": f["owner_id"],
        "created_at": f["created_at"],
        "is_owner": f["owner_id"] == user["id"],
    }


def link_view(link: dict) -> dict:
    now = iso(clock.now())
    if link["revoked"]:
        state = "revoked"
    elif link["expires_at"] <= now:
        state = "expired"
    elif link.get("max_downloads") and link["download_count"] >= link["max_downloads"]:
        state = "used_up"
    elif link.get("locked"):
        state = "locked"
    else:
        state = "active"
    return {
        "id": link["id"],
        "file_id": link["file_id"],
        "expires_at": link["expires_at"],
        "max_downloads": link.get("max_downloads"),
        "download_count": link["download_count"],
        "password_protected": link["password_protected"],
        "state": state,
        "created_at": link["created_at"],
    }


def owned_file(file_id: str, user: dict) -> dict:
    f = store.get_file(file_id)
    if not f or f["status"] == "deleted":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    if f["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return f


def readable_file(file_id: str, user: dict) -> dict:
    f = store.get_file(file_id)
    if not f or f["status"] != "ready":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    allowed = (
        f["owner_id"] == user["id"]
        or user["role"] == "admin"
        or store.get_grant(file_id, user["id"]) is not None
    )
    if not allowed:
        # 404 rather than 403: do not reveal that the file exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return f


def content_disposition(name: str) -> str:
    ascii_name = name.encode("ascii", "ignore").decode() or "file"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"


def presigned_download(f: dict) -> str:
    s = get_settings()
    return s3_presign_client().generate_presigned_url(
        "get_object",
        Params={
            "Bucket": s.bucket_name,
            "Key": f["s3_key"],
            "ResponseContentDisposition": content_disposition(f["name"]),
            "ResponseContentType": "application/octet-stream",
        },
        ExpiresIn=s.presign_seconds,
    )


# ---------------------------------------------------------------- files


@router.get("/files")
def list_files(user: dict = Depends(current_user)):
    owned = store.list_files_by_owner(user["id"])
    shared = store.list_files_shared_with(user["id"])
    return {
        "owned": [file_view(f, user) for f in owned if f["status"] == "ready"],
        "shared_with_me": [file_view(f, user) for f in shared],
    }


@router.post("/files/upload-url", status_code=201)
def create_upload(
    body: UploadIn,
    user: dict = Depends(require_role("admin", "member")),
):
    s = get_settings()
    if body.size > s.max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Files can be at most {s.max_upload_bytes // (1024 * 1024)} MB",
        )
    f = store.create_file(user["id"], clean_name(body.name), body.size, body.content_type[:120])
    post = s3_presign_client().generate_presigned_post(
        Bucket=s.bucket_name,
        Key=f["s3_key"],
        Fields={"Content-Type": f["content_type"]},
        Conditions=[
            ["content-length-range", 1, s.max_upload_bytes],
            {"Content-Type": f["content_type"]},
        ],
        ExpiresIn=300,
    )
    return {"file": file_view(f, user), "upload": post}


@router.post("/files/{file_id}/complete")
def complete_upload(
    file_id: str,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    f = store.get_file(file_id)
    if not f or f["owner_id"] != user["id"] or f["status"] != "pending":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Upload not found")
    s = get_settings()
    try:
        head = s3_client().head_object(Bucket=s.bucket_name, Key=f["s3_key"])
    except ClientError as err:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The file was not uploaded") from err
    size = int(head["ContentLength"])
    f = store.update_file(file_id, status="ready", size=size)
    record(
        info,
        "file.upload",
        actor=user,
        target_type="file",
        target_id=file_id,
        details={"name": f["name"], "size": size},
    )
    return file_view(f, user)


@router.get("/files/{file_id}/download")
def download(
    file_id: str, user: dict = Depends(current_user), info: RequestInfo = Depends(request_info)
):
    f = readable_file(file_id, user)
    record(
        info,
        "file.download",
        actor=user,
        target_type="file",
        target_id=file_id,
        details={"name": f["name"]},
    )
    return {"url": presigned_download(f), "expires_in": get_settings().presign_seconds}


@router.delete("/files/{file_id}")
def delete_file(
    file_id: str,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    f = owned_file(file_id, user)
    s = get_settings()
    s3_client().delete_object(Bucket=s.bucket_name, Key=f["s3_key"])
    for link in store.list_links_for_file(file_id):
        if not link["revoked"]:
            store.update_link(link["id"], revoked=True)
    for grant in store.list_grants_for_file(file_id):
        store.delete_grant(file_id, grant["user_id"])
    store.update_file(file_id, status="deleted", deleted_at=iso(clock.now()))
    record(
        info,
        "file.delete",
        actor=user,
        target_type="file",
        target_id=file_id,
        details={"name": f["name"]},
    )
    return {"ok": True}


# ---------------------------------------------------------------- internal sharing


@router.get("/files/{file_id}/grants")
def list_grants(file_id: str, user: dict = Depends(require_role("admin", "member"))):
    owned_file(file_id, user)
    out = []
    for g in store.list_grants_for_file(file_id):
        u = store.get_user(g["user_id"])
        if u:
            out.append(
                {
                    "user_id": u["id"],
                    "email": u["email"],
                    "name": u["name"],
                    "created_at": g["created_at"],
                }
            )
    return out


@router.post("/files/{file_id}/grants", status_code=201)
def add_grant(
    file_id: str,
    body: GrantIn,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    f = owned_file(file_id, user)
    target = store.get_user_by_email(body.email)
    if not target or target["status"] == "disabled":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No colleague with that email")
    if target["id"] == f["owner_id"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You already own this file")
    store.put_grant(file_id, target["id"], user["id"])
    record(
        info,
        "grant.create",
        actor=user,
        target_type="file",
        target_id=file_id,
        details={"to": target["email"]},
    )
    return {"user_id": target["id"], "email": target["email"], "name": target["name"]}


@router.delete("/files/{file_id}/grants/{user_id}")
def remove_grant(
    file_id: str,
    user_id: str,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    owned_file(file_id, user)
    store.delete_grant(file_id, user_id)
    record(
        info,
        "grant.delete",
        actor=user,
        target_type="file",
        target_id=file_id,
        details={"user_id": user_id},
    )
    return {"ok": True}


# ---------------------------------------------------------------- external links


@router.get("/files/{file_id}/links")
def list_links(file_id: str, user: dict = Depends(require_role("admin", "member"))):
    owned_file(file_id, user)
    return [link_view(link) for link in store.list_links_for_file(file_id)]


@router.post("/files/{file_id}/links", status_code=201)
def create_link(
    file_id: str,
    body: LinkIn,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    s = get_settings()
    f = owned_file(file_id, user)
    if f["status"] != "ready":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is not ready")
    if body.expires_in_hours > s.max_link_hours:
        raise HTTPException(422, f"Links can last at most {s.max_link_hours // 24} days")
    token = new_token()
    link = store.create_link(
        file_id,
        user["id"],
        token_hash(token),
        clock.now() + timedelta(hours=body.expires_in_hours),
        body.max_downloads,
        hash_password(body.password) if body.password else None,
    )
    record(
        info,
        "link.create",
        actor=user,
        target_type="link",
        target_id=link["id"],
        details={
            "file_id": file_id,
            "hours": body.expires_in_hours,
            "password": body.password is not None,
            "max_downloads": body.max_downloads,
        },
    )
    # The token is shown exactly once; only its hash is stored.
    return {**link_view(link), "url": f"{s.app_url}/s/{token}"}


@router.delete("/links/{link_id}")
def revoke_link(
    link_id: str,
    user: dict = Depends(require_role("admin", "member")),
    info: RequestInfo = Depends(request_info),
):
    link = store.get_link(link_id)
    if not link or (link["owner_id"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Link not found")
    link = store.update_link(link_id, revoked=True)
    record(info, "link.revoke", actor=user, target_type="link", target_id=link_id)
    return link_view(link)

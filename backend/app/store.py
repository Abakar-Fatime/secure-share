"""DynamoDB data access (single-table design).

Key layout (PK / SK):
  USER#<id>          / PROFILE          user record          GSI1: USERS / <email>
  USER#<id>          / SEEN#COUNTRY#<cc> first time a country was seen for this user
  EMAIL#<email>      / USER             uniqueness lock + email lookup
  GSUB#<google sub>  / USER             Google account lookup
  INVITE#<hash>      / META             one-time invite token (TTL)
  LOGINFAIL#<email>  / <ts>#<rand>      failed login attempt   GSI1: FAILIP#<ip> / <ts> (TTL)
  FILE#<id>          / META             file metadata          GSI1: OWNER#<user> / <ts>
  FILE#<id>          / GRANT#<user>     internal share         GSI1: GRANTEE#<user> / <ts>
  LINK#<id>          / META             external share link    GSI1: FILELINKS#<file> / <ts>
  TOKEN#<hash>       / LINK             link token lookup (only the SHA-256 of the token is stored)
  AUDIT#<yyyy-mm-dd> / <ts>#<id>        audit event            GSI1: ACTOR#<user|anon> / <ts>
  ALERT#<id>         / META             security alert         GSI1: ALERTS / <ts>
  ALERTKEY#<key>     / LOCK             alert de-duplication (TTL)
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from .aws import dynamodb_table
from .clock import clock, iso


class ConflictError(Exception):
    pass


def _clean(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


_INTERNAL = {"PK", "SK", "GSI1PK", "GSI1SK", "ttl"}


def _public(item: dict | None) -> dict | None:
    if item is None:
        return None
    return {k: v for k, v in _clean(item).items() if k not in _INTERNAL}


def _to_ddb(value: Any) -> Any:
    """DynamoDB does not accept Python floats; store them as Decimal."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_ddb(v) for v in value]
    return value


def new_id() -> str:
    return uuid.uuid4().hex


def _ttl(dt: datetime) -> int:
    return int(dt.timestamp())


def _query_all(**kwargs) -> list[dict]:
    table = dynamodb_table()
    items: list[dict] = []
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def _is_conditional_failure(err: ClientError) -> bool:
    return err.response["Error"]["Code"] in (
        "ConditionalCheckFailedException",
        "TransactionCanceledException",
    )


# ---------------------------------------------------------------- users


def create_user(
    email: str,
    name: str,
    role: str,
    password_hash: str | None = None,
    status: str = "active",
) -> dict:
    email = email.lower().strip()
    user_id = new_id()
    now = iso(clock.now())
    item = {
        "PK": f"USER#{user_id}",
        "SK": "PROFILE",
        "GSI1PK": "USERS",
        "GSI1SK": email,
        "id": user_id,
        "email": email,
        "name": name,
        "role": role,
        "status": status,
        "password_hash": password_hash,
        "mfa_enabled": False,
        "token_version": 0,
        "created_at": now,
    }
    client = dynamodb_table().meta.client
    name_t = dynamodb_table().name
    try:
        client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": name_t,
                        "Item": {"PK": f"EMAIL#{email}", "SK": "USER", "user_id": user_id},
                        "ConditionExpression": "attribute_not_exists(PK)",
                    }
                },
                {"Put": {"TableName": name_t, "Item": item}},
            ]
        )
    except ClientError as err:
        if _is_conditional_failure(err):
            raise ConflictError("email already registered") from err
        raise
    return _public(item)


def get_user(user_id: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"USER#{user_id}", "SK": "PROFILE"})
    return _public(resp.get("Item"))


def get_user_by_email(email: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"EMAIL#{email.lower().strip()}", "SK": "USER"})
    item = resp.get("Item")
    return get_user(item["user_id"]) if item else None


def get_user_by_google_sub(sub: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"GSUB#{sub}", "SK": "USER"})
    item = resp.get("Item")
    return get_user(item["user_id"]) if item else None


def link_google(user_id: str, sub: str) -> None:
    dynamodb_table().put_item(Item={"PK": f"GSUB#{sub}", "SK": "USER", "user_id": user_id})
    update_user(user_id, google_linked=True)


def update_user(user_id: str, **fields: Any) -> dict:
    if not fields:
        return get_user(user_id)  # type: ignore[return-value]
    names = {f"#f{i}": k for i, k in enumerate(fields)}
    values = {f":v{i}": v for i, v in enumerate(fields.values())}
    expr = "SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
    resp = dynamodb_table().update_item(
        Key={"PK": f"USER#{user_id}", "SK": "PROFILE"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ConditionExpression="attribute_exists(PK)",
        ReturnValues="ALL_NEW",
    )
    return _public(resp["Attributes"])  # type: ignore[return-value]


def bump_token_version(user_id: str) -> None:
    dynamodb_table().update_item(
        Key={"PK": f"USER#{user_id}", "SK": "PROFILE"},
        UpdateExpression="ADD token_version :one",
        ExpressionAttributeValues={":one": 1},
    )


def use_totp_step(user_id: str, step: int) -> bool:
    """Record the TOTP time-step just used. Returns False if it was already used (replay)."""
    try:
        dynamodb_table().update_item(
            Key={"PK": f"USER#{user_id}", "SK": "PROFILE"},
            UpdateExpression="SET totp_last_step = :s",
            ConditionExpression="attribute_not_exists(totp_last_step) OR totp_last_step < :s",
            ExpressionAttributeValues={":s": step},
        )
        return True
    except ClientError as err:
        if _is_conditional_failure(err):
            return False
        raise


def list_users() -> list[dict]:
    items = _query_all(IndexName="GSI1", KeyConditionExpression=Key("GSI1PK").eq("USERS"))
    return [_public(i) for i in items]  # type: ignore[misc]


def mark_country_seen(user_id: str, country: str) -> bool:
    """Returns True if this is the first time the country is seen for the user."""
    try:
        dynamodb_table().put_item(
            Item={
                "PK": f"USER#{user_id}",
                "SK": f"SEEN#COUNTRY#{country}",
                "first_seen": iso(clock.now()),
            },
            ConditionExpression="attribute_not_exists(PK)",
        )
        return True
    except ClientError as err:
        if _is_conditional_failure(err):
            return False
        raise


def seen_countries(user_id: str) -> list[str]:
    items = _query_all(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_id}")
        & Key("SK").begins_with("SEEN#COUNTRY#")
    )
    return [i["SK"].rsplit("#", 1)[-1] for i in items]


# ---------------------------------------------------------------- invites


def create_invite(user_id: str, token_hash: str, hours: int = 72) -> None:
    expires = clock.now() + timedelta(hours=hours)
    dynamodb_table().put_item(
        Item={
            "PK": f"INVITE#{token_hash}",
            "SK": "META",
            "user_id": user_id,
            "expires_at": iso(expires),
            "ttl": _ttl(expires),
        }
    )


def consume_invite(token_hash: str) -> dict | None:
    try:
        resp = dynamodb_table().delete_item(
            Key={"PK": f"INVITE#{token_hash}", "SK": "META"},
            ConditionExpression="attribute_exists(PK) AND expires_at > :now",
            ExpressionAttributeValues={":now": iso(clock.now())},
            ReturnValues="ALL_OLD",
        )
    except ClientError as err:
        if _is_conditional_failure(err):
            return None
        raise
    return _clean(resp.get("Attributes"))


# ---------------------------------------------------------------- login failures


def record_login_failure(email: str, ip: str) -> None:
    now = clock.now()
    ts = iso(now)
    dynamodb_table().put_item(
        Item={
            "PK": f"LOGINFAIL#{email.lower()}",
            "SK": f"{ts}#{secrets.token_hex(4)}",
            "GSI1PK": f"FAILIP#{ip}",
            "GSI1SK": ts,
            "email": email.lower(),
            "ip": ip,
            "at": ts,
            "ttl": _ttl(now + timedelta(days=1)),
        }
    )


def login_failures_since(email: str, since: datetime) -> int:
    items = _query_all(
        KeyConditionExpression=Key("PK").eq(f"LOGINFAIL#{email.lower()}")
        & Key("SK").gte(iso(since))
    )
    return len(items)


def failed_emails_from_ip_since(ip: str, since: datetime) -> set[str]:
    items = _query_all(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"FAILIP#{ip}") & Key("GSI1SK").gte(iso(since)),
    )
    return {i["email"] for i in items}


# ---------------------------------------------------------------- files


def create_file(owner_id: str, name: str, size: int, content_type: str) -> dict:
    file_id = new_id()
    now = iso(clock.now())
    item = {
        "PK": f"FILE#{file_id}",
        "SK": "META",
        "GSI1PK": f"OWNER#{owner_id}",
        "GSI1SK": now,
        "id": file_id,
        "owner_id": owner_id,
        "name": name,
        "size": size,
        "content_type": content_type,
        "s3_key": f"files/{owner_id}/{file_id}",
        "status": "pending",
        "created_at": now,
    }
    dynamodb_table().put_item(Item=item)
    return _public(item)  # type: ignore[return-value]


def get_file(file_id: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"FILE#{file_id}", "SK": "META"})
    return _public(resp.get("Item"))


def update_file(file_id: str, **fields: Any) -> dict:
    names = {f"#f{i}": k for i, k in enumerate(fields)}
    values = {f":v{i}": v for i, v in enumerate(fields.values())}
    expr = "SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
    resp = dynamodb_table().update_item(
        Key={"PK": f"FILE#{file_id}", "SK": "META"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return _public(resp["Attributes"])  # type: ignore[return-value]


def list_files_by_owner(owner_id: str) -> list[dict]:
    items = _query_all(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"OWNER#{owner_id}"),
        ScanIndexForward=False,
    )
    return [_public(i) for i in items if i.get("status") != "deleted"]  # type: ignore[misc]


def put_grant(file_id: str, user_id: str, granted_by: str) -> dict:
    now = iso(clock.now())
    item = {
        "PK": f"FILE#{file_id}",
        "SK": f"GRANT#{user_id}",
        "GSI1PK": f"GRANTEE#{user_id}",
        "GSI1SK": now,
        "file_id": file_id,
        "user_id": user_id,
        "granted_by": granted_by,
        "created_at": now,
    }
    dynamodb_table().put_item(Item=item)
    return _public(item)  # type: ignore[return-value]


def get_grant(file_id: str, user_id: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"FILE#{file_id}", "SK": f"GRANT#{user_id}"})
    return _public(resp.get("Item"))


def delete_grant(file_id: str, user_id: str) -> None:
    dynamodb_table().delete_item(Key={"PK": f"FILE#{file_id}", "SK": f"GRANT#{user_id}"})


def list_grants_for_file(file_id: str) -> list[dict]:
    items = _query_all(
        KeyConditionExpression=Key("PK").eq(f"FILE#{file_id}") & Key("SK").begins_with("GRANT#")
    )
    return [_public(i) for i in items]  # type: ignore[misc]


def list_files_shared_with(user_id: str) -> list[dict]:
    grants = _query_all(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"GRANTEE#{user_id}"),
        ScanIndexForward=False,
    )
    files = [get_file(g["file_id"]) for g in grants]
    return [f for f in files if f and f["status"] == "ready"]


# ---------------------------------------------------------------- share links


def create_link(
    file_id: str,
    owner_id: str,
    token_hash: str,
    expires_at: datetime,
    max_downloads: int | None,
    password_hash: str | None,
) -> dict:
    link_id = new_id()
    now = iso(clock.now())
    item: dict[str, Any] = {
        "PK": f"LINK#{link_id}",
        "SK": "META",
        "GSI1PK": f"FILELINKS#{file_id}",
        "GSI1SK": now,
        "id": link_id,
        "file_id": file_id,
        "owner_id": owner_id,
        "expires_at": iso(expires_at),
        "download_count": 0,
        "password_protected": password_hash is not None,
        "password_hash": password_hash,
        "revoked": False,
        "failed_passwords": 0,
        "created_at": now,
    }
    if max_downloads is not None:
        item["max_downloads"] = max_downloads
    table = dynamodb_table()
    table.put_item(Item=item)
    table.put_item(Item={"PK": f"TOKEN#{token_hash}", "SK": "LINK", "link_id": link_id})
    return _public(item)  # type: ignore[return-value]


def get_link(link_id: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"LINK#{link_id}", "SK": "META"})
    return _public(resp.get("Item"))


def get_link_by_token_hash(token_hash: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"TOKEN#{token_hash}", "SK": "LINK"})
    item = resp.get("Item")
    return get_link(item["link_id"]) if item else None


def list_links_for_file(file_id: str) -> list[dict]:
    items = _query_all(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(f"FILELINKS#{file_id}"),
        ScanIndexForward=False,
    )
    return [_public(i) for i in items]  # type: ignore[misc]


def update_link(link_id: str, **fields: Any) -> dict:
    names = {f"#f{i}": k for i, k in enumerate(fields)}
    values = {f":v{i}": v for i, v in enumerate(fields.values())}
    expr = "SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
    resp = dynamodb_table().update_item(
        Key={"PK": f"LINK#{link_id}", "SK": "META"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return _public(resp["Attributes"])  # type: ignore[return-value]


def count_link_download(link_id: str) -> dict | None:
    """Atomically count one download. Returns None when the link is revoked or used up."""
    try:
        resp = dynamodb_table().update_item(
            Key={"PK": f"LINK#{link_id}", "SK": "META"},
            UpdateExpression="ADD download_count :one",
            ConditionExpression=(
                Attr("revoked").eq(False)
                & (
                    Attr("max_downloads").not_exists()
                    | Attr("download_count").lt(Attr("max_downloads"))
                )
            ),
            ExpressionAttributeValues={":one": 1},
            ReturnValues="ALL_NEW",
        )
    except ClientError as err:
        if _is_conditional_failure(err):
            return None
        raise
    return _public(resp["Attributes"])


def add_link_password_failure(link_id: str) -> int:
    resp = dynamodb_table().update_item(
        Key={"PK": f"LINK#{link_id}", "SK": "META"},
        UpdateExpression="ADD failed_passwords :one",
        ExpressionAttributeValues={":one": 1},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["failed_passwords"])


# ---------------------------------------------------------------- audit


def put_event(event: dict) -> None:
    ts = event["at"]
    actor = event.get("actor_id") or "anon"
    dynamodb_table().put_item(
        Item={
            "PK": f"AUDIT#{ts[:10]}",
            "SK": f"{ts}#{event['id']}",
            "GSI1PK": f"ACTOR#{actor}",
            "GSI1SK": ts,
            **{k: _to_ddb(v) for k, v in event.items() if v is not None},
        }
    )


def events_for_day(day: str, limit: int | None = None) -> list[dict]:
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("PK").eq(f"AUDIT#{day}"),
        "ScanIndexForward": False,
    }
    if limit:
        resp = dynamodb_table().query(Limit=limit, **kwargs)
        items = resp.get("Items", [])
    else:
        items = _query_all(**kwargs)
    return [_public(i) for i in items]  # type: ignore[misc]


def events_for_actor(actor_id: str, since: datetime, limit: int | None = None) -> list[dict]:
    kwargs: dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq(f"ACTOR#{actor_id}")
        & Key("GSI1SK").gte(iso(since)),
        "ScanIndexForward": False,
    }
    if limit:
        items = dynamodb_table().query(Limit=limit, **kwargs).get("Items", [])
    else:
        items = _query_all(**kwargs)
    return [_public(i) for i in items]  # type: ignore[misc]


# ---------------------------------------------------------------- alerts


def create_alert_once(dedupe_key: str, alert: dict, window_minutes: int = 60) -> dict | None:
    """Create an alert unless an identical one (same rule + subject) fired in this window."""
    now = clock.now()
    try:
        dynamodb_table().put_item(
            Item={
                "PK": f"ALERTKEY#{dedupe_key}",
                "SK": "LOCK",
                "until": iso(now + timedelta(minutes=window_minutes)),
                "ttl": _ttl(now + timedelta(minutes=window_minutes)),
            },
            ConditionExpression="attribute_not_exists(PK) OR #u < :now",
            ExpressionAttributeNames={"#u": "until"},
            ExpressionAttributeValues={":now": iso(now)},
        )
    except ClientError as err:
        if _is_conditional_failure(err):
            return None
        raise
    alert_id = new_id()
    item = {
        "PK": f"ALERT#{alert_id}",
        "SK": "META",
        "GSI1PK": "ALERTS",
        "GSI1SK": alert["at"],
        "id": alert_id,
        "status": "open",
        **{k: _to_ddb(v) for k, v in alert.items() if v is not None},
    }
    dynamodb_table().put_item(Item=item)
    return _public(item)


def list_alerts(limit: int = 100) -> list[dict]:
    resp = dynamodb_table().query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("ALERTS"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_public(i) for i in resp.get("Items", [])]  # type: ignore[misc]


def get_alert(alert_id: str) -> dict | None:
    resp = dynamodb_table().get_item(Key={"PK": f"ALERT#{alert_id}", "SK": "META"})
    return _public(resp.get("Item"))


def update_alert(alert_id: str, **fields: Any) -> dict:
    names = {f"#f{i}": k for i, k in enumerate(fields)}
    values = {f":v{i}": v for i, v in enumerate(fields.values())}
    expr = "SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
    resp = dynamodb_table().update_item(
        Key={"PK": f"ALERT#{alert_id}", "SK": "META"},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )
    return _public(resp["Attributes"])  # type: ignore[return-value]

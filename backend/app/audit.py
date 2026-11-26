"""Audit logging: every security-relevant action is recorded, then checked by the detector."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from . import detector, store
from .clock import clock, iso

log = logging.getLogger("secure-share.audit")


@dataclass
class RequestInfo:
    ip: str
    country: str | None
    user_agent: str


class StoreHistory:
    """detector.History backed by DynamoDB."""

    def login_failures_for_email(self, email: str, since: datetime) -> int:
        return store.login_failures_since(email, since)

    def failed_emails_from_ip(self, ip: str, since: datetime) -> set[str]:
        return store.failed_emails_from_ip_since(ip, since)

    def actor_events(self, actor_id: str, since: datetime) -> list[dict]:
        return store.events_for_actor(actor_id, since)

    def seen_countries(self, user_id: str) -> set[str]:
        return set(store.seen_countries(user_id))


_history = StoreHistory()


def record(
    info: RequestInfo,
    action: str,
    outcome: str = "success",
    actor: dict | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
) -> dict:
    event = {
        "id": store.new_id(),
        "at": iso(clock.now()),
        "action": action,
        "outcome": outcome,
        "actor_id": actor["id"] if actor else None,
        "actor_email": actor["email"] if actor else None,
        "ip": info.ip,
        "country": info.country,
        "user_agent": info.user_agent[:200],
        "target_type": target_type,
        "target_id": target_id,
        "details": details or None,
    }
    store.put_event(event)
    try:
        for finding in detector.evaluate(event, _history):
            store.create_alert_once(
                finding.dedupe_key,
                {
                    "at": event["at"],
                    "rule": finding.rule,
                    "severity": finding.severity,
                    "title": finding.title,
                    "reason": finding.reason,
                    "user_id": finding.user_id,
                    "subject": finding.subject,
                    "event_id": event["id"],
                    "evidence": finding.evidence,
                },
                window_minutes=finding.dedupe_minutes,
            )
    except Exception:  # detection must never break the user's request
        log.exception("detector failed for event %s", event["id"])
    if actor and outcome == "success" and action in detector.LOGIN_ACTIONS and info.country:
        store.mark_country_seen(actor["id"], info.country)
    return event

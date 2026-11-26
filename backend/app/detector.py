"""Suspicious-activity detection.

Every audit event is checked as it happens. Rules are plain functions over the event
plus a small history interface, so the same code runs against DynamoDB in the API and
against an in-memory event stream in the offline evaluation (scripts/evaluate_detector.py).
Each finding carries a plain-language reason an admin can act on.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from .clock import parse_iso

HIGH, MEDIUM, LOW = "high", "medium", "low"

LOGIN_ACTIONS = {"auth.login", "auth.google_login"}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    title: str
    reason: str
    user_id: str | None = None
    dedupe_minutes: int = 60
    evidence: dict = field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        return f"{self.rule}#{self.subject}"


class History(Protocol):
    """What the rules need to know about the past."""

    def login_failures_for_email(self, email: str, since: datetime) -> int: ...

    def failed_emails_from_ip(self, ip: str, since: datetime) -> set[str]: ...

    def actor_events(self, actor_id: str, since: datetime) -> list[dict]: ...

    def seen_countries(self, user_id: str) -> set[str]: ...


@dataclass
class Thresholds:
    brute_force_failures: int = 5
    brute_force_window_min: int = 10
    spray_accounts: int = 5
    spray_window_min: int = 10
    travel_window_hours: int = 2
    burst_min_downloads: int = 20
    burst_sigma: float = 4.0
    burst_baseline_days: int = 14
    off_hours_min_logins: int = 30
    off_hours_max_share: float = 0.02
    link_password_failures: int = 5
    mass_links: int = 10
    mass_deletes: int = 15


T = Thresholds()


def _at(event: dict) -> datetime:
    return parse_iso(event["at"])


def _count(events: Iterable[dict], action: str, outcome: str = "success") -> int:
    return sum(1 for e in events if e["action"] == action and e.get("outcome") == outcome)


# ---------------------------------------------------------------- rules


def brute_force(event: dict, h: History) -> list[Finding]:
    if event["action"] != "auth.login" or event.get("outcome") != "failure":
        return []
    email = (event.get("details") or {}).get("email") or event.get("actor_email")
    if not email:
        return []
    since = _at(event) - timedelta(minutes=T.brute_force_window_min)
    n = h.login_failures_for_email(email, since)
    if n < T.brute_force_failures:
        return []
    return [
        Finding(
            "brute_force",
            HIGH,
            email,
            "Repeated failed logins on one account",
            f"{n} wrong passwords for {email} in the last {T.brute_force_window_min} minutes "
            f"(threshold {T.brute_force_failures}). The account is temporarily locked.",
            user_id=event.get("actor_id"),
            evidence={"failures": n, "ip": event.get("ip")},
        )
    ]


def password_spray(event: dict, h: History) -> list[Finding]:
    if event["action"] != "auth.login" or event.get("outcome") != "failure" or not event.get("ip"):
        return []
    since = _at(event) - timedelta(minutes=T.spray_window_min)
    emails = h.failed_emails_from_ip(event["ip"], since)
    if len(emails) < T.spray_accounts:
        return []
    return [
        Finding(
            "password_spray",
            HIGH,
            event["ip"],
            "One address is trying many accounts",
            f"IP {event['ip']} failed to log in to {len(emails)} different accounts in "
            f"{T.spray_window_min} minutes, a typical password-spraying pattern.",
            evidence={"accounts": sorted(emails)[:10]},
        )
    ]


def _prior_logins(event: dict, h: History, since: datetime) -> list[dict]:
    return [
        e
        for e in h.actor_events(event["actor_id"], since)
        if e["action"] in LOGIN_ACTIONS and e.get("outcome") == "success" and e["id"] != event["id"]
    ]


def new_country(event: dict, h: History) -> list[Finding]:
    if event["action"] not in LOGIN_ACTIONS or event.get("outcome") != "success":
        return []
    country, uid = event.get("country"), event.get("actor_id")
    if not country or not uid:
        return []
    seen = h.seen_countries(uid)
    if not seen or country in seen:
        return []
    return [
        Finding(
            "new_country",
            MEDIUM,
            f"{uid}#{country}",
            "Login from a new country",
            f"{event.get('actor_email')} signed in from {country} for the first time. "
            f"Previously seen: {', '.join(sorted(seen))}.",
            user_id=uid,
            dedupe_minutes=24 * 60,
            evidence={"country": country, "known": sorted(seen)},
        )
    ]


def impossible_travel(event: dict, h: History) -> list[Finding]:
    if event["action"] not in LOGIN_ACTIONS or event.get("outcome") != "success":
        return []
    country, uid = event.get("country"), event.get("actor_id")
    if not country or not uid:
        return []
    window = timedelta(hours=T.travel_window_hours)
    for prev in _prior_logins(event, h, _at(event) - window):
        if prev.get("country") and prev["country"] != country:
            minutes = int((_at(event) - _at(prev)).total_seconds() // 60)
            return [
                Finding(
                    "impossible_travel",
                    HIGH,
                    uid,
                    "Logins from two countries too close together",
                    f"{event.get('actor_email')} signed in from {prev['country']} and then from "
                    f"{country} {minutes} minutes later. Nobody travels that fast; the "
                    f"account may be shared or stolen.",
                    user_id=uid,
                    evidence={"from": prev["country"], "to": country, "minutes": minutes},
                )
            ]
    return []


def download_burst(event: dict, h: History) -> list[Finding]:
    if event["action"] != "file.download" or event.get("outcome") != "success":
        return []
    uid = event.get("actor_id")
    if not uid:
        return []
    now = _at(event)
    hour_start = now - timedelta(hours=1)
    history = h.actor_events(uid, now - timedelta(days=T.burst_baseline_days))
    downloads = [
        e for e in history if e["action"] == "file.download" and e.get("outcome") == "success"
    ]
    last_hour = sum(1 for e in downloads if _at(e) > hour_start) + (
        0 if any(e["id"] == event["id"] for e in downloads) else 1
    )
    # Baseline: downloads per hour over the previous days, empty hours included.
    buckets: dict[int, int] = {}
    for e in downloads:
        if _at(e) <= hour_start:
            buckets[int((now - _at(e)).total_seconds() // 3600)] = (
                buckets.get(int((now - _at(e)).total_seconds() // 3600), 0) + 1
            )
    hours = T.burst_baseline_days * 24
    series = [buckets.get(i, 0) for i in range(1, hours)]
    mean, std = statistics.fmean(series), statistics.pstdev(series)
    threshold = max(T.burst_min_downloads, mean + T.burst_sigma * std)
    if last_hour < threshold:
        return []
    return [
        Finding(
            "download_burst",
            HIGH if last_hour >= 2 * threshold else MEDIUM,
            uid,
            "Unusually many downloads",
            f"{event.get('actor_email')} downloaded {last_hour} files in the last hour. Their "
            f"normal rate is {mean:.2f} per hour (alert level {threshold:.0f}). This can "
            f"mean data is being taken before someone leaves, or a stolen session.",
            user_id=uid,
            evidence={
                "last_hour": last_hour,
                "mean": round(mean, 3),
                "threshold": round(threshold, 1),
            },
        )
    ]


def off_hours(event: dict, h: History) -> list[Finding]:
    if event["action"] not in LOGIN_ACTIONS or event.get("outcome") != "success":
        return []
    uid = event.get("actor_id")
    if not uid:
        return []
    now = _at(event)
    logins = _prior_logins(event, h, now - timedelta(days=30))
    if len(logins) < T.off_hours_min_logins:
        return []
    hour = now.hour
    near = sum(1 for e in logins if min((_at(e).hour - hour) % 24, (hour - _at(e).hour) % 24) <= 1)
    share = near / len(logins)
    if share >= T.off_hours_max_share:
        return []
    return [
        Finding(
            "off_hours",
            LOW,
            uid,
            "Login at an unusual time",
            f"{event.get('actor_email')} signed in at {now:%H:%M} UTC. Only {share:.0%} of "
            f"their last {len(logins)} logins happened within an hour of this time.",
            user_id=uid,
            dedupe_minutes=12 * 60,
            evidence={"hour_utc": hour, "share": round(share, 3), "logins": len(logins)},
        )
    ]


def link_password_guessing(event: dict, h: History) -> list[Finding]:
    if event["action"] != "link.password_failure":
        return []
    failures = int((event.get("details") or {}).get("failures", 0))
    if failures < T.link_password_failures:
        return []
    return [
        Finding(
            "link_password_guessing",
            MEDIUM,
            event.get("target_id") or "?",
            "Someone is guessing a share-link password",
            f"{failures} wrong passwords were tried on a protected share link. The link "
            f"has been locked; the owner can create a new one.",
            user_id=(event.get("details") or {}).get("owner_id"),
            evidence={"failures": failures, "ip": event.get("ip")},
        )
    ]


def _volume_rule(
    action: str, limit: int, minutes: int, rule: str, title: str, text: str
) -> Callable[[dict, History], list[Finding]]:
    def check(event: dict, h: History) -> list[Finding]:
        if (
            event["action"] != action
            or event.get("outcome") != "success"
            or not event.get("actor_id")
        ):
            return []
        since = _at(event) - timedelta(minutes=minutes)
        recent = h.actor_events(event["actor_id"], since)
        n = _count(recent, action) + (0 if any(e["id"] == event["id"] for e in recent) else 1)
        if n < limit:
            return []
        return [
            Finding(
                rule,
                MEDIUM,
                event["actor_id"],
                title,
                text.format(who=event.get("actor_email"), n=n, minutes=minutes),
                user_id=event["actor_id"],
                evidence={"count": n},
            )
        ]

    check.__name__ = rule
    return check


mass_link_creation = _volume_rule(
    "link.create",
    T.mass_links,
    60,
    "mass_link_creation",
    "Many public links created quickly",
    "{who} created {n} external share links in {minutes} minutes.",
)

mass_deletion = _volume_rule(
    "file.delete",
    T.mass_deletes,
    30,
    "mass_deletion",
    "Many files deleted quickly",
    "{who} deleted {n} files in {minutes} minutes. Check this was intended.",
)

RULES = [
    brute_force,
    password_spray,
    new_country,
    impossible_travel,
    download_burst,
    off_hours,
    link_password_guessing,
    mass_link_creation,
    mass_deletion,
]


def evaluate(event: dict, history: History) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(event, history))
    return findings

"""In-memory detector.History, used by unit tests and the offline detector evaluation."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .clock import parse_iso
from .detector import LOGIN_ACTIONS


class MemoryHistory:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self._by_actor: dict[str, list[dict]] = defaultdict(list)
        self._failures: list[tuple[datetime, str, str]] = []  # (at, email, ip)
        self._countries: dict[str, set[str]] = defaultdict(set)

    def add(self, event: dict) -> None:
        """Record an event the way the API does (before the detector runs)."""
        self.events.append(event)
        if event.get("actor_id"):
            self._by_actor[event["actor_id"]].append(event)
        if event["action"] in ("auth.login", "auth.mfa") and event.get("outcome") == "failure":
            email = (event.get("details") or {}).get("email") or event.get("actor_email")
            if email:
                self._failures.append((parse_iso(event["at"]), email, event.get("ip") or ""))

    def after_detection(self, event: dict) -> None:
        """Bookkeeping the API does after the detector ran."""
        if (
            event["action"] in LOGIN_ACTIONS
            and event.get("outcome") == "success"
            and event.get("actor_id")
            and event.get("country")
        ):
            self._countries[event["actor_id"]].add(event["country"])

    # detector.History
    def login_failures_for_email(self, email: str, since: datetime) -> int:
        return sum(1 for at, e, _ in self._failures if e == email and at >= since)

    def failed_emails_from_ip(self, ip: str, since: datetime) -> set[str]:
        return {e for at, e, i in self._failures if i == ip and at >= since}

    def actor_events(self, actor_id: str, since: datetime) -> list[dict]:
        out = []
        for e in reversed(self._by_actor.get(actor_id, [])):
            if parse_iso(e["at"]) < since:
                break
            out.append(e)
        return out

    def seen_countries(self, user_id: str) -> set[str]:
        return set(self._countries.get(user_id, set()))

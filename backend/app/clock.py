"""A tiny injectable clock, so tests and simulations can control time."""

from datetime import UTC, datetime
from functools import lru_cache


class Clock:
    def __init__(self) -> None:
        self._frozen: datetime | None = None

    def now(self) -> datetime:
        return self._frozen or datetime.now(UTC)

    def freeze(self, at: datetime) -> None:
        self._frozen = at

    def unfreeze(self) -> None:
        self._frozen = None


clock = Clock()


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@lru_cache(maxsize=65536)
def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)

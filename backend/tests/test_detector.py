"""Rule-level tests on an in-memory event stream (no AWS involved)."""

from datetime import UTC, datetime, timedelta
from itertools import count

from app import detector
from app.clock import iso
from app.memory_history import MemoryHistory

_ids = count()
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


def ev(at, action, outcome="success", uid="u1", **extra):
    return {
        "id": f"e{next(_ids)}",
        "at": iso(at),
        "action": action,
        "outcome": outcome,
        "actor_id": uid,
        "actor_email": f"{uid}@example.com" if uid else None,
        "ip": extra.pop("ip", "10.0.0.1"),
        "country": extra.pop("country", "TD"),
        **extra,
    }


def run(h, event):
    h.add(event)
    found = detector.evaluate(event, h)
    h.after_detection(event)
    return {f.rule for f in found}


def test_new_country_only_after_history():
    h = MemoryHistory()
    assert "new_country" not in run(h, ev(T0, "auth.login", country="TD"))
    assert "new_country" not in run(h, ev(T0 + timedelta(days=1), "auth.login", country="TD"))
    assert "new_country" in run(h, ev(T0 + timedelta(days=2), "auth.login", country="FR"))


def test_impossible_travel():
    h = MemoryHistory()
    run(h, ev(T0, "auth.login", country="TD"))
    assert "impossible_travel" in run(h, ev(T0 + timedelta(minutes=40), "auth.login", country="BR"))


def test_travel_after_long_gap_is_fine():
    h = MemoryHistory()
    run(h, ev(T0, "auth.login", country="TD"))
    rules = run(h, ev(T0 + timedelta(hours=10), "auth.login", country="FR"))
    assert "impossible_travel" not in rules


def test_download_burst_respects_personal_baseline():
    h = MemoryHistory()
    # A heavy user: ~30 downloads every working hour for two weeks.
    t = T0 - timedelta(days=14)
    while t < T0:
        if 8 <= t.hour < 17:
            for i in range(30):
                h.add(ev(t + timedelta(minutes=i), "file.download"))
        t += timedelta(hours=1)
    rules = set()
    for i in range(30):
        rules |= run(h, ev(T0 + timedelta(minutes=i), "file.download"))
    assert "download_burst" not in rules


def test_download_burst_fires_for_quiet_user():
    h = MemoryHistory()
    for d in range(14):
        h.add(ev(T0 - timedelta(days=d + 1), "file.download"))
    rules = set()
    for i in range(25):
        rules |= run(h, ev(T0 + timedelta(minutes=i), "file.download"))
    assert "download_burst" in rules


def test_off_hours():
    h = MemoryHistory()
    for d in range(35):
        run(h, ev(T0 - timedelta(days=35 - d), "auth.login"))
    assert "off_hours" in run(h, ev(T0.replace(hour=3), "auth.login"))
    assert "off_hours" not in run(h, ev(T0.replace(hour=9, minute=30), "auth.login"))


def test_off_hours_needs_enough_history():
    h = MemoryHistory()
    for d in range(5):
        run(h, ev(T0 - timedelta(days=5 - d), "auth.login"))
    assert "off_hours" not in run(h, ev(T0.replace(hour=3), "auth.login"))


def test_failed_login_rules():
    h = MemoryHistory()
    rules = set()
    for i in range(5):
        rules |= run(
            h,
            ev(
                T0 + timedelta(minutes=i),
                "auth.login",
                "failure",
                uid=None,
                details={"email": "a@example.com"},
            ),
        )
    assert "brute_force" in rules and "password_spray" not in rules


def test_failures_spread_out_do_not_fire():
    h = MemoryHistory()
    rules = set()
    for i in range(5):
        rules |= run(
            h,
            ev(
                T0 + timedelta(minutes=15 * i),
                "auth.login",
                "failure",
                uid=None,
                details={"email": "a@example.com"},
            ),
        )
    assert "brute_force" not in rules


def test_findings_explain_themselves():
    h = MemoryHistory()
    run(h, ev(T0, "auth.login", country="TD"))
    found = detector.evaluate(ev(T0 + timedelta(minutes=5), "auth.login", country="JP"), h)
    travel = next(f for f in found if f.rule == "impossible_travel")
    assert "TD" in travel.reason and "JP" in travel.reason and "5 minutes" in travel.reason
    assert travel.severity == detector.HIGH

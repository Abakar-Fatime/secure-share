"""Offline evaluation of the suspicious-activity detector.

Simulates 30 days of normal activity for an organisation, injects labelled attacks
(plus a few deliberately evasive ones), replays everything through the exact same rules
the API uses, and measures detection rate, false alarms and detection delay.

    python -m scripts.evaluate_detector --seeds 5 --out ../docs/detector-evaluation.md
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

from app import detector
from app.clock import iso, parse_iso
from app.memory_history import MemoryHistory

START = datetime(2026, 10, 1, tzinfo=UTC)
DAYS = 30
ATTACK_FROM_DAY = 20

ATTACKS = {
    # name: (expected rule, number of instances)
    "brute_force": ("brute_force", 10),
    "password_spray": ("password_spray", 6),
    "stolen_credentials_abroad": ("impossible_travel", 8),
    "data_exfiltration": ("download_burst", 8),
    "night_login_compromise": ("off_hours", 6),
    "link_password_guessing": ("link_password_guessing", 6),
    "mass_link_creation": ("mass_link_creation", 5),
    "mass_deletion": ("mass_deletion", 5),
}
EVASIVE = {
    # attacks built to stay under the thresholds; reported as known blind spots
    "slow_brute_force": ("brute_force", 4),
    "slow_exfiltration": ("download_burst", 4),
}

_ids = count()


@dataclass
class User:
    id: str
    email: str
    country: str
    start_hour: int  # usual first login hour (UTC)
    downloads_per_day: float
    traveller: bool


def make_event(
    at, action, user=None, outcome="success", ip=None, country=None, label=None, **details
):
    return {
        "id": f"e{next(_ids)}",
        "at": iso(at),
        "action": action,
        "outcome": outcome,
        "actor_id": user.id if user else None,
        "actor_email": user.email if user else None,
        "ip": ip or (f"41.202.{zlib.crc32(user.id.encode()) % 250}.10" if user else "?"),
        "country": country or (user.country if user else None),
        "target_id": details.pop("target_id", None),
        "details": details or None,
        "_label": label,
    }


def simulate_normal(rng: random.Random, users: list[User]) -> list[dict]:
    events = []
    for u in users:
        trip_day = rng.randrange(3, DAYS - 5) if u.traveller else None
        for day in range(DAYS):
            date = START + timedelta(days=day)
            if date.weekday() >= 5 and rng.random() < 0.85:
                continue
            country = "FR" if trip_day is not None and trip_day <= day < trip_day + 4 else u.country
            ip = None if country == u.country else f"90.1.{day}.{rng.randrange(250)}"
            for _ in range(rng.choice([1, 1, 1, 2, 2, 3])):
                t = date + timedelta(
                    hours=u.start_hour + rng.gauss(0, 0.7) + rng.random() * 3,
                    minutes=rng.randrange(60),
                )
                if rng.random() < 0.04:  # typo
                    events.append(
                        make_event(
                            t - timedelta(seconds=30),
                            "auth.login",
                            None,
                            "failure",
                            ip=ip,
                            country=country,
                            email=u.email,
                        )
                    )
                events.append(make_event(t, "auth.login", u, ip=ip, country=country))
            for _ in range(_poisson(rng, u.downloads_per_day)):
                t = date + timedelta(hours=u.start_hour + rng.random() * 8.5)
                events.append(make_event(t, "file.download", u, ip=ip, country=country))
            for _ in range(_poisson(rng, 1.2)):
                t = date + timedelta(hours=u.start_hour + rng.random() * 8)
                events.append(make_event(t, "file.upload", u, ip=ip, country=country))
            for _ in range(_poisson(rng, 0.6)):
                t = date + timedelta(hours=u.start_hour + rng.random() * 8)
                events.append(make_event(t, "link.create", u, ip=ip, country=country))
            for _ in range(_poisson(rng, 0.4)):
                t = date + timedelta(hours=u.start_hour + rng.random() * 8)
                events.append(make_event(t, "file.delete", u, ip=ip, country=country))
            # outside visitors sometimes mistype a link password
            if rng.random() < 0.05:
                t = date + timedelta(hours=rng.randrange(24))
                link = f"link-{u.id}-{day}"
                for k in range(1, rng.choice([1, 1, 2]) + 1):
                    events.append(
                        make_event(
                            t + timedelta(seconds=20 * k),
                            "link.password_failure",
                            None,
                            "failure",
                            ip="102.1.1.1",
                            country="TD",
                            target_id=link,
                            failures=k,
                            owner_id=u.id,
                        )
                    )
    return events


def _poisson(rng: random.Random, lam: float) -> int:
    # Knuth's algorithm; fine for small lambda
    limit, k, p = pow(2.718281828459045, -lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def inject(rng, users, kind, n, label_prefix):
    events = []
    for i in range(n):
        label = f"{label_prefix}:{kind}:{i}"
        u = rng.choice(users)
        day = START + timedelta(days=rng.randrange(ATTACK_FROM_DAY, DAYS))
        t = day + timedelta(hours=u.start_hour + 2, minutes=rng.randrange(120))
        attacker_ip = f"185.{rng.randrange(255)}.{rng.randrange(255)}.{rng.randrange(255)}"
        if kind == "brute_force":
            for k in range(rng.randrange(6, 16)):
                events.append(
                    make_event(
                        t + timedelta(seconds=20 * k),
                        "auth.login",
                        None,
                        "failure",
                        ip=attacker_ip,
                        country="RU",
                        label=label,
                        email=u.email,
                    )
                )
        elif kind == "slow_brute_force":
            for k in range(12):
                events.append(
                    make_event(
                        t + timedelta(minutes=5 * k),
                        "auth.login",
                        None,
                        "failure",
                        ip=attacker_ip,
                        country="RU",
                        label=label,
                        email=u.email,
                    )
                )
        elif kind == "password_spray":
            targets = rng.sample(users, rng.randrange(8, 20))
            for k, v in enumerate(targets):
                events.append(
                    make_event(
                        t + timedelta(seconds=15 * k),
                        "auth.login",
                        None,
                        "failure",
                        ip=attacker_ip,
                        country="NG",
                        label=label,
                        email=v.email,
                    )
                )
        elif kind == "stolen_credentials_abroad":
            # a normal login, then the attacker uses the same account from elsewhere
            events.append(make_event(t, "auth.login", u))
            events.append(
                make_event(
                    t + timedelta(minutes=rng.randrange(20, 90)),
                    "auth.login",
                    u,
                    ip=attacker_ip,
                    country=rng.choice(["BR", "VN", "US"]),
                    label=label,
                )
            )
        elif kind == "data_exfiltration":
            for k in range(rng.randrange(40, 121)):
                events.append(
                    make_event(t + timedelta(seconds=25 * k), "file.download", u, label=label)
                )
        elif kind == "slow_exfiltration":
            # spread over a whole working day, at about twice the user's normal hourly rate
            per_hour = max(2, round(u.downloads_per_day / 8 * 2))
            for h in range(8):
                for k in range(per_hour):
                    events.append(
                        make_event(
                            t + timedelta(hours=h, minutes=k * 50 // per_hour),
                            "file.download",
                            u,
                            label=label,
                        )
                    )
        elif kind == "night_login_compromise":
            night = day + timedelta(hours=(u.start_hour + 12) % 24, minutes=rng.randrange(60))
            events.append(make_event(night, "auth.login", u, label=label))
        elif kind == "link_password_guessing":
            link = f"target-link-{i}"
            for k in range(1, rng.randrange(6, 13)):
                events.append(
                    make_event(
                        t + timedelta(seconds=5 * k),
                        "link.password_failure",
                        None,
                        "failure",
                        ip=attacker_ip,
                        country="CN",
                        label=label,
                        target_id=link,
                        failures=k,
                        owner_id=u.id,
                    )
                )
        elif kind == "mass_link_creation":
            for k in range(rng.randrange(12, 26)):
                events.append(make_event(t + timedelta(minutes=k), "link.create", u, label=label))
        elif kind == "mass_deletion":
            for k in range(rng.randrange(20, 41)):
                events.append(
                    make_event(t + timedelta(seconds=30 * k), "file.delete", u, label=label)
                )
    return events


def run_once(seed: int, n_users: int = 40) -> dict:
    rng = random.Random(seed)
    users = [
        User(
            id=f"u{i}",
            email=f"user{i}@example.td",
            country=rng.choices(["TD", "CM", "FR"], [0.8, 0.1, 0.1])[0],
            start_hour=rng.choice([6, 7, 7, 8, 8, 9]),
            downloads_per_day=rng.choice([1, 2, 4, 8, 15, 30, 60]),
            traveller=rng.random() < 0.15,
        )
        for i in range(n_users)
    ]
    events = simulate_normal(rng, users)
    for kind, (_, n) in ATTACKS.items():
        events += inject(rng, users, kind, n, "attack")
    for kind, (_, n) in EVASIVE.items():
        events += inject(rng, users, kind, n, "evasive")
    events.sort(key=lambda e: e["at"])

    h = MemoryHistory()
    locks: dict[str, datetime] = {}
    alerts = []
    for e in events:
        h.add(e)
        for f in detector.evaluate(e, h):
            now = parse_iso(e["at"])
            if f.dedupe_key in locks and locks[f.dedupe_key] > now:
                continue  # same de-duplication the API applies
            locks[f.dedupe_key] = now + timedelta(minutes=f.dedupe_minutes)
            alerts.append(
                {"rule": f.rule, "severity": f.severity, "label": e["_label"], "at": e["at"]}
            )
        h.after_detection(e)

    by_label = defaultdict(list)
    for e in events:
        if e["_label"]:
            by_label[e["_label"]].append(e)
    fired = defaultdict(set)
    for a in alerts:
        if a["label"]:
            fired[a["label"]].add(a["rule"])

    result = {
        "events": len(events),
        "alerts": len(alerts),
        "attacks": {},
        "false_alarms": Counter(),
    }
    for group, table in (("attack", ATTACKS), ("evasive", EVASIVE)):
        for kind, (rule, n) in table.items():
            detected = 0
            delays = []
            for i in range(n):
                label = f"{group}:{kind}:{i}"
                if rule in fired[label]:
                    detected += 1
                    # how many attacker actions happened before the first alert
                    first = min(
                        a["at"] for a in alerts if a["label"] == label and a["rule"] == rule
                    )
                    delays.append(sum(1 for x in by_label[label] if x["at"] <= first))
            result["attacks"][kind] = {
                "group": group,
                "rule": rule,
                "n": n,
                "detected": detected,
                "delays": delays,
            }
    for a in alerts:
        if a["label"] is None:
            result["false_alarms"][a["rule"]] += 1
    result["true_alerts"] = sum(1 for a in alerts if a["label"] and a["label"].startswith("attack"))
    result["user_days"] = n_users * DAYS
    return result


def render(results: list[dict], seeds: list[int]) -> str:
    lines = []
    n_events = statistics.fmean(r["events"] for r in results)
    lines += [
        "# Detector evaluation",
        "",
        "Generated by `backend/scripts/evaluate_detector.py`. The script simulates an "
        f"organisation of 40 people over {DAYS} days, injects labelled attacks in the last "
        f"{DAYS - ATTACK_FROM_DAY} days, and replays every event through the same rules the API "
        "runs (`backend/app/detector.py`), including alert de-duplication.",
        "",
        f"Runs: {len(seeds)} random seeds ({', '.join(map(str, seeds))}); "
        f"about {n_events:,.0f} events per run.",
        "",
        "## Detection of attacks",
        "",
        "| Attack | Rule | Detected | Median actions before alert |",
        "|---|---|---|---|",
    ]
    totals = Counter()
    for kind in list(ATTACKS) + list(EVASIVE):
        det = sum(r["attacks"][kind]["detected"] for r in results)
        n = sum(r["attacks"][kind]["n"] for r in results)
        delays = [d for r in results for d in r["attacks"][kind]["delays"]]
        group = results[0]["attacks"][kind]["group"]
        if group == "attack":
            totals["det"] += det
            totals["n"] += n
        name = kind.replace("_", " ") + (" *(evasive)*" if group == "evasive" else "")
        med = f"{statistics.median(delays):g}" if delays else "n/a"
        lines.append(
            f"| {name} | `{results[0]['attacks'][kind]['rule']}` | {det}/{n} "
            f"({det / n:.0%}) | {med} |"
        )
    true_alerts = sum(r["true_alerts"] for r in results)
    fa = Counter()
    for r in results:
        fa.update(r["false_alarms"])
    false_total = sum(fa.values())
    user_days = sum(r["user_days"] for r in results)
    lines += [
        "",
        "## Summary",
        "",
        f"- **Detection rate (standard attacks): {totals['det']}/{totals['n']} "
        f"({totals['det'] / totals['n']:.1%})**",
        f"- **Alert precision: {true_alerts / (true_alerts + false_total):.1%}** "
        f"({true_alerts} alerts on attacks, {false_total} on normal activity)",
        f"- **False alarms: {false_total / user_days * 1000:.1f} per 1,000 user-days** "
        f"(about {false_total / len(results) / DAYS:.2f} per day for a 40-person team)",
        "",
        "## Where the false alarms come from",
        "",
        "| Rule | False alarms (all runs) | Typical cause in the simulation |",
        "|---|---|---|",
    ]
    causes = {
        "new_country": "a colleague genuinely travelling",
        "off_hours": "an unusually early or late but legitimate login",
        "download_burst": "a heavy day for a normally quiet user",
        "brute_force": "several typos in a row",
        "mass_deletion": "end-of-project clean-up",
        "mass_link_creation": "sharing many files at once",
        "impossible_travel": "first login abroad shortly after one at home",
        "link_password_guessing": "visitors mistyping a link password",
        "password_spray": "shared office IP with several typos",
    }
    for rule, n in fa.most_common():
        lines.append(f"| `{rule}` | {n} | {causes.get(rule, '')} |")
    if not fa:
        lines.append("| none | 0 | |")
    lines += [
        "",
        "## Known blind spots",
        "",
        "The *evasive* rows are attacks designed to stay under the thresholds: a password "
        "guesser that waits 5 minutes between tries, and a data thief who downloads at twice "
        "their normal pace spread over a full day. Fixed per-window thresholds miss these by "
        "design. Catching them would need longer-window baselines (for example daily totals "
        "per user) or per-IP reputation, at the cost of more false alarms.",
        "",
        "`off_hours` is deliberately cautious: it stays silent until a person has at least 30 "
        "logins in the previous 30 days, and once someone has signed in at a given hour, later "
        "logins at that hour no longer look unusual. The missed night logins in the simulation "
        "are these two cases (new-ish accounts, or a second night attack on the same person).",
        "",
        "`new_country` alerts on genuine travel are expected: they are medium severity and meant "
        "to be confirmed with the person, not to block them.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--out", type=Path, default=Path("../docs/detector-evaluation.md"))
    args = p.parse_args()
    seeds = list(range(1, args.seeds + 1))
    results = [run_once(s) for s in seeds]
    text = render(results, seeds)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text)
    args.out.with_suffix(".json").write_text(
        json.dumps([{**r, "false_alarms": dict(r["false_alarms"])} for r in results], indent=1)
    )
    print(text)


if __name__ == "__main__":
    main()

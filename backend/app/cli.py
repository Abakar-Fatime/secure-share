"""Admin command line.

python -m app.cli init-local                 create table + bucket on a local AWS emulator
python -m app.cli create-admin EMAIL NAME    first admin account (prints a one-time invite link)
python -m app.cli seed-demo                  demo users, files and 14 days of activity
"""

from __future__ import annotations

import argparse
import random
from datetime import timedelta

from . import store
from .audit import RequestInfo, record
from .aws import create_local_resources, s3_client
from .clock import clock
from .config import get_settings
from .security import hash_password, new_token, token_hash

DEMO_PASSWORD = "Demo-Password-2026"  # noqa: S105 - documented demo credential, local only
DEMO_TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # noqa: S105 - local demo only


def create_admin(email: str, name: str) -> str:
    """Create an invited admin and return their one-time invite link."""
    user = store.create_user(email, name, "admin", status="invited")
    token = new_token()
    store.create_invite(user["id"], token_hash(token))
    return f"{get_settings().app_url}/invite/{token}"


def _info(rng: random.Random, country: str = "TD", ip: str | None = None) -> RequestInfo:
    return RequestInfo(
        ip=ip or f"41.202.{rng.randrange(1, 250)}.{rng.randrange(1, 250)}",
        country=country,
        user_agent="Mozilla/5.0 (demo)",
    )


def seed_demo(days: int = 14) -> None:
    if get_settings().environment == "production":
        raise SystemExit("Refusing to seed demo data in production")
    rng = random.Random(7)  # noqa: S311 - demo data, not security
    s = get_settings()
    people = [
        ("admin@demo.td", "Amina Mahamat", "admin"),
        ("idriss@demo.td", "Idriss Abakar", "member"),
        ("halime@demo.td", "Halimé Oumar", "member"),
        ("moussa@demo.td", "Moussa Djibrine", "member"),
        ("zara@demo.td", "Zara Ngarlem", "viewer"),
        ("koumba@demo.td", "Koumba Nadjé", "viewer"),
    ]
    users = {}
    for email, name, role in people:
        u = store.get_user_by_email(email) or store.create_user(
            email, name, role, password_hash=hash_password(DEMO_PASSWORD)
        )
        users[email] = u
    store.update_user(users["admin@demo.td"]["id"], mfa_enabled=True, totp_secret=DEMO_TOTP_SECRET)

    end = clock.now()
    start = end - timedelta(days=days)
    names = [
        "Budget_2027.xlsx",
        "Contrat_fournisseur.pdf",
        "Rapport_mensuel_oct.pdf",
        "Plan_maintenance.docx",
        "Photos_site.zip",
        "Inventaire_pieces.csv",
        "Procedure_securite.pdf",
        "Presentation_client.pptx",
    ]
    files = []
    try:
        for d in range(days):
            day = start + timedelta(days=d)
            if day.weekday() >= 5:
                continue
            for u in users.values():
                clock.freeze(day.replace(hour=7) + timedelta(minutes=rng.randrange(150)))
                record(_info(rng), "auth.login", actor=u, details={"method": "password"})
                if u["role"] != "viewer" and rng.random() < 0.5:
                    clock.freeze(clock.now() + timedelta(minutes=rng.randrange(30, 240)))
                    name = rng.choice(names)
                    f = store.create_file(
                        u["id"], name, rng.randrange(20_000, 4_000_000), "application/octet-stream"
                    )
                    s3_client().put_object(
                        Bucket=s.bucket_name,
                        Key=f["s3_key"],
                        Body=f"Demo content for {name}\n".encode(),
                    )
                    store.update_file(f["id"], status="ready")
                    record(
                        _info(rng),
                        "file.upload",
                        actor=u,
                        target_type="file",
                        target_id=f["id"],
                        details={"name": name},
                    )
                    files.append(f)
                for _ in range(rng.randrange(0, 6)):
                    if not files:
                        break
                    clock.freeze(clock.now() + timedelta(minutes=rng.randrange(5, 60)))
                    f = rng.choice(files)
                    record(
                        _info(rng),
                        "file.download",
                        actor=u,
                        target_type="file",
                        target_id=f["id"],
                        details={"name": f["name"]},
                    )
        # A few suspicious moments so the security dashboard has something to show.
        idriss, halime = users["idriss@demo.td"], users["halime@demo.td"]
        attack = end - timedelta(days=2, hours=3)
        for k in range(7):
            clock.freeze(attack + timedelta(seconds=25 * k))
            store.record_login_failure(halime["email"], "185.220.101.4")
            record(
                _info(rng, "RU", "185.220.101.4"),
                "auth.login",
                "failure",
                details={"email": halime["email"], "reason": "password"},
            )
        clock.freeze(end - timedelta(days=1, hours=5))
        record(_info(rng), "auth.login", actor=idriss)
        clock.freeze(end - timedelta(days=1, hours=4, minutes=25))
        record(_info(rng, "BR", "177.38.12.9"), "auth.login", actor=idriss)
        burst = end - timedelta(hours=6)
        for k in range(35):
            clock.freeze(burst + timedelta(seconds=40 * k))
            f = rng.choice(files)
            record(
                _info(rng, "BR", "177.38.12.9"),
                "file.download",
                actor=idriss,
                target_type="file",
                target_id=f["id"],
                details={"name": f["name"]},
            )
    finally:
        clock.unfreeze()
    print(f"Seeded {len(users)} users, {len(files)} files, {days} days of activity.")
    print(f"Sign in as admin@demo.td / {DEMO_PASSWORD}")
    print(f"Admin authenticator secret (add to any TOTP app): {DEMO_TOTP_SECRET}")


def main() -> None:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-local")
    a = sub.add_parser("create-admin")
    a.add_argument("email")
    a.add_argument("name")
    sub.add_parser("seed-demo")
    args = p.parse_args()
    if args.cmd == "init-local":
        create_local_resources()
        print("Local table and bucket are ready.")
    elif args.cmd == "create-admin":
        url = create_admin(args.email, args.name)
        print(f"Admin created. Open this link within 72 hours to set a password:\n{url}")
    elif args.cmd == "seed-demo":
        seed_demo()


if __name__ == "__main__":
    main()

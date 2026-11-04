"""Administrative command line.

    python -m dfa.cli create-user <username> --role admin     (password from DFA_NEW_PASSWORD or prompt)
    python -m dfa.cli list-users
    python -m dfa.cli disable-user <username>
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from .auth import ROLES, create_user
from .config import get_settings
from .db import init_engine, session_scope
from .models import ApiToken, User


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dfa.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("--role", choices=ROLES, default="analyst")
    sub.add_parser("list-users")
    d = sub.add_parser("disable-user")
    d.add_argument("username")
    args = ap.parse_args(argv)
    init_engine(get_settings().db_url)
    if args.cmd == "create-user":
        password = os.environ.get("DFA_NEW_PASSWORD") or getpass.getpass("Password: ")
        try:
            with session_scope() as db:
                u = create_user(db, args.username, password, args.role)
                print(f"created {u.username} ({u.role})")
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    elif args.cmd == "list-users":
        with session_scope() as db:
            for u in db.execute(select(User).order_by(User.username)).scalars():
                print(f"{u.id:4d} {u.username:24s} {u.role:8s} {'disabled' if u.disabled else ''}")
    elif args.cmd == "disable-user":
        with session_scope() as db:
            u = db.execute(select(User).where(User.username == args.username)).scalar_one_or_none()
            if not u:
                print("no such user", file=sys.stderr)
                return 1
            u.disabled = True
            for t in db.execute(select(ApiToken).where(ApiToken.user_id == u.id)).scalars():
                t.revoked = True
            print(f"disabled {u.username}; tokens revoked")
    return 0


if __name__ == "__main__":
    sys.exit(main())

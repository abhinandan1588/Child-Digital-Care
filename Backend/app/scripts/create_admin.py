"""Create an admin account.

    python -m app.scripts.create_admin --email ops@example.com --role super_admin

The password is read interactively (or from ``ADMIN_BOOTSTRAP_PASSWORD``) so it
never appears in shell history or a process listing. A generated password is
printed once if none is supplied.

MFA is marked as *required* on every account created here. Enforcement itself
happens at the identity-provider or reverse-proxy layer in production; see
docs/DEPLOYMENT.md.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import secrets
import sys

from app.core.logging import configure_logging
from app.core.permissions import AdminRoleName
from app.core.security import MIN_PASSWORD_LENGTH
from app.db.session import dispose_engine, session_scope
from app.services import admin_service

MIN_ADMIN_PASSWORD_LENGTH = 16


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a Child Digital Care admin user.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", default=None, help="Display name (defaults to the email).")
    parser.add_argument(
        "--role",
        action="append",
        dest="roles",
        choices=[role.value for role in AdminRoleName],
        help="Repeatable. Defaults to support_admin.",
    )
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help="Generate a strong password and print it once.",
    )
    return parser.parse_args(argv)


def resolve_password(generate: bool) -> str:
    if generate:
        password = secrets.token_urlsafe(24)
        print("Generated password (store it in your password manager now):")
        print(f"  {password}")
        return password

    from_env = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")
    if from_env:
        return from_env

    if not sys.stdin.isatty():
        raise SystemExit(
            "No TTY available. Set ADMIN_BOOTSTRAP_PASSWORD or pass --generate-password."
        )

    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    return password


async def run(args: argparse.Namespace) -> int:
    password = resolve_password(args.generate_password)
    if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
        raise SystemExit(
            f"Admin passwords must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters "
            f"(ordinary accounts require {MIN_PASSWORD_LENGTH})."
        )

    roles = args.roles or [AdminRoleName.support_admin.value]

    try:
        async with session_scope() as session:
            # Ensure the catalogue exists, so a first-run bootstrap works.
            await admin_service.seed_rbac(session)
            admin = await admin_service.create_admin_user(
                session,
                email=args.email,
                display_name=args.name or args.email,
                password=password,
                role_names=roles,
            )
            print(f"Created admin {admin.email} (id={admin.id}) with roles: {', '.join(roles)}")
            print(
                "MFA is marked as required. Enforce it at your identity provider or "
                "reverse proxy before exposing the admin API publicly."
            )
    finally:
        await dispose_engine()
    return 0


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    return asyncio.run(run(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())

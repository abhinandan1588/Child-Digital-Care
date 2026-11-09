"""Seed the admin permission and role rows.

Safe to run repeatedly and safe to run in production: it only inserts the
default permission/role catalogue, never user accounts or test data.

    python -m app.scripts.seed_admin_rbac
"""

from __future__ import annotations

import asyncio

from app.core.logging import configure_logging
from app.db.session import dispose_engine, session_scope
from app.services import admin_service


async def main() -> None:
    configure_logging()
    try:
        async with session_scope() as session:
            permissions, roles, links = await admin_service.seed_rbac(session)
        print(
            f"Admin RBAC seeded: {permissions} permission(s), {roles} role(s), "
            f"{links} role-permission link(s) created."
        )
    finally:
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())

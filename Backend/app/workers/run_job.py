"""Run a background job once, without Celery.

Useful for operators and for CI:

    python -m app.workers.run_job process_outbox
    python -m app.workers.run_job apply_retention
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
from collections.abc import Awaitable, Callable

from app.core.logging import configure_logging
from app.db.session import dispose_engine
from app.workers import jobs

JOBS: dict[str, Callable[[], Awaitable[object]]] = {
    "process_outbox": jobs.process_outbox,
    "expire_commands": jobs.expire_commands,
    "expire_pairing_invitations": jobs.expire_pairing_invitations,
    "mark_stale_devices": jobs.mark_stale_devices,
    "cleanup_sessions": jobs.cleanup_sessions,
    "apply_retention": jobs.apply_retention,
    "resend_pending_wakeups": jobs.resend_pending_wakeups,
    "execute_due_deletions": jobs.execute_due_deletions,
    "deactivate_revoked_device_tokens": jobs.deactivate_revoked_device_tokens,
}


async def _run(name: str) -> object:
    try:
        return await JOBS[name]()
    finally:
        await dispose_engine()


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = argv if argv is not None else sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print("Usage: python -m app.workers.run_job <job>")
        print("Available jobs:")
        for name in sorted(JOBS):
            print(f"  {name}")
        return 0 if args else 1

    name = args[0]
    if name not in JOBS:
        print(f"Unknown job: {name}")
        print(f"Available: {', '.join(sorted(JOBS))}")
        return 1

    result = asyncio.run(_run(name))
    if dataclasses.is_dataclass(result) and not isinstance(result, type):
        payload = dataclasses.asdict(result)
    else:
        payload = {"result": result}
    print(json.dumps({"job": name, **payload}, default=str, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

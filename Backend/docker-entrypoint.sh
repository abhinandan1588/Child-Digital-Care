#!/bin/sh
# ---------------------------------------------------------------------------
# Container entrypoint.
#
# Brings the schema up to date before handing control to the process in CMD,
# so the image is correct whether it is started by a Render Blueprint, by a
# service configured through a dashboard, or by docker compose. Without this,
# a deployment that forgets to run migrations starts cleanly and then fails
# every request with "relation does not exist", which is a much worse signal
# than refusing to start.
#
# Set RUN_MIGRATIONS_ON_START=false when something else owns migrations - a
# Render preDeployCommand, a Kubernetes init container, or a release job. Do
# that before scaling beyond one instance, so simultaneous boots cannot race
# on schema changes.
# ---------------------------------------------------------------------------
set -eu

if [ "${RUN_MIGRATIONS_ON_START:-true}" = "true" ]; then
    echo "entrypoint: applying database migrations"
    alembic upgrade head
    echo "entrypoint: migrations up to date"
else
    echo "entrypoint: RUN_MIGRATIONS_ON_START=false, skipping migrations"
fi

exec "$@"

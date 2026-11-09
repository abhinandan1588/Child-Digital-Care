# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Child Digital Care backend image.
#
# Two stages so build tooling never ships to production, and a non-root
# runtime user so a container escape does not start as root.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build-only dependencies for packages with C extensions (argon2, asyncpg).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app

# Install into a self-contained virtualenv that is copied into the runtime
# stage, so the final image has no compiler and no pip cache.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install .


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production

# curl is used by the compose health check only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 cdc \
    && useradd --system --uid 10001 --gid cdc --create-home --shell /usr/sbin/nologin cdc

WORKDIR /srv/app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=cdc:cdc app ./app
COPY --chown=cdc:cdc migrations ./migrations
COPY --chown=cdc:cdc alembic.ini pyproject.toml ./

USER cdc

EXPOSE 8000

# No secrets, no .env and no service-account JSON are baked in; configuration
# arrives as environment variables and mounted secrets at run time.
#
# The port is read from $PORT so the same image runs on platforms that assign
# one (Render, Cloud Run, Heroku) and falls back to 8000 for compose and local
# runs. --proxy-headers is required behind those platforms' TLS terminators,
# otherwise every request looks like plain HTTP from the proxy's own address.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips '*'"]

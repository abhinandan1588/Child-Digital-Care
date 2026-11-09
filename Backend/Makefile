.DEFAULT_GOAL := help
SHELL := /bin/bash
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# The test suite runs on SQLite so it needs no external services. Everything
# else expects the Postgres/Redis stack from docker-compose.
TEST_ENV := APP_ENV=test DATABASE_URL=sqlite+aiosqlite:///:memory: REDIS_URL= \
	SECRET_KEY=test-secret-key-at-least-32-characters-long RATE_LIMIT_ENABLED=false
LOCAL_DB := DATABASE_URL=sqlite+aiosqlite:///./local.sqlite3

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Local environment
# ---------------------------------------------------------------------------
.PHONY: venv
venv: ## Create the virtualenv and install dependencies
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install -e '.[dev]'

.PHONY: install-fcm
install-fcm: ## Add the optional Firebase push dependency
	$(PIP) install -e '.[dev,fcm]'

.PHONY: lock
lock: ## Write requirements.lock from the current environment
	$(PIP) freeze --exclude-editable > requirements.lock

# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------
.PHONY: lint
lint: ## Lint (ruff)
	$(VENV)/bin/ruff check .

.PHONY: format
format: ## Format in place (ruff)
	$(VENV)/bin/ruff format .
	$(VENV)/bin/ruff check . --fix

.PHONY: format-check
format-check: ## Verify formatting without writing
	$(VENV)/bin/ruff format --check .

.PHONY: typecheck
typecheck: ## Static type check (mypy)
	$(VENV)/bin/mypy

.PHONY: test
test: ## Run the whole test suite
	$(TEST_ENV) $(PY) -m pytest tests

.PHONY: test-unit test-integration test-security test-contract
test-unit: ## Unit tests only
	$(TEST_ENV) $(PY) -m pytest tests/unit
test-integration: ## Integration tests only
	$(TEST_ENV) $(PY) -m pytest tests/integration
test-security: ## Authorization-boundary tests only
	$(TEST_ENV) $(PY) -m pytest tests/security
test-contract: ## API contract tests only
	$(TEST_ENV) $(PY) -m pytest tests/contract

.PHONY: coverage
coverage: ## Test suite with a coverage report
	$(TEST_ENV) $(PY) -m pytest tests --cov=app --cov-report=term-missing

.PHONY: check
check: lint format-check typecheck migration-check test ## Everything CI runs

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply migrations to DATABASE_URL
	$(VENV)/bin/alembic upgrade head

.PHONY: migration
migration: ## Autogenerate a migration: make migration m="add x"
	@test -n "$(m)" || (echo 'Usage: make migration m="describe the change"'; exit 1)
	$(VENV)/bin/alembic revision --autogenerate -m "$(m)"

.PHONY: migration-check
migration-check: ## Fail if the models and the migrations disagree
	rm -f .migration-check.sqlite3
	DATABASE_URL=sqlite+aiosqlite:///./.migration-check.sqlite3 $(VENV)/bin/alembic upgrade head
	DATABASE_URL=sqlite+aiosqlite:///./.migration-check.sqlite3 $(VENV)/bin/alembic check
	rm -f .migration-check.sqlite3

.PHONY: downgrade
downgrade: ## Roll back one migration
	$(VENV)/bin/alembic downgrade -1

.PHONY: sql
sql: ## Print the DDL a fresh migration would run
	$(VENV)/bin/alembic upgrade head --sql

# ---------------------------------------------------------------------------
# Running locally without Docker (SQLite)
# ---------------------------------------------------------------------------
.PHONY: dev
dev: ## Run the API against a local SQLite database
	$(LOCAL_DB) APP_ENV=development DEBUG=true REDIS_URL= \
		$(VENV)/bin/uvicorn app.main:app --reload --port 8000

.PHONY: dev-migrate
dev-migrate: ## Migrate the local SQLite database
	$(LOCAL_DB) $(VENV)/bin/alembic upgrade head

.PHONY: seed
seed: ## Seed obviously fake development data
	$(LOCAL_DB) APP_ENV=development $(PY) -m app.scripts.seed_dev

.PHONY: seed-rbac
seed-rbac: ## Seed the admin permission/role catalogue
	$(LOCAL_DB) APP_ENV=development $(PY) -m app.scripts.seed_admin_rbac

.PHONY: admin
admin: ## Create an admin: make admin email=ops@example.com role=super_admin
	@test -n "$(email)" || (echo 'Usage: make admin email=... [role=...]'; exit 1)
	$(LOCAL_DB) APP_ENV=development $(PY) -m app.scripts.create_admin \
		--email "$(email)" --role "$(or $(role),support_admin)" --generate-password

.PHONY: job
job: ## Run one background job: make job name=process_outbox
	@test -n "$(name)" || (echo 'Usage: make job name=process_outbox'; exit 1)
	$(LOCAL_DB) APP_ENV=development $(PY) -m app.workers.run_job $(name)

.PHONY: openapi
openapi: ## Write the OpenAPI document to openapi.json
	$(TEST_ENV) $(PY) -c "import json; from app.main import create_app; \
		print(json.dumps(create_app().openapi(), indent=2))" > openapi.json
	@echo "wrote openapi.json"

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
.PHONY: up
up: ## Build and start the Docker stack
	docker compose up --build -d

.PHONY: down
down: ## Stop the Docker stack
	docker compose down

.PHONY: logs
logs: ## Follow API logs
	docker compose logs -f api

.PHONY: docker-migrate
docker-migrate: ## Apply migrations inside the api container
	docker compose exec api alembic upgrade head

.PHONY: docker-test
docker-test: ## Run the test suite inside the api container
	docker compose exec api pytest

.PHONY: clean
clean: ## Remove caches and local scratch databases
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	rm -f local.sqlite3 .autogen.sqlite3 .mig.sqlite3 .migration-check.sqlite3
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

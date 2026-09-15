.PHONY: dev fmt lint migrate test test-terraform coverage

REMY_DATABASE_URL ?= sqlite:///.remy/reports.db
export REMY_DATABASE_URL
TERRAFORM ?= terraform

dev:
	mkdir -p .remy
	uv run uvicorn remy.api.app:app --host 127.0.0.1 --port 8000 --no-access-log

fmt:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv run ruff check .
	uv run mypy remy

test:
	uv run pytest

migrate:
	mkdir -p .remy
	REMY_DATABASE_URL="$(REMY_DATABASE_URL)" uv run python -c 'import os; from remy.db.store import Store; Store(os.environ["REMY_DATABASE_URL"]); print("prototype report table ready")'

test-terraform:
	uv run python -m scripts.validate_terraform --terraform "$(TERRAFORM)"

coverage:
	uv run python -m scripts.coverage

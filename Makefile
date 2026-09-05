.PHONY: install dev test lint format format-check check typecheck run clean up down logs ps

COMPOSE ?= docker compose

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=ulpf --cov-report=term-missing --cov-report=xml

lint:
	ruff check .

format:
	ruff format .
	ruff check --select I --fix .

format-check:
	ruff format --check .
	ruff check --select I .

# Run before every commit and at the end of every phase. Does not depend on
# pre-commit being installed (Windows-friendly equivalent: scripts/win/check.ps1).
# Each line is its own command, so `make` already stops at the first failure.
check:
	ruff format .
	ruff check . --fix
	ruff check .
	pytest -q

typecheck:
	mypy ulpf

run:
	python -m ulpf.cli.main run

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

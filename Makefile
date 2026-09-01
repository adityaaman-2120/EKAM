.PHONY: install dev test lint typecheck run clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=ulpf --cov-report=term-missing --cov-report=xml

lint:
	ruff check .

typecheck:
	mypy ulpf

run:
	uvicorn ulpf.api:app --host 0.0.0.0 --port 8000 --reload

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

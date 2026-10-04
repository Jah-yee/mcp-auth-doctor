.PHONY: install lint format test check build demo clean

PY ?= uv run

install:
	uv venv && uv pip install -e ".[dev]" build

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

demo:
	$(PY) python scripts/demo_server.py --port 8765

clean:
	rm -rf dist build .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

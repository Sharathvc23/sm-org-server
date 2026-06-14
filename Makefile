.PHONY: ci-local sync lint format typecheck test

# One command, run before every push. Mirrors CI exactly and hard-fails on the
# first red step. Same checks the GOVERNANCE gate names: ruff, mypy --strict, pytest.
ci-local: sync lint format typecheck test

sync:
	uv sync --extra dev

lint:
	uv run ruff check .

format:
	uv run ruff format --check .

typecheck:
	uv run mypy sm_server

test:
	uv run pytest -v

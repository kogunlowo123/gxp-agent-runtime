.PHONY: install format lint typecheck security contracts test integration validation check helm terraform image run clean

install:
	uv sync

format:
	uv run black src tests
	uv run ruff check src tests --fix

lint:
	uv run ruff check src tests
	uv run black --check src tests

typecheck:
	uv run mypy

security:
	uv run python -m bandit -q -r src -c pyproject.toml

contracts:
	uv run python -m gxp_agent_runtime.contracts --check

test:
	uv run pytest

integration:
	uv run pytest tests/integration -m integration --no-cov

validation:
	uv run pytest --junitxml=dist/junit.xml
	uv run python -m gxp_agent_runtime.validation --junit dist/junit.xml \
		--out dist/validation-package.json --markdown dist/traceability-matrix.md --strict

check: lint typecheck security contracts test

helm:
	helm lint deployments/helm/gxp-agent-runtime -f deployments/helm/gxp-agent-runtime/ci/test-values.yaml

terraform:
	terraform fmt -recursive -check deployments/terraform
	for c in aws azure gcp; do terraform -chdir=deployments/terraform/$$c init -backend=false -input=false && terraform -chdir=deployments/terraform/$$c validate; done

image:
	docker build -t gxp-agent-runtime:dev .

run:
	docker compose up --build

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml

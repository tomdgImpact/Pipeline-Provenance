# Developer entry points. CI runs the same targets, so a green `make check`
# locally means the same gates ran.

.DEFAULT_GOAL := help
PY := python3

.PHONY: help
help: ## List available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

.PHONY: install
install: ## Install the project and its development dependencies
	uv pip install -e ".[dev,remote]"

.PHONY: lint
lint: ## Style and static lint
	ruff check .
	ruff format --check .

.PHONY: type
type: ## Strict type check
	mypy

.PHONY: test
test: ## Unit and end-to-end suites (excludes the blocking security step)
	pytest -m "not security and not demo and not gui"

.PHONY: test-security
test-security: ## Adversarial corpus. Fails if it collects nothing or skips anything.
	pytest -m security -p no:randomly --strict-markers -W error::pytest.PytestUnraisableExceptionWarning

.PHONY: test-gui
test-gui: ## Browser coverage of the HTML report
	pytest -m gui

.PHONY: audit-self
audit-self: ## Run the dependency and secret gates this project recommends
	pip-audit --strict
	bandit -c pyproject.toml -r src -ll
	gitleaks detect --no-banner --redact

.PHONY: check
check: lint type test test-security ## Everything CI blocks on

.PHONY: clean
clean: ## Remove build and cache artifacts
	rm -rf build dist .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

# Makefile for Schema Development Environment

.PHONY: all help up down shell validate release test repo.init infra.deps infra.coverage infra.clean fmt lint check typecheck build

# Default to showing help
all: help

# =============================================================================
# Container Lifecycle Management
# =============================================================================

up:
	@echo "--- Starting development environment in the background ---"
	@docker compose up -d builder

down:
	@echo "--- Stopping development environment ---"
	@docker compose down -v

shell:
	@echo "--- Opening a shell into the running builder container ---"
	@docker compose exec builder bash

build:
	@echo "--- Building Docker images ---"
	@docker compose build

# =============================================================================
# Main Development Tasks
# =============================================================================

validate:
	@echo "--- Validating all schemas against the meta-schema ---"
	@docker compose exec builder python tools/compiler.py validate

release:
	@echo "--- Building and signing release schemas ---"
	@docker compose exec builder python tools/compiler.py release
	@tools/release.sh project.yaml
	@git add project.yaml

test:
	@echo "--- Running pytest for the compiler infrastructure ---"
	@docker compose exec builder python -m pytest --cov=tools.compiler --cov-report=term-missing tests/

fmt:
	@echo "--- Formatting Python code with Black and Isort ---"
	@docker compose exec builder python -m black .
	@docker compose exec builder python -m isort .

lint:
	@echo "--- Linting Python code with Ruff ---"
	@docker compose exec builder python -m ruff check .
	@echo "--- Linting YAML files with yamllint ---"
	@docker compose exec builder python -m yamllint .

typecheck:
	@echo "--- Running static type checking with MyPy ---"
	@docker compose exec builder python -m mypy .

check: fmt lint typecheck
	@echo "--- Running all code quality checks (format, lint, typecheck) ---"

# =============================================================================
# Repository Setup
# =============================================================================

repo.init:
	@echo "--- Initializing repository hooks ---"
	@sh tools/init-hooks.sh

# =============================================================================
# Infrastructure & Maintenance Tasks
# =============================================================================

infra.deps:
	@echo "--- Initializing Python dependencies into ./p_venv cache ---"
	@docker compose run --rm setup

infra.coverage:
	@echo "--- Generating HTML coverage report ---"
	@docker compose exec builder python -m pytest --cov=tools.compiler --cov-report=html
	@echo "HTML coverage report generated in ./htmlcov/index.html"

infra.clean:
	@echo "--- Cleaning up all generated files and caches ---"
	@docker compose down -v --remove-orphans
	@rm -rf ./p_venv
	@rm -f ./requirements.txt
	@rm -rf ./htmlcov

# =============================================================================
# Help
# =============================================================================

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Container Lifecycle:"
	@echo "  up            Start the development container in the background."
	@echo "  down          Stop and remove the development container."
	@echo "  shell         Open an interactive shell into the running container."
	@echo "  build         Build Docker images."
	@echo ""
	@echo "Main Tasks:"
	@echo "  validate      Run fast, offline validation of all schemas."
	@echo "  release       Build, checksum, and sign all non-dev schemas (requires Vault)."
	@echo "  test          Run pytest for the compiler infrastructure code."
	@echo "  fmt           Format Python code with Black and Isort."
	@echo "  lint          Lint Python code with Ruff and YAML files with yamllint."
	@echo "  typecheck     Run static type checking with MyPy."
	@echo "  check         Run all code quality checks (fmt, lint, typecheck)."
	@echo ""
	@echo "Repository Setup:"
	@echo "  repo.init     Set up the Git hooks for this repository (pre-commit, commit-msg)."
	@echo ""
	@echo "Infrastructure & Maintenance:"
	@echo "  infra.deps    (Re)generate requirements.txt and install dependencies into the cache."
	@echo "  infra.coverage Generate HTML coverage report."
	@echo "  infra.clean   Remove all generated files, caches, and stopped containers."

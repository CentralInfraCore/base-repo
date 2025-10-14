# Makefile for Schema Development Environment

.PHONY: all help up down shell validate release test repo.init infra.deps infra.lint infra.clean

# Default to showing help
all: help

# =============================================================================
# Container Lifecycle Management
# =============================================================================

up:
	@echo "--- Starting development environment in the background ---"
	@docker-compose up -d builder

down:
	@echo "--- Stopping development environment ---"
	@docker-compose down -v

shell:
	@echo "--- Opening a shell into the running builder container ---"
	@docker-compose exec builder bash

# =============================================================================
# Main Development Tasks
# =============================================================================

validate:
	@echo "--- Validating all schemas against the meta-schema ---"
	@docker-compose exec builder /app/p_venv/bin/python tools/compiler.py validate

release:
	@echo "--- Building and signing release schemas ---"
	@if [ -z "$(VAULT_TOKEN)" ]; then \
		echo "[ERROR] VAULT_TOKEN environment variable is not set."; \
		exit 1; \
	fi
	@docker-compose exec builder /app/p_venv/bin/python tools/compiler.py release

test:
	@echo "--- Running pytest for the compiler infrastructure ---"
	@docker-compose exec builder /app/p_venv/bin/python -m pytest

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
	@docker-compose run --rm setup

infra.lint:
	@echo "--- Running linters on infrastructure code ---"
	@echo "--> Linting Python code with flake8..."
	@docker-compose exec builder /app/p_venv/bin/flake8 tools/
	@echo "--> Linting YAML files with yamllint..."
	@docker-compose exec builder /app/p_venv/bin/yamllint .

infra.clean:
	@echo "--- Cleaning up all generated files and caches ---"
	@docker-compose down -v --remove-orphans
	@rm -rf ./p_venv
	@rm -f ./requirements.txt

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
	@echo ""
	@echo "Main Tasks:"
	@echo "  validate      Run fast, offline validation of all schemas."
	@echo "  release       Build, checksum, and sign all non-dev schemas (requires Vault)."
	@echo "  test          Run pytest for the compiler infrastructure code."
	@echo ""
	@echo "Repository Setup:"
	@echo "  repo.init     Set up the Git hooks for this repository (pre-commit, commit-msg)."
	@echo ""
	@echo "Infrastructure & Maintenance:"
	@echo "  infra.deps    (Re)generate requirements.txt and install dependencies into the cache."
	@echo "  infra.lint    Run static analysis and linting on the infrastructure code."
	@echo "  infra.clean   Remove all generated files, caches, and stopped containers."

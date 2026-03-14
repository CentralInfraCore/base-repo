# Makefile for Core Infrastructure Tasks

PYTHON := ./p_venv/bin/python
MCP_HOST ?= 127.0.0.1
MCP_PORT ?= 8000

# ---- Phony ----
.PHONY: infra.up infra.down infra.shell infra.build infra.fmt infra.lint infra.typecheck infra.check infra.repo.init infra.deps infra.coverage infra.clean infra.help infra.kb.build infra.mcp.run infra.mcp.run.sse infra.mcp.config

# =============================================================================
# Container Lifecycle Management
# =============================================================================

infra.up:
	@echo "--- Starting development environment in the background ---"
	@docker compose up -d

infra.down:
	@echo "--- Stopping development environment ---"
	@docker compose down -v

infra.shell:
	@echo "--- Opening a shell into the running builder container ---"
	@docker compose exec builder bash

infra.build:
	@echo "--- Building Docker images ---"
	@docker compose build

# =============================================================================
# Code Quality & Formatting
# =============================================================================

infra.fmt:
	@echo "--- Formatting Python code with Black and Isort ---"
	@docker compose exec builder python -m black --exclude p_venv .
	@docker compose exec builder python -m isort --skip-glob "p_venv/*" .

infra.lint:
	@echo "--- Linting Python code with Ruff ---"
	@docker compose exec builder python -m ruff check .
	@echo "--- Linting YAML files with yamllint ---"
	@docker compose exec builder python -m yamllint .

infra.typecheck:
	@echo "--- Running static type checking with MyPy ---"
	@docker compose exec builder python -m mypy --exclude p_venv .

infra.security:
	@echo "--- Running security checks with Bandit ---"
	@docker compose exec builder python3 -m bandit -r tools

infra.check: infra.fmt infra.lint infra.typecheck infra.security
	@echo "--- Running all code quality checks (format, lint, typecheck) ---"

# =============================================================================
# Repository Setup
# =============================================================================

infra.repo.init:
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
	@docker compose exec builder python -m pytest --ignore p_venv --cov=tools.compiler --cov-report=html
	@echo "HTML coverage report generated in ./htmlcov/index.html"

infra.test:
	@echo "--- Running pytest for the compiler infrastructure ---"
	@docker compose exec builder python -m pytest $(PYTEST_ARGS)

infra.clean:
	@echo "--- Cleaning up all generated files and caches ---"
	@docker compose down -v --remove-orphans
	@rm -rf ./p_venv
	@rm -f ./requirements.txt
	@rm -rf ./htmlcov

# =============================================================================
# Knowledge Base & MCP Server
# =============================================================================

infra.mcp.config:
	@echo "--- Generating .mcp.json for this repo ---"
	@sed "s|{{REPO_ROOT}}|$(shell pwd)|g" .mcp.json.tpl > .mcp.json
	@echo ".mcp.json generated at $(shell pwd)"

infra.kb.build:
	@echo "--- Building knowledge base from ./source ---"
	@$(PYTHON) make_source.py

infra.mcp.run:
	@echo "--- Starting MCP server (stdio) ---"
	@$(PYTHON) mcp-server/server.py

infra.mcp.run.sse:
	@echo "--- Starting MCP server (SSE / HTTP) on $(MCP_HOST):$(MCP_PORT) ---"
	@$(PYTHON) mcp-server/server.py --sse --host $(MCP_HOST) --port $(MCP_PORT)

# =============================================================================
# Infrastructure Help (Implementation Details)
# =============================================================================

infra.help:
	@echo ""
	@echo "--- Infrastructure Implementation Details (from infra.mk) ---"
	@echo "Container Lifecycle (using Docker):"
	@echo "  infra.up            Start the development container in the background."
	@echo "  infra.down          Stop and remove the development container."
	@echo "  infra.shell         Open an interactive shell into the running container."
	@echo "  infra.build         Build Docker images."
	@echo ""
	@echo "Code Quality & Formatting:"
	@echo "  infra.fmt           Format Python code with Black and Isort."
	@echo "  infra.lint          Lint Python code with Ruff and YAML files with yamllint."
	@echo "  infra.typecheck     Run static type checking with MyPy."
	@echo "  infra.check         Run all code quality checks (fmt, lint, typecheck)."
	@echo ""
	@echo "Repository Setup:"
	@echo "  infra.repo.init     Set up the Git hooks for this repository (pre-commit, commit-msg)."
	@echo ""
	@echo "Knowledge Base & MCP Server (uses ./p_venv, no Docker):"
	@echo "  mcp.config          Generate .mcp.json with absolute paths for this repo."
	@echo "  kb.build            Build the knowledge base from ./source (make_source.py)."
	@echo "  mcp.run             Start the MCP server in stdio mode."
	@echo "  mcp.run.sse         Start the MCP server in SSE/HTTP mode."
	@echo "    MCP_HOST=x.x.x.x   Bind host (default: 127.0.0.1, env: MCP_HOST)"
	@echo "    MCP_PORT=XXXX       Bind port (default: 8000, env: MCP_PORT)"
	@echo ""
	@echo "Infrastructure & Maintenance:"
	@echo "  infra.deps          (Re)generate requirements.txt and install dependencies into the cache."
	@echo "  infra.coverage      Generate HTML coverage report."
	@echo "  infra.clean         Remove all generated files, caches, and stopped containers."

# Makefile for Schema Development Environment

# ---- Includes ----
include mk/infra.mk

# ---- Phony ----
.PHONY: all help validate release test up down shell build fmt lint check typecheck repo.init

# Default to showing help
all: help

# =============================================================================
# Compiler Flags (can be overridden on command line, e.g., make release VERBOSE=1)
# =============================================================================
VERBOSE ?=
DEBUG ?=
DRY_RUN ?=
GIT_TIMEOUT ?= 60
VAULT_TIMEOUT ?= 10

# Construct COMPILER_CLI_ARGS based on VERBOSE and DEBUG flags
COMPILER_CLI_ARGS =
ifeq ($(VERBOSE),1)
    COMPILER_CLI_ARGS += --verbose
endif
ifeq ($(DEBUG),1)
    COMPILER_CLI_ARGS += --debug
endif
ifeq ($(DRY_RUN),1)
    COMPILER_CLI_ARGS += --dry-run
endif
COMPILER_CLI_ARGS += --git-timeout $(GIT_TIMEOUT)
COMPILER_CLI_ARGS += --vault-timeout $(VAULT_TIMEOUT)


# =============================================================================
# Container Lifecycle Management (Aliases)
# =============================================================================

up: infra.up
down: infra.down
shell: infra.shell
build: infra.build

# =============================================================================
# Main Development Tasks
# =============================================================================

validate:
	@echo "--- Validating all schemas against the meta-schema ---"
	@docker compose exec builder python tools/compiler.py validate $(COMPILER_CLI_ARGS)

release:
	@echo "--- Building and signing release schemas ---"
	@docker compose exec builder python tools/compiler.py release $(COMPILER_CLI_ARGS)
	# The release.sh script is no longer needed as its functionality has been integrated into compiler.py
	# @tools/release.sh project.yaml
	# @git add project.yaml # This is now handled by compiler.py

test:
	@echo "--- Running pytest for the compiler infrastructure ---"
	@docker compose exec builder python -m pytest --cov=tools.compiler --cov-report=term-missing tests/

# =============================================================================
# Code Quality & Formatting (Aliases)
# =============================================================================

fmt: infra.fmt
lint: infra.lint
typecheck: infra.typecheck
check: infra.check

# =============================================================================
# Repository Setup (Aliases)
# =============================================================================

repo.init: infra.repo.init

# =============================================================================
# Help
# =============================================================================

help:
	@echo "Usage: make [target] [OPTIONS]"
	@echo ""
	@echo "--- High-Level Project Commands ---"
	@echo "Development Environment:"
	@echo "  up            Start the development environment."
	@echo "  down          Stop and remove the development environment."
	@echo "  shell         Open an interactive shell into the running environment."
	@echo "  build         Build the development environment."
	@echo ""
	@echo "Main Tasks:"
	@echo "  validate      Run fast, offline validation of all schemas."
	@echo "  release       Build, checksum, and sign all non-dev schemas (requires Vault)."
	@echo "  test          Run pytest for the compiler infrastructure code."
	@echo ""
	@echo "Options for validate/release:"
	@echo "  VERBOSE=1     Enable verbose output."
	@echo "  DEBUG=1       Enable debug output (most verbose)."
	@echo "  DRY_RUN=1     Perform a trial run without making any changes."
	@echo "  GIT_TIMEOUT=N Set Git command timeout in seconds (default: 60)."
	@echo "  VAULT_TIMEOUT=N Set Vault API call timeout in seconds (default: 10)."
	@echo ""
	@echo "Code Quality & Formatting:"
	@echo "  fmt           Format all code."
	@echo "  lint          Lint all code and files."
	@echo "  typecheck     Run static type checking."
	@echo "  check         Run all code quality checks (fmt, lint, typecheck)."
	@echo ""
	@echo "Repository Setup:"
	@echo "  repo.init     Set up the Git hooks for this repository."
	@echo ""
	@echo "Maintenance:"
	@echo "  infra.deps    (Re)generate and install dependencies."
	@echo "  infra.coverage Generate code coverage report."
	@echo "  infra.clean   Remove all generated files and caches."
	@$(MAKE) infra.help

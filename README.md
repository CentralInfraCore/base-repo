# Schema Compiler & Signing Infrastructure

This repository provides a robust, containerized development environment for creating, validating, and cryptographically signing versioned schema definitions.

## Overview

The primary goal of this framework is to establish a governed, secure, and reproducible workflow for managing schemas. It ensures that every schema is validated and its integrity is verifiable through cryptographic signatures.

- **Governance:** All schemas must conform to a central meta-schema.
- **Security:** Signing is handled by HashiCorp Vault, ensuring private keys are never exposed.
- **Reproducibility:** The entire environment is containerized with Docker.

For a detailed explanation of the system's architecture and the release process, please see the **[Architecture Overview](docs/en/architecture.md)**.

---

## Getting Started

This section will guide you through the initial setup of the project.

### Prerequisites

- `docker`
- `docker-compose`
- `make`
- `git`

### Quick Start

1.  **Start the Vault Signing Agent:**
    A helper script is provided to run a local Vault server for development. This must be running in a separate terminal.
    ```sh
    # See the script's --help for all options
    ./tools/vault-sign-agent.sh -k <key.pem> -c <cert.crt> --root-ca-file <root.pem>
    ```

2.  **Initialize the Environment:**
    These commands will install dependencies, build the Docker image, start the container, and set up Git hooks.
    ```sh
    make infra.deps
    make build
    make up
    make repo.init
    ```

Your environment is now ready. For a detailed guide on day-to-day development and creating releases, please see the **[Developer Workflow](docs/en/workflow.md)**.

---

## Makefile Commands

A `Makefile` provides a simple interface for all common tasks.

- `make validate`: Validate your local schema changes.
- `make test`: Run the Python test suite.
- `make check`: Run all code quality checks (linting, formatting, type-checking).
- `make release-dependency VERSION=v1.2.3`: Create a new signed release of a dependency schema.

For a complete list and description of all available commands, please see the **[Makefile Cheatsheet](docs/en/makefile-cheatsheet.md)**.

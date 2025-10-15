# Schema Compiler & Signing Infrastructure

This repository serves as a template and a toolkit for creating, validating, and cryptographically signing versioned schema definitions. It provides a robust, containerized development environment to ensure consistency, security, and reproducibility.

## Core Concepts

- **Meta-Schema:** The `schema/index.yaml` file is the heart of the system. It's a JSON Schema that defines the rules for all other schema files, including required metadata, versioning formats, and the structure of the `createdBy` and `validity` fields.
- **Compiler Script:** The `tools/compiler.py` script is the engine. It validates schemas against the meta-schema and handles the "release" process, which includes calculating checksums and interacting with a Vault server to get cryptographic signatures.
- **Containerized Environment:** All development tasks are run inside a Docker container defined by `Dockerfile` and orchestrated by `docker-compose.yml`. This guarantees that the environment is identical for all developers and in CI/CD pipelines.
- **Makefile Interface:** The `Makefile` provides a simple, high-level interface for interacting with the complex underlying system.
- **Secure Signing:** The release process uses HashiCorp Vault for signing, ensuring that private keys are never directly handled by the script.

---

## Getting Started

Follow these steps to set up your local development environment.

### Prerequisites

- `docker`
- `docker-compose`
- `make`
- A running HashiCorp Vault instance for the `release` command (can be the one from `tools/vault-sign-agent.sh`).

### Quickstart (60 seconds)

Get up and running with these three commands:

```sh
make repo.init   # Initialize repository hooks
make up          # Start the development container
make test        # Run tests
```

### 1. Install Dependencies

This command will create a local cache for Python packages in a `./p_venv` directory. It only needs to be run once, or after updating `requirements.in`.

```sh
make infra.deps
```

### 2. Start the Development Container

This will start the `builder` container in the background. It will remain running until you stop it.

```sh
make up
```

### 3. Initialize the Repository

This step sets up the necessary Git hooks for automated validation and commit message signing. It should be run once per new clone of the repository.

```sh
make repo.init
```

Your environment is now ready!

---

## Creating a New Project from this Template

This repository includes a script to help you initialize a new project based on a specific branch or tag of this template. The script will clone the template, set up your new repository's remote, and clean up the temporary branches.

### Usage

1.  Navigate to a directory where you want to create your new project (do **not** run this inside the template repository itself).
2.  Run the `init_from_template.sh` script with the required parameters:

```sh
/path/to/this_template_repo/tools/init_from_template.sh <source_repo_url> <source_branch_or_tag> <your_new_repo_url>
```

**Example:**

To create a new project from the `feature-A` branch of the template:

```sh
# Assuming you are in your ~/projects directory
# and this template repo is at ~/git/base-repo
~/git/base-repo/tools/init_from_template.sh https://github.com/felhasznalo/repo.git feature-A https://github.com/XXX/YYY.git
```

The script will create a `YYY` directory, initialize it as a Git repository, push the `main` branch to your new remote URL (`https://github.com/XXX/YYY.git`), and configure the original template repository as a remote named `base` for future updates.

---

## Usage

All commands are run from the project root.

### Container Lifecycle

- `make up`: Start the development container in the background.
- `make down`: Stop and remove the development container.
- `make shell`: Open an interactive shell into the running container.
- `make build`: Build Docker images.

### Main Development Tasks

- `make validate`: Run fast, offline validation of all schemas.
- `make release`: Build, checksum, and sign all non-dev schemas (requires Vault).
- `make test`: Run pytest for the compiler infrastructure code.
- `make fmt`: Format Python code with Black and Isort.
- `make lint`: Lint Python code with Ruff and YAML files with yamllint.
- `make typecheck`: Run static type checking with MyPy.
- `make check`: Run all code quality checks (fmt, lint, typecheck).

### Repository Setup

- `make repo.init`: Set up the Git hooks for this repository (pre-commit, commit-msg).

### Infrastructure & Maintenance

- `make infra.deps`: (Re)generate requirements.txt and install dependencies into the cache.
- `make infra.coverage`: Generate HTML coverage report.
- `make infra.clean`: Remove all generated files, caches, and stopped containers.

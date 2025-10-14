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

## Usage

All commands are run from the project root.

### Validate Schemas

Run a fast, offline validation of all schema files in the `schema/` directory against the meta-schema.

```sh
make validate
```

### Run Tests

Run the `pytest` suite for the compiler infrastructure itself.

```sh
make test
```

### Create a Release

This command processes all non-`.dev` schemas, calculates their checksums, gets them signed by Vault, and outputs the final, signed artifacts to the `source/` directory.

**Before running, ensure the Vault service is running and you have set the required environment variables:**

```sh
# Example for the local vault-sign-agent
export VAULT_ADDR="https://host.docker.internal:18200"
export VAULT_TOKEN=$(cat $XDG_RUNTIME_DIR/vault/sign-token)

# For a production Vault with a proper CA, also set this:
# export VAULT_CACERT=/path/to/vault_ca.pem

make release
```

### Open a Shell in the Container

For debugging or running commands manually, you can open an interactive shell inside the running `builder` container.

```sh
make shell
```

### Stop the Environment

When you are finished with your work, stop the development container.

```sh
make down
```

### Clean Everything

To remove all generated files, caches, and stopped containers, run:

```sh
make infra.clean
```

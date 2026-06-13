# CIC WASM Module Template

This repository is a template for building a **CIC iSDK guest module**: a small
WASM binary (built with TinyGo) that the relay host
(`CIC-Relay/core/cabinet`) loads via [wazero](https://wazero.io) and drives
through the `Call` ABI, with a built-in, cryptographically signed release
pipeline.

## Overview

- **Module:** Implement your domain logic in `module/handlers.go` against the
  iSDK v1 `Call` ABI (`init` / `process` / `get` / `notify`). See the
  **[WASM Module Authoring Guide](docs/en/wasm-module-authoring.md)** for the
  full contract and error-typing conventions.
- **Build & host-load test:** `make wasm.build` compiles the guest module with
  TinyGo; `make wasm.test` host-loads `module/module.wasm` against the same
  wazero runtime used by the relay cabinet and exercises the ABI.
- **ABI manifest:** `project.yaml`'s `abi:` block (exports/operations/
  envelopeVersion) declares the guest <-> host contract; `make wasm.test`
  fails if `module/module.wasm` doesn't export everything it declares. See
  **[WASM ABI Contract](docs/contracts/en/wasm-abi.md)**.
- **Provenance:** Every release signs both the source-spec checksum
  (`project.yaml`) and the built artifact's `buildHash`
  (`sha256(module/module.wasm)`), so a released module is a "provable, signed
  artifact" end to end.

For a detailed explanation of the system's architecture and the release
process, please see the **[Architecture Overview](docs/en/architecture.md)**.

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

3.  **Build and test the WASM module:**
    ```sh
    make wasm.build
    make wasm.test
    ```

Your environment is now ready. For a detailed guide on day-to-day development and creating releases, please see the **[Developer Workflow](docs/en/workflow.md)**.

---

## Makefile Commands

A `Makefile` provides a simple interface for all common tasks.

- `make wasm.build`: Build `module/module.wasm` with TinyGo and compute its `buildHash`.
- `make wasm.rebuild-verify`: Rebuild the guest module to a scratch path and verify its sha256 matches `project.yaml`'s `metadata.buildHash` — catches a stale/non-reproducible `module.wasm`.
- `make wasm.test`: Host-load `module.wasm` against the relay cabinet ABI (wazero).
- `make validate`: Validate your local schema changes.
- `make test`: Run the Python test suite.
- `make check`: Run all code quality checks (linting, formatting, type-checking).
- `make golang.quality`: Run the Go quality gate (fmt/vet/lint/vuln) for `module/`.
- `make manifest-verify` / `make manifest-update`: Verify/regenerate `MANIFEST.sha256`.
- `make verify-release`: Offline release-readiness check — `project.yaml` schema (incl. `abi:`), `module.wasm` buildHash, ABI exports, `MANIFEST.sha256`, and provenance field status. See [release-artifact.md](docs/contracts/en/release-artifact.md).
- `make release VERSION=v1.2.3`: Create a new signed release.

For a complete list and description of all available commands, please see the **[Makefile Cheatsheet](docs/en/makefile-cheatsheet.md)**.

---

## Inherited: Schema Compiler & Signing Infrastructure

This template's release/signing pipeline (`tools/`, `mk/infra.mk`,
`project.yaml` + `project.schema.yaml`) was inherited from the CIC schema
compiler ecosystem (`schemas/main`). It provides:

- **Governance:** All schemas must conform to a central meta-schema.
- **Security:** Signing is handled by HashiCorp Vault, ensuring private keys are never exposed.
- **Reproducibility:** The entire environment is containerized with Docker.

This is the backbone underneath the WASM module template above — most users
of this template will not need to touch it directly beyond `make release`.

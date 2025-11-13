# Architecture Overview

This document provides a high-level overview of the schema compilation and signing infrastructure.

## Core Philosophy

The primary goal of this framework is to establish a governed, secure, and reproducible workflow for managing versioned schemas. Every non-development schema is cryptographically signed, ensuring its integrity and providing a verifiable audit trail.

- **Governance:** All schemas must conform to a central meta-schema.
- **Security:** Signing is handled by HashiCorp Vault, ensuring private keys are never exposed.
- **Reproducibility:** The entire environment is containerized with Docker, guaranteeing that every developer and CI/CD pipeline operates in an identical setting.

## Component Breakdown

The repository is structured into several key directories:

- **/schemas**: Contains the "source of truth" schemas. This is where developers make changes. The `index.yaml` file is the central **meta-meta-schema** that governs all other schemas.
- **/dependencies**: Stores released, signed, and versioned schemas that can be used as validators by other schemas. These are the building blocks.
- **/release**: Contains final, signed, application-specific schemas that are ready for consumption by applications.
- **/tools**: Holds all the scripting and tooling required to power the framework, including the Python compiler, shell scripts for the release process, and Git hooks.
- **/p_venv**: A local cache for Python dependencies, managed by `pip-tools`. This directory is not checked into Git.

## The Release and Signing Flow

The following diagram illustrates the process of creating a signed schema artifact from a source file.

```
+----------------+      +----------------+      +----------------------+      +---------------------+
|   Developer    |----->|  make release  |----->|   Docker Container   |----->|  Signed Artifact    |
| (Edits schema) |      | (in Makefile)  |      |  (tools/compiler.py) |      | (e.g., dependency.yaml) |
+----------------+      +----------------+      +----------+-----------+      +---------------------+
                                                           |
                                                           | (HTTPS API Call)
                                                           v
                                                  +----------------+
                                                  |  Vault Server  |
                                                  | (Signing & KV) |
                                                  +----------------+
```

**Flow Steps:**

1.  **Developer Action:** A developer modifies a schema file in the `/schemas` directory.
2.  **Initiate Release:** The developer runs `make release-dependency VERSION=v1.2.3`.
3.  **Container Execution:** The `Makefile` command executes the `tools/release.sh` script inside the `builder` Docker container.
4.  **Compilation & Signing:**
    - The `release.sh` script calls the `tools/compiler.py` script.
    - The compiler validates the source schema against its declared meta-schema.
    - It calculates a checksum of the schema's `spec` block.
    - It fetches the signing certificate and issuer certificate from Vault's KV store.
    - It constructs a metadata block, creates a hash of it, and sends **only the hash** to Vault's Transit Engine for signing.
    - Vault returns a signature.
5.  **Artifact Assembly:** The compiler assembles the final YAML file, including the original schema, the new version number, the checksum, the signature, and the `createdBy` block containing the certificate details.
6.  **Git Operations:** The `release.sh` script creates a new Git branch, commits the signed artifact, and creates a GPG-signed Git tag for the release.

import base64
import datetime
import hashlib
import json  # Added import for json
import logging
import os
import sys
import tempfile
from pathlib import Path

import requests  # Import requests for API accessibility check
import yaml
from jsonschema import ValidationError as JsonSchemaValidationError
from jsonschema import validate

from .releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    ReleaseError,
    VaultServiceError,
)


class ValidationFailureError(ReleaseError):
    """Custom exception for schema validation failures."""

    pass


def load_yaml(path: Path):
    """Loads a YAML file."""
    try:
        with open(path, "r") as f:
            content = f.read()
            if not content.strip():
                return None
            return yaml.safe_load(content)
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found at: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML syntax error in {path}: {e}") from e


def write_yaml(path: Path, data):
    """Writes data to a YAML file atomically."""
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, dir=path.parent, encoding="utf-8"
        ) as tmp_file:
            tmp_name = tmp_file.name
            yaml.dump(data, tmp_file, sort_keys=False, indent=2)
        os.replace(tmp_name, path)
    except (IOError, OSError) as e:
        raise ReleaseError(f"Failed to write YAML file to {path}: {e}") from e
    except Exception as e:
        raise ReleaseError(
            f"An unexpected error occurred during atomic write to {path}: {e}"
        ) from e
    finally:
        if tmp_name and Path(tmp_name).exists():
            try:
                Path(tmp_name).unlink()
            except Exception as unlink_e:
                logging.getLogger(__name__).warning(
                    f"Failed to clean up temporary file {tmp_name}: {unlink_e}"
                )


def get_reproducible_repo_hash(git_service, tree_id):
    """Calculates a reproducible SHA256 hash of a given git tree object."""
    try:
        archive_bytes = git_service.archive_tree_bytes(tree_id, prefix="./")
        hasher = hashlib.sha256()
        hasher.update(archive_bytes)
        digest = hasher.digest()
        return base64.b64encode(digest).decode("utf-8")
    except Exception as e:
        raise ReleaseError(f"Error during repo hash calculation: {e}") from e


class ReleaseManager:
    def __init__(
        self,
        config,
        git_service,
        vault_service,
        project_root: Path = Path("."),
        dry_run=False,
        logger=None,
    ):
        self.config = config
        self.git_service = git_service
        self.vault_service = vault_service
        self.project_root = project_root.resolve()
        self.dry_run = dry_run
        self.logger = logger if logger else logging.getLogger(__name__)

    def _path(self, relative_path):
        return self.project_root / relative_path

    def _check_base_branch_and_version(
        self, release_version: str, skip_git_state_checks: bool = False
    ):
        """Checks git state, branch, and version validity."""
        component_name = self.config.get("component_name", "main")
        original_base_branch = self.git_service.get_current_branch()
        self.logger.info(
            f"✓ Starting release process for component '{component_name}' from branch '{original_base_branch}'."
        )

        if not skip_git_state_checks:
            if self.git_service.is_dirty():
                raise GitStateError(
                    "Uncommitted changes detected. Please commit or stash them before starting a release."
                )
            self.git_service.assert_clean_index()

        return component_name, original_base_branch

    def _check_api_accessibility(self, api_url: str):
        """
        Checks if a given API URL is accessible.
        Exits with 0 regardless of success/failure, as requested.
        """
        self.logger.info(f"Checking API accessibility for: {api_url}")
        try:
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            self.logger.info(
                f"✓ API '{api_url}' is accessible. Status: {response.status_code}"
            )
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"API '{api_url}' is NOT accessible: {e}")
        # As requested, exit with 0 regardless of accessibility
        sys.exit(0)

    def _validate_final_project_yaml(self):
        """
        Validates the project.yaml against the project.schema.yaml.
        This is used in the finalization phase to ensure all required fields (including signatures) are present.
        """
        self.logger.info("Validating final project.yaml against schema...")
        try:
            schema_path = self._path("project.schema.yaml")
            schema = load_yaml(schema_path)
            if schema is None:
                raise ConfigurationError(
                    f"Project schema file '{schema_path}' is empty."
                )

            project_yaml_path = self._path("project.yaml")
            instance = load_yaml(project_yaml_path)
            if instance is None:
                raise ConfigurationError(
                    f"Project YAML file '{project_yaml_path}' is empty."
                )

            validate(instance=instance, schema=schema)
            self.logger.info("✓ project.yaml is valid against the schema.")
        except (ConfigurationError, JsonSchemaValidationError) as e:
            raise ValidationFailureError(f"Final project.yaml validation failed: {e}")
        except Exception as e:
            raise ReleaseError(
                f"An unexpected error occurred during project.yaml validation: {e}"
            )

    def _execute_developer_preparation_phase(
        self, release_version: str, component_name: str, original_base_branch: str
    ):
        """
        Handles the developer preparation phase: creates release branch, updates project.yaml, commits, tags.
        """
        project_yaml_path = self._path("project.yaml")
        release_branch_name = (
            f"{component_name}/releases/v{release_version}"
            if component_name != "main"
            else f"releases/v{release_version}"
        )

        try:
            self.logger.info(
                f"Creating release branch: '{release_branch_name}' from '{original_base_branch}'"
            )
            if not self.dry_run:
                self.git_service.checkout(release_branch_name, create_new=True)
            self.logger.info(f"✓ Switched to release branch: '{release_branch_name}'")

            self.logger.info("Collecting data for the developer release step...")

            tree_id = self.git_service.write_tree()
            repo_checksum = get_reproducible_repo_hash(self.git_service, tree_id)
            self.logger.info(f"✓ Calculated repository checksum: {repo_checksum}")

            cert_mount = self.config.get("vault_cert_mount")
            user_cert_secret_name = self.config.get("vault_cert_secret_name")
            user_cert_secret_key = self.config.get("vault_cert_secret_key")
            self.logger.info(
                f"Requesting user certificate from Vault: {cert_mount}/{user_cert_secret_name}..."
            )
            user_certificate = self.vault_service.get_certificate(
                cert_mount, user_cert_secret_name, user_cert_secret_key
            )
            self.logger.info("✓ User certificate obtained.")

            cic_cert_secret_name = self.config.get(
                "cic_root_ca_secret_name", "CICRootCA"
            )
            cic_cert_secret_key = self.config.get("vault_cert_secret_key")
            self.logger.info(
                f"Requesting CIC Root CA certificate from Vault: {cert_mount}/{cic_cert_secret_name}..."
            )
            cic_root_ca_cert = self.vault_service.get_certificate(
                cert_mount, cic_cert_secret_name, cic_cert_secret_key
            )
            self.logger.info("✓ CIC Root CA certificate obtained.")

            self.logger.info("Assembling the developer-stage project.yaml metadata...")
            project_data = load_yaml(project_yaml_path) or {}

            # Prepare data to be signed
            data_to_sign = {
                "name": project_data.get("metadata", {}).get("name", "unknown"),
                "version": release_version,  # Changed from f"v{release_version}"
                "checksum": repo_checksum,
                # Add any other relevant metadata that should be part of the signature
            }
            # Convert to a canonical JSON string for consistent hashing
            data_to_sign_json = json.dumps(
                data_to_sign, sort_keys=True, separators=(",", ":")
            )
            data_to_sign_hash = hashlib.sha256(
                data_to_sign_json.encode("utf-8")
            ).digest()
            data_to_sign_b64 = base64.b64encode(data_to_sign_hash).decode("utf-8")

            vault_key_name = self.config.get("vault_key_name")
            if not vault_key_name:
                raise ConfigurationError(
                    "vault_key_name not found in compiler_settings."
                )

            self.logger.info(
                f"Signing project metadata with Vault key: {vault_key_name}..."
            )
            signature = self.vault_service.sign(data_to_sign_b64, vault_key_name)
            self.logger.info("✓ Project metadata signed successfully.")

            metadata = {
                "name": project_data.get("metadata", {}).get("name", "unknown"),
                "description": project_data.get("metadata", {}).get("description", ""),
                "version": release_version,  # Changed from f"v{release_version}"
                "license": project_data.get("metadata", {}).get("license", ""),
                "owner": project_data.get("metadata", {}).get("owner", ""),
                "tags": project_data.get("metadata", {}).get("tags", []),
                "validatedBy": {"name": "TBD", "version": "TBD", "checksum": "TBD"},
                "createdBy": {
                    "name": "Gabor Zoltan Sinko",  # Placeholder, should be parsed from cert
                    "email": "sgz@centralinfracore.hu",  # Placeholder, should be parsed from cert
                    "certificate": user_certificate,
                    "issuer_certificate": cic_root_ca_cert,
                },
                "build_timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "validity": {
                    "from": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "until": (
                        datetime.datetime.now(datetime.timezone.utc)
                        + datetime.timedelta(days=365)
                    ).isoformat(),
                },
                "checksum": repo_checksum,
                "sign": signature,
                "buildHash": "",
                "cicSign": "",
                "cicSignedCA": {"certificate": ""},
            }
            project_data["metadata"] = metadata

            if self.dry_run:
                self.logger.info(
                    "[DRY-RUN] The following data would be written to project.yaml:"
                )
                self.logger.info(yaml.dump(project_data, sort_keys=False, indent=2))
            else:
                self.logger.info("Writing developer-stage metadata to project.yaml...")
                write_yaml(project_yaml_path, project_data)
                self.logger.info("✓ project.yaml updated for developer release step.")
                self.git_service.add(str(project_yaml_path))

                commit_message = (
                    f"release: Prepare {component_name} v{release_version} for build"
                )
                self.logger.info(f"Committing changes with message: '{commit_message}'")
                self.git_service.run(["git", "commit", "-m", commit_message])
                self.logger.info("✓ Developer release commit created successfully.")

            self.logger.info(
                f"✓ Release branch '{release_branch_name}' created. Proceed with build and finalization."
            )
            self.logger.info(
                f"ACTION REQUIRED: You are now on branch '{release_branch_name}'."
            )
            self.logger.info(
                "  1. Run your build process to generate artifacts and update 'buildHash' and 'sign' fields in project.yaml."
            )
            self.logger.info("  2. Commit the updated project.yaml to this branch.")
            self.logger.info(
                "  3. Merge this branch into 'main' and delete this branch when done."
            )

            self._check_api_accessibility(
                "https://api.centralinfra.hu"
            )  # This will sys.exit(0)

            return release_version, component_name
        except Exception as e:
            self.logger.critical(
                f"Release process failed during Git operations: {e}", exc_info=True
            )
            if not self.dry_run:
                try:
                    self.logger.warning(
                        f"Attempting to clean up release branch '{release_branch_name}'."
                    )
                    self.git_service.checkout(original_base_branch)
                    self.git_service.delete_branch(release_branch_name, force=True)
                    self.logger.info("✓ Release branch cleaned up.")
                except Exception as cleanup_e:
                    self.logger.critical(
                        f"Failed to clean up release branch: {cleanup_e}", exc_info=True
                    )
            raise ReleaseError(f"Release process failed: {e}") from e

    def _execute_finalization_phase(
        self,
        release_version: str,
        component_name: str,
        original_base_branch: str,
        release_branch_name: str,
    ):
        """
        Handles the finalization phase: validates project.yaml, commits, tags, merges, and cleans up.
        """
        project_yaml_path = self._path("project.yaml")
        main_branch = self.config.get("main_branch", "main")  # Get main_branch

        self.logger.info(
            f"--- Starting Finalization for v{release_version} on branch '{release_branch_name}' ---"
        )

        self._validate_final_project_yaml()
        self.logger.info(
            "✓ project.yaml is fully validated and ready for finalization."
        )

        if not self.dry_run:
            if self.git_service.is_dirty():
                self.logger.info(
                    "Committing pending changes to project.yaml (from build process)..."
                )
                self.git_service.add(str(project_yaml_path))
                self.git_service.run(
                    [
                        "git",
                        "commit",
                        "-m",
                        f"release: Finalize {component_name} v{release_version} build artifacts",
                    ]
                )
            else:
                self.logger.info(
                    "No pending changes to project.yaml detected. Assuming manual commit of build artifacts."
                )

        final_tag_name = f"{component_name}@v{release_version}"
        final_tag_message = f"Release {component_name} v{release_version}"
        if not self.dry_run:
            self.logger.info(f"Creating final annotated tag: '{final_tag_name}'")
            self.git_service.run(
                ["git", "tag", "-a", final_tag_name, "-m", final_tag_message]
            )
            self.logger.info("✓ Final release tag created.")

        self.logger.info(
            f"Switching back to main branch: '{main_branch}'"
        )  # Updated log message
        if not self.dry_run:
            self.git_service.checkout(main_branch)  # Checkout main_branch

        self.logger.info(
            f"Merging '{release_branch_name}' into '{main_branch}'"
        )  # Updated log message
        if not self.dry_run:
            self.git_service.merge(
                release_branch_name,
                no_ff=True,
                message=f"Merge branch '{release_branch_name}' for release {release_version}",
            )

        self.logger.info(f"Deleting release branch: '{release_branch_name}'")
        if not self.dry_run:
            self.git_service.delete_branch(release_branch_name)

        self.logger.info(
            f"✓ Release v{release_version} successfully finalized and merged into '{main_branch}'."
        )  # Updated log message

        return release_version, component_name

    def run_release_close(self, release_version: str):
        """
        Orchestrates the release process based on the current Git branch and dry_run status.
        """
        component_name, original_base_branch = self._check_base_branch_and_version(
            release_version, skip_git_state_checks=self.dry_run
        )

        if not self.vault_service:
            raise VaultServiceError("VaultService is not initialized.")

        main_branch = self.config.get("main_branch", "main")
        release_branch_name = (
            f"{component_name}/releases/v{release_version}"
            if component_name != "main"
            else f"releases/v{release_version}"
        )

        # If dry_run is active, always simulate the developer preparation phase
        if self.dry_run:
            self.logger.info("[DRY-RUN] Simulating Developer Preparation Phase.")
            return self._execute_developer_preparation_phase(
                release_version, component_name, original_base_branch
            )

        # Phase 1: Developer Preparation (if on main branch)
        elif original_base_branch == main_branch:
            return self._execute_developer_preparation_phase(
                release_version, component_name, original_base_branch
            )

        # Phase 2: Finalization (if on a release branch)
        elif original_base_branch == release_branch_name:
            return self._execute_finalization_phase(
                release_version,
                component_name,
                original_base_branch,
                release_branch_name,
            )

        # Phase 3: Invalid Branch
        else:
            raise GitStateError(
                f"Release command must be run from the main branch ('{main_branch}') "
                f"to start a new release, or from an existing release branch ('{release_branch_name}') "
                f"to finalize it. Currently on '{original_base_branch}'."
            )

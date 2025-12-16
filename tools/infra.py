import base64
import datetime
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path

import requests
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

    def _validate_final_project_yaml(self):
        """
        Validates the project.yaml against the project.schema.yaml.
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

    def run_check(self, release_version: str):
        """
        Performs pre-flight checks for a release.
        """
        self.logger.info(f"--- Running Pre-flight Checks for v{release_version} ---")

        if not self.vault_service:
            raise VaultServiceError("VaultService is not initialized.")

        if self.git_service.is_dirty():
            raise GitStateError(
                "Uncommitted changes detected. Please commit or stash them before starting a release."
            )
        self.git_service.assert_clean_index()
        self.logger.info("✓ Git repository is clean.")

        # Check Vault connectivity
        try:
            self.vault_service.check_connection()
            self.logger.info("✓ Vault connection successful.")
        except VaultServiceError as e:
            raise VaultServiceError(f"Vault connection check failed: {e}") from e

        self.logger.info("✓ Pre-flight checks passed.")
        return True

    def run_prepare_release(self, release_version: str):
        """
        Handles the developer preparation phase: creates release branch, updates project.yaml, commits.
        This phase should be run from the main development branch.
        """
        self.logger.info(f"--- Preparing Release v{release_version} ---")
        component_name = self.config.get("component_name", "main")
        main_branch = self.config.get("main_branch", "main")
        original_base_branch = self.git_service.get_current_branch()

        if original_base_branch != main_branch and not self.dry_run:
            raise GitStateError(
                f"Release preparation must be run from the main branch ('{main_branch}'). "
                f"Currently on '{original_base_branch}'."
            )

        if self.git_service.is_dirty() and not self.dry_run:
            raise GitStateError(
                "Uncommitted changes detected. Please commit or stash them before starting a release."
            )

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
            user_certificate = self.vault_service.get_certificate(
                cert_mount, user_cert_secret_name, user_cert_secret_key
            )

            cic_cert_secret_name = self.config.get("cic_root_ca_secret_name", "CICRootCA")
            cic_cert_secret_key = self.config.get("vault_cert_secret_key")
            cic_root_ca_cert = self.vault_service.get_certificate(
                cert_mount, cic_cert_secret_name, cic_cert_secret_key
            )

            self.logger.info("Assembling the developer-stage project.yaml metadata...")
            project_data = load_yaml(project_yaml_path) or {}

            data_to_sign = {
                "name": project_data.get("metadata", {}).get("name", "unknown"),
                "version": release_version,
                "checksum": repo_checksum,
            }
            data_to_sign_json = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":"))
            data_to_sign_hash = hashlib.sha256(data_to_sign_json.encode("utf-8")).digest()
            data_to_sign_b64 = base64.b64encode(data_to_sign_hash).decode("utf-8")

            vault_key_name = self.config.get("vault_key_name")
            if not vault_key_name:
                raise ConfigurationError("vault_key_name not found in compiler_settings.")

            signature = self.vault_service.sign(data_to_sign_b64, vault_key_name)
            self.logger.info("✓ Project metadata signed successfully.")

            metadata = {
                "name": project_data.get("metadata", {}).get("name", "unknown"),
                "description": project_data.get("metadata", {}).get("description", ""),
                "version": release_version,
                "license": project_data.get("metadata", {}).get("license", ""),
                "owner": project_data.get("metadata", {}).get("owner", ""),
                "tags": project_data.get("metadata", {}).get("tags", []),
                "validatedBy": {"name": "TBD", "version": "TBD", "checksum": "TBD"},
                "createdBy": {
                    "name": "Gabor Zoltan Sinko",
                    "email": "sgz@centralinfracore.hu",
                    "certificate": user_certificate,
                    "issuer_certificate": cic_root_ca_cert,
                },
                "build_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "validity": {
                    "from": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "until": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).isoformat(),
                },
                "checksum": repo_checksum,
                "sign": signature,
                "buildHash": "",
                "cicSign": "",
                "cicSignedCA": {"certificate": ""},
            }
            project_data["metadata"] = metadata

            if self.dry_run:
                self.logger.info("[DRY-RUN] The following data would be written to project.yaml:")
                self.logger.info(yaml.dump(project_data, sort_keys=False, indent=2))
            else:
                self.logger.info("Writing developer-stage metadata to project.yaml...")
                write_yaml(project_yaml_path, project_data)
                self.logger.info("✓ project.yaml updated for developer release step.")
                self.git_service.add(str(project_yaml_path))

                commit_message = f"release: Prepare {component_name} v{release_version} for build"
                self.logger.info(f"Committing changes with message: '{commit_message}'")
                self.git_service.run(["git", "commit", "-m", commit_message])
                self.logger.info("✓ Developer release commit created successfully.")

            self.logger.info(f"✓ Release branch '{release_branch_name}' created. Proceed with build and finalization.")
            self.logger.info(f"ACTION REQUIRED: You are now on branch '{release_branch_name}'.")
            self.logger.info("  1. Run your build process to generate artifacts and update 'buildHash' in project.yaml.")
            self.logger.info("  2. Commit the updated project.yaml to this branch.")
            self.logger.info(f"  3. Run 'compiler close --version {release_version}' to finalize the release.")

        except Exception as e:
            self.logger.critical(f"Release preparation failed: {e}", exc_info=True)
            if not self.dry_run:
                try:
                    self.logger.warning(f"Attempting to clean up by switching back to '{original_base_branch}'.")
                    self.git_service.checkout(original_base_branch)
                    self.git_service.delete_branch(release_branch_name, force=True)
                    self.logger.info(f"✓ Cleaned up failed release branch '{release_branch_name}'.")
                except Exception as cleanup_e:
                    self.logger.critical(f"Failed to clean up release branch: {cleanup_e}", exc_info=True)
            raise ReleaseError(f"Release preparation failed: {e}") from e

    def run_finalize_release(self, release_version: str):
        """
        Handles the finalization phase: validates project.yaml, commits, tags, merges, and cleans up.
        This phase should be run from the release branch.
        """
        self.logger.info(f"--- Finalizing Release v{release_version} ---")
        component_name = self.config.get("component_name", "main")
        main_branch = self.config.get("main_branch", "main")
        release_branch_name = (
            f"{component_name}/releases/v{release_version}"
            if component_name != "main"
            else f"releases/v{release_version}"
        )
        current_branch = self.git_service.get_current_branch()

        if current_branch != release_branch_name and not self.dry_run:
            raise GitStateError(
                f"Release finalization must be run from the release branch ('{release_branch_name}'). "
                f"Currently on '{current_branch}'."
            )

        self._validate_final_project_yaml()
        self.logger.info("✓ project.yaml is fully validated and ready for finalization.")

        project_yaml_path = self._path("project.yaml")
        if not self.dry_run:
            if self.git_service.is_dirty():
                self.logger.info("Committing pending changes to project.yaml (from build process)...")
                self.git_service.add(str(project_yaml_path))
                self.git_service.run(
                    ["git", "commit", "-m", f"release: Finalize {component_name} v{release_version} build artifacts"]
                )
            else:
                self.logger.info("No pending changes to project.yaml detected. Assuming manual commit of build artifacts.")

        final_tag_name = f"{component_name}@v{release_version}"
        final_tag_message = f"Release {component_name} v{release_version}"
        if self.dry_run:
            self.logger.info(f"[DRY-RUN] Would create final annotated tag: '{final_tag_name}'")
        else:
            self.logger.info(f"Creating final annotated tag: '{final_tag_name}'")
            self.git_service.run(["git", "tag", "-a", final_tag_name, "-m", final_tag_message])
            self.logger.info("✓ Final release tag created.")

        self.logger.info(f"Switching back to main branch: '{main_branch}'")
        if not self.dry_run:
            self.git_service.checkout(main_branch)

        self.logger.info(f"Merging '{release_branch_name}' into '{main_branch}'")
        if not self.dry_run:
            self.git_service.merge(
                release_branch_name,
                no_ff=True,
                message=f"Merge branch '{release_branch_name}' for release {release_version}",
            )

        self.logger.info(f"Deleting release branch: '{release_branch_name}'")
        if not self.dry_run:
            self.git_service.delete_branch(release_branch_name)

        self.logger.info(f"✓ Release v{release_version} successfully finalized and merged into '{main_branch}'.")

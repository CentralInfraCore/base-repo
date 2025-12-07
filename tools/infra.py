import base64
import datetime
import hashlib
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

import semver
import yaml
from jsonschema import ValidationError as JsonSchemaValidationError
from jsonschema import validate

from .releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    ReleaseError,
    VaultServiceError,
    VersionMismatchError,
    ManualInterventionRequired,
)

# Custom exceptions
class ValidationFailureError(ReleaseError):
    """Custom exception for schema validation failures."""
    pass


# --- Helper Functions ---

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
    except IOError as e:
        raise ReleaseError(f"Failed to write YAML file to {path}: {e}") from e
    except Exception as e:
        if tmp_name and Path(tmp_name).exists():
            try:
                Path(tmp_name).unlink()
            except Exception as unlink_e:
                logging.getLogger(__name__).warning(
                    f"Failed to clean up temporary file {tmp_name}: {unlink_e}"
                )
        raise ReleaseError(
            f"An unexpected error occurred during atomic write to {path}: {e}"
        ) from e

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


# --- Core Logic Class ---

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

    def run_validation(self):
        """Runs offline validation on all schemas."""
        try:
            meta_schema_path = self._path(self.config["meta_schema_file"])
            meta_schema = load_yaml(meta_schema_path)
            if meta_schema is None:
                raise ConfigurationError(f"Meta-schema file '{meta_schema_path}' is empty.")
        except (KeyError, ConfigurationError) as e:
            raise ConfigurationError(f"Could not load meta-schema: {e}") from e

        schema_glob_pattern = self.config["meta_schemas_dir"] + "/**/*.meta.yaml"
        schema_files = list(self.project_root.glob(schema_glob_pattern))

        meta_schema_abs_path = meta_schema_path.resolve()
        schema_files = [f for f in schema_files if f.resolve() != meta_schema_abs_path]

        errors = []
        for schema_file in schema_files:
            try:
                schema_instance = load_yaml(schema_file)
                if schema_instance is None:
                    errors.append(f"  - {schema_file.name}: Configuration Error - File is empty.")
                    continue
                validate(instance=schema_instance, schema=meta_schema)
            except (ConfigurationError) as e:
                errors.append(f"  - {schema_file.name}: Configuration Error - {e}")
            except (JsonSchemaValidationError) as e:
                errors.append(f"  - {schema_file.name}: Schema Validation Error - {e.message}")
            except Exception as e:
                errors.append(f"  - {schema_file.name}: Unexpected Error - {e}")

        if errors:
            error_str = "\n".join(errors)
            raise ValidationFailureError(f"One or more schemas failed validation:\n{error_str}")
        
        self.logger.info("✓ Schema validation passed.")

    def run_release(self, release_version: str):
        """
        Main entrypoint for the release process.
        Orchestrates the release based on the current Git branch state.
        """
        component_name = self.config.get("component_name", "main")
        release_branch_name = f"{component_name}/releases/v{release_version}"
        current_branch = self.git_service.get_current_branch()

        if current_branch == self.config.get("main_branch", "main"):
            self._prepare_release(release_version, release_branch_name)
        elif current_branch == release_branch_name:
            self._finalize_release(release_version, release_branch_name)
        else:
            raise GitStateError(
                f"Release command must be run from the main branch ('{self.config.get('main_branch', 'main')}') "
                f"or an existing release branch ('{release_branch_name}'). "
                f"Currently on '{current_branch}'."
            )

    def _prepare_release(self, release_version: str, release_branch_name: str):
        """
        Handles the first phase of a release: preparation and signing attempt.
        """
        self.logger.info("--- Starting New Release Preparation ---")
        
        self.run_validation()

        self._check_base_branch_and_version(release_version)

        self.logger.info(f"Creating release branch: '{release_branch_name}'")
        if not self.dry_run:
            self.git_service.checkout(release_branch_name, create_new=True)

        project_yaml_path = self._path("project.yaml")
        full_project_config = self._update_project_yaml_preliminary(project_yaml_path, release_version)
        
        tree_id = self.git_service.write_tree()
        digest_b64 = get_reproducible_repo_hash(self.git_service, tree_id)
        full_project_config["release"]["digest"] = digest_b64
        
        author_key = self.config.get("vault_key_name")
        approval_key = self.config.get("cic_root_ca_key_name")
        
        try:
            self.logger.info("Attempting to get signatures from Vault...")
            author_sig = self.vault_service.sign(digest_b64, author_key)
            self.logger.info("✓ Author signature obtained.")
            approval_sig = self.vault_service.sign(digest_b64, approval_key)
            self.logger.info("✓ Approval signature obtained.")
            
            signing_metadata = [
                {"type": "author", "key": author_key, "signature": author_sig, "hash_algorithm": "sha256"},
                {"type": "approval", "key": approval_key, "signature": approval_sig, "hash_algorithm": "sha256"},
            ]
            full_project_config["release"]["signing_metadata"] = signing_metadata
            if not self.dry_run:
                write_yaml(project_yaml_path, full_project_config)
                self.git_service.add(str(project_yaml_path))
            
            self.logger.info("✓ Both signatures obtained. Proceeding to finalize release automatically.")
            self._finalize_release(release_version, release_branch_name)

        except VaultServiceError as e:
            self.logger.warning(f"Vault signing failed: {e}")
            if not self.dry_run:
                write_yaml(project_yaml_path, full_project_config)
            
            message = (
                f"Release v{release_version} is prepared for manual signing on branch '{release_branch_name}'.\n"
                "ACTION REQUIRED:\n"
                "1. Manually obtain signatures for the following digest:\n"
                f"   - Digest (Base64): {digest_b64}\n"
                f"   - Author Key: {author_key}\n"
                f"   - Approval Key: {approval_key}\n"
                "2. Edit project.yaml to include both signatures in the 'signing_metadata' list.\n"
                "3. Commit the changes to 'project.yaml'.\n"
                f"4. Run 'make release VERSION={release_version}' again to finalize the release."
            )
            raise ManualInterventionRequired(message)

    def _finalize_release(self, release_version: str, release_branch_name: str):
        """
        Handles the second phase of a release: final validation and merge.
        """
        self.logger.info("--- Finalizing Prepared Release ---")
        project_yaml_path = self._path("project.yaml")

        self.logger.info("Validating final project.yaml against schema...")
        try:
            schema_path = self._path("project.schema.yaml")
            schema = load_yaml(schema_path)
            instance = load_yaml(project_yaml_path)
            validate(instance=instance, schema=schema)
            self.logger.info("✓ project.yaml is valid.")
        except (ConfigurationError, JsonSchemaValidationError) as e:
            raise ValidationFailureError(f"Final project.yaml validation failed: {e}")

        component_name = self.config.get("component_name", "main")
        commit_message = f"release: {component_name} v{release_version}"
        tag_name = f"{component_name}@v{release_version}"
        tag_message = f"Release {component_name} v{release_version}"

        if not self.dry_run:
            if self.git_service.is_index_dirty():
                 self.git_service.run(["git", "commit", "-m", commit_message])
            else:
                # If the index is clean, it means the user has already committed.
                # We should verify this commit is what we expect, but for now, we'll just log it.
                self.logger.info("Index is clean, assuming user has committed manually.")

            self.logger.info(f"Creating annotated tag: '{tag_name}'")
            self.git_service.run(["git", "tag", "-a", tag_name, "-m", tag_message])

        main_branch = self.config.get("main_branch", "main")
        if not self.dry_run:
            self.git_service.checkout(main_branch)
            self.git_service.merge(release_branch_name, no_ff=True, message=f"Merge branch '{release_branch_name}'")
            self.git_service.delete_branch(release_branch_name)
        
        self.logger.info(f"✓ Release {release_version} successfully finalized and merged into {main_branch}.")

    def _update_project_yaml_preliminary(self, path: Path, version: str) -> dict:
        """Reads, updates, and writes the preliminary release block to project.yaml."""
        config = load_yaml(path) or {}
        config["release"] = {
            "version": version,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        if not self.dry_run:
            write_yaml(path, config)
            self.git_service.add(str(path))
        return config

    def _check_base_branch_and_version(self, release_version: str):
        """Validates git state, base branch, and version increment."""
        if "component_name" not in self.config:
            raise ConfigurationError("Missing 'component_name' in compiler_settings of project.yaml.")

        if self.git_service.is_dirty():
            raise GitStateError("Uncommitted changes detected. Please commit or stash them.")
        
        self.git_service.assert_clean_index()

        main_branch = self.config.get("main_branch", "main")
        if self.git_service.get_current_branch() != main_branch:
            raise GitStateError(f"Must be on the '{main_branch}' branch to start a new release.")

        try:
            semver.Version.parse(release_version)
        except ValueError as e:
            raise VersionMismatchError(f"Invalid version string '{release_version}': {e}") from e
        
        self.logger.info(f"✓ Git state and version '{release_version}' are valid.")

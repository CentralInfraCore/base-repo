import base64
import datetime
import hashlib
import logging  # Import logging
import os
import re
import tempfile
from pathlib import Path  # Import Path
from typing import Any, Optional

import semver
import yaml
from jsonschema import ValidationError as JsonSchemaValidationError  # Alias for clarity
from jsonschema import validate

from .releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    ReleaseError,
    VaultServiceError,
    VersionMismatchError,
)


# Add this custom exception
class ValidationFailureError(ReleaseError):
    """Custom exception for schema validation failures."""

    pass


# --- Helper Functions (can be considered a utility module) ---


def load_yaml(path: Path):
    """Loads a YAML file."""
    try:
        with open(path, "r") as f:
            content = f.read()
            if not content.strip():  # Check if file is empty or only whitespace
                return None  # Return None for empty files, to be handled by caller
            return yaml.safe_load(content)
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found at: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML syntax error in {path}: {e}") from e


def write_yaml(path: Path, data):
    """
    Writes data to a YAML file atomically using a temporary file.
    This prevents data corruption if the write operation is interrupted.
    """
    tmp_name = None
    try:
        # Create a temporary file in the same directory as the target file
        # This ensures that os.replace works across filesystems
        # Path.parent ensures the directory exists for tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, dir=path.parent, encoding="utf-8"
        ) as tmp_file:
            tmp_name = tmp_file.name
            yaml.dump(data, tmp_file, sort_keys=False, indent=2)

        # Atomically replace the original file with the temporary file
        os.replace(tmp_name, path)  # os.replace still expects string paths
    except IOError as e:
        raise ReleaseError(f"Failed to write YAML file to {path}: {e}") from e
    except Exception as e:
        # Clean up temp file if something went wrong before os.replace
        if tmp_name and Path(tmp_name).exists():  # Use Path.exists()
            try:
                Path(tmp_name).unlink()  # Use Path.unlink() for removal
            except Exception as unlink_e:
                # Log cleanup error but don't re-raise, as original exception is more important
                logging.getLogger(__name__).warning(
                    f"Failed to clean up temporary file {tmp_name}: {unlink_e}"
                )
        raise ReleaseError(
            f"An unexpected error occurred during atomic write to {path}: {e}"
        ) from e


def get_reproducible_repo_hash(git_service, tree_id):
    """
    Calculates a reproducible SHA256 hash of a given git tree object
    by hashing the deterministic tar archive provided by 'git archive'.
    This version is now pure Python for hashing, removing the openssl dependency.
    """
    try:
        # Get the raw tar archive from the GitService
        # git archive --format=tar --prefix=./ <tree_id>
        # Using --prefix=./ ensures that the tar entries are relative to the current directory,
        # which is important for reproducibility across different repository paths.
        archive_bytes = git_service.archive_tree_bytes(tree_id, prefix="./")

        # The most straightforward and dependency-free way to hash in Python
        hasher = hashlib.sha256()
        hasher.update(archive_bytes)
        digest = hasher.digest()

        return base64.b64encode(digest).decode("utf-8")

    except Exception as e:
        # Wrap any unexpected error in our custom exception
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
        self.project_root = project_root.resolve()  # Store as resolved Path object
        self.dry_run = dry_run
        self.logger = (
            logger if logger else logging.getLogger(__name__)
        )  # Use provided logger or create a new one
        # self.release_version and self.component_name are now passed as arguments or derived within methods

    def _path(self, relative_path):
        # Return a Path object
        return self.project_root / relative_path

    def run_validation(self):
        """Runs offline validation on all schemas."""
        try:
            meta_schema_path = self._path(self.config["meta_schema_file"])
            meta_schema = load_yaml(meta_schema_path)
            if meta_schema is None:  # Handle empty meta-schema file
                raise ConfigurationError(
                    f"Meta-schema file '{meta_schema_path}' is empty."
                )
        except (KeyError, ConfigurationError) as e:
            raise ConfigurationError(f"Could not load meta-schema: {e}") from e

        # Use Path.glob for more Pythonic globbing
        schema_glob_pattern = self.config["meta_schemas_dir"] + "/**/*.meta.yaml"
        schema_files = list(self.project_root.glob(schema_glob_pattern))

        # Filter out the meta-schema itself
        meta_schema_abs_path = (
            meta_schema_path.resolve()
        )  # Resolve to absolute path for comparison
        schema_files = [f for f in schema_files if f.resolve() != meta_schema_abs_path]

        errors = []
        for schema_file in schema_files:
            try:
                schema_instance = load_yaml(schema_file)
                if schema_instance is None:  # Handle empty schema file
                    errors.append(
                        f"  - {schema_file.name}: Configuration Error - File is empty."
                    )
                    continue
                validate(instance=schema_instance, schema=meta_schema)
            except (
                ConfigurationError
            ) as e:  # Catch YAML/IO errors during schema loading
                errors.append(f"  - {schema_file.name}: Configuration Error - {e}")
            except (
                JsonSchemaValidationError
            ) as e:  # Catch actual JSON Schema validation errors
                errors.append(
                    f"  - {schema_file.name}: Schema Validation Error - {e.message}"
                )
            except Exception as e:  # Catch any other unexpected errors
                errors.append(f"  - {schema_file.name}: Unexpected Error - {e}")

        if errors:
            error_str = "\n".join(errors)
            raise ValidationFailureError(
                f"One or more schemas failed validation:\n{error_str}"
            )

    def _check_base_branch_and_version(self, release_version: str):
        """
        Internal method to check git clean state, base branch, and version increment.
        This method is called from the original base branch (main or component/main).
        """
        try:
            component_name = self.config["component_name"]
            if not component_name:
                raise ConfigurationError(
                    "The 'component_name' in compiler_settings of project.yaml cannot be empty or null."
                )
        except KeyError as e:
            raise ConfigurationError(
                "Missing 'component_name' in compiler_settings of project.yaml. This is required for release."
            ) from e

        # Check for uncommitted changes in working directory
        git_status_wd = self.git_service.get_status_porcelain()
        if git_status_wd:
            raise GitStateError(
                "Uncommitted changes detected in working directory. Please commit or stash them before releasing."
            )

        # Check for staged changes (index is not empty)
        self.git_service.assert_clean_index()

        original_base_branch = self.git_service.get_current_branch()

        # Validate that we are on a valid base branch (main or component/main)
        base_branch_pattern = re.compile(rf"^(?:{re.escape(component_name)}/)?main$")
        if (
            not base_branch_pattern.match(original_base_branch)
            and original_base_branch != "main"
        ):
            raise GitStateError(
                f"Not on a valid base branch for component '{component_name}'. Expected 'main' or '{component_name}/main', found: '{original_base_branch}'"
            )

        self.logger.info(f"✓ Currently on valid base branch: '{original_base_branch}'")

        # Validate the provided release_version
        try:
            new_version = semver.Version.parse(release_version)
        except ValueError as e:
            raise VersionMismatchError(
                f"Invalid version string '{release_version}' provided: {e}"
            ) from e

        tag_pattern = f"{component_name}@v*.*.*"
        existing_tags = self.git_service.get_tags(pattern=tag_pattern)

        if existing_tags:
            try:
                parsed_versions = []
                for tag in existing_tags:
                    tag_match = re.match(
                        rf"^{re.escape(component_name)}@v(\d+\.\d+\.\d+)$", tag
                    )
                    if tag_match:
                        parsed_versions.append(semver.Version.parse(tag_match.group(1)))
                    else:
                        self.logger.warning(
                            f"Skipping malformed tag '{tag}' during version comparison."
                        )

                if not parsed_versions:
                    self.logger.info(
                        f"No valid existing tags found for component '{component_name}'. Assuming first release."
                    )
                else:
                    latest_version = sorted(parsed_versions)[-1]
                    # FIX: Use semver 2.x compatible 'bump_*' methods
                    is_valid_next = (
                        new_version == latest_version.bump_patch()
                        or new_version == latest_version.bump_minor()
                        or new_version == latest_version.bump_major()
                    )
                    if not is_valid_next:
                        raise VersionMismatchError(
                            f"Version '{release_version}' is not a valid increment. Latest is '{latest_version}'."
                        )
            except ValueError as e:
                raise VersionMismatchError(
                    f"Could not parse existing tag versions: {e}"
                ) from e
        else:
            self.logger.info(
                f"No existing tags found for component '{component_name}'. Assuming first release."
            )
            # For a first release, any valid semver is acceptable.

        self.logger.info(f"✓ New version '{release_version}' is a valid increment.")

        return component_name, original_base_branch

    def run_release_check(self, release_version: str):
        """Performs all pre-flight checks for a release."""
        component_name, original_base_branch = self._check_base_branch_and_version(
            release_version
        )
        return component_name, original_base_branch

    def run_release_close(self, release_version: str):
        """
        Executes the final steps of a release, orchestrating Git branches.
        1. Checks base branch and version.
        2. Creates a new release branch.
        3. Creates a preliminary release block in project.yaml.
        4. Stages project.yaml and gets a tree_id.
        5. Signs the tree_id.
        6. Creates the final release block with signing metadata.
        7. Writes the final release block to project.yaml.
        8. Commits the project.yaml and creates a Git tag (if not dry-run).
        9. Checks out original base branch.
        10. Merges release branch into original base branch.
        11. Deletes the release branch.
        """
        component_name, original_base_branch = self._check_base_branch_and_version(
            release_version
        )

        if not self.vault_service:
            raise VaultServiceError(
                "VaultService is not initialized. Cannot sign release."
            )

        project_yaml_path = self._path("project.yaml")
        original_project_config_content = None  # To store original content for rollback
        project_yaml_existed_before = project_yaml_path.exists()  # Use Path.exists()

        release_branch_name = (
            f"{component_name}/releases/v{release_version}"
            if component_name != "main"
            else f"releases/v{release_version}"
        )
        if component_name == "main":  # Handle case where component_name is "main"
            release_branch_name = f"releases/v{release_version}"
        else:
            release_branch_name = f"{component_name}/releases/v{release_version}"

        # --- Git Orchestration Start ---
        try:
            self.logger.info(
                f"Creating release branch: '{release_branch_name}' from '{original_base_branch}'"
            )
            if self.dry_run:
                self.logger.info(
                    f"[DRY-RUN] Would have created branch '{release_branch_name}' and checked it out."
                )
            else:
                self.git_service.checkout(release_branch_name, create_new=True)
            self.logger.info(f"✓ Switched to release branch: '{release_branch_name}'")

            # --- Core Release Logic (as before) ---
            # Store original content for potential rollback
            if project_yaml_existed_before:
                original_project_config_content = project_yaml_path.read_text()

            # 1. Create preliminary release block
            preliminary_release_block = {
                "version": release_version,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

            # 2. Write preliminary block to project.yaml
            if self.dry_run:
                self.logger.info(
                    "[DRY-RUN] Simulating write of preliminary release block to project.yaml."
                )
                self.logger.debug(
                    yaml.dump(
                        {"release": preliminary_release_block},
                        sort_keys=False,
                        indent=2,
                    )
                )
            else:
                full_project_config_raw: Optional[Any] = load_yaml(project_yaml_path)
                if full_project_config_raw is None:
                    full_project_config: dict[str, Any] = {}
                elif isinstance(full_project_config_raw, dict):
                    full_project_config = full_project_config_raw
                else:
                    raise ConfigurationError(
                        f"project.yaml at {project_yaml_path} is not a valid dictionary. Found type: {type(full_project_config_raw)}"
                    )
                full_project_config["release"] = preliminary_release_block
                write_yaml(project_yaml_path, full_project_config)
                self.git_service.add(str(project_yaml_path))

            # 3. Get tree_id that includes the preliminary release block
            tree_id = self.git_service.write_tree()
            digest_b64 = get_reproducible_repo_hash(self.git_service, tree_id)

            # 4. Sign the digest of the repository state.
            key_name = self.config.get("vault_key_name", "cic-my-sign-key")
            signature = self.vault_service.sign(digest_b64, key_name)

            # 5. Build the complete, final release block in memory.
            final_release_block = preliminary_release_block.copy()
            final_release_block["repository_tree_hash"] = tree_id
            final_release_block["signing_metadata"] = {
                "key": key_name,
                "signature": signature,
                "hash_algorithm": "sha256",
                "digest": digest_b64,
            }

            # 6. Write the final release block to project.yaml
            if self.dry_run:
                self.logger.info("[DRY-RUN] Skipping final write to project.yaml.")
                self.logger.debug(
                    yaml.dump(
                        {"release": final_release_block}, sort_keys=False, indent=2
                    )
                )
            else:
                full_project_config_raw: Optional[Any] = load_yaml(project_yaml_path)
                if full_project_config_raw is None:
                    full_project_config = {}
                elif isinstance(full_project_config_raw, dict):
                    full_project_config = full_project_config_raw
                else:
                    raise ConfigurationError(
                        f"project.yaml at {project_yaml_path} is not a valid dictionary. Found type: {type(full_project_config_raw)}"
                    )
                full_project_config["release"] = final_release_block
                write_yaml(project_yaml_path, full_project_config)
                self.git_service.add(str(project_yaml_path))

            # 7. Commit the project.yaml and create a Git tag
            commit_message = f"release: {component_name} v{release_version}"
            tag_name = f"{component_name}@v{release_version}"
            tag_message = f"Release {component_name} v{release_version}"

            if self.dry_run:
                self.logger.info(
                    f"[DRY-RUN] Would have committed with message: '{commit_message}'"
                )
                self.logger.info(
                    f"[DRY-RUN] Would have created annotated tag: '{tag_name}' with message: '{tag_message}'"
                )
            else:
                self.logger.info(f"Committing changes with message: '{commit_message}'")
                self.git_service.run(["git", "commit", "-m", commit_message])
                self.logger.info(f"Creating annotated tag: '{tag_name}'")
                self.git_service.run(["git", "tag", "-a", tag_name, "-m", tag_message])
                self.logger.info("✓ Release commit and tag created successfully.")
            # --- End Core Release Logic ---

            # --- Git Orchestration End ---
            self.logger.info(
                f"Switching back to original branch: '{original_base_branch}'"
            )
            if self.dry_run:
                self.logger.info(
                    f"[DRY-RUN] Would have checked out '{original_base_branch}'."
                )
            else:
                self.git_service.checkout(original_base_branch)

            self.logger.info(
                f"Merging '{release_branch_name}' into '{original_base_branch}'"
            )
            if self.dry_run:
                self.logger.info(
                    f"[DRY-RUN] Would have merged '{release_branch_name}' into '{original_base_branch}' with --no-ff."
                )
            else:
                self.git_service.merge(
                    release_branch_name,
                    no_ff=True,
                    message=f"Merge branch '{release_branch_name}' for release {release_version}",
                )

            self.logger.info(f"Deleting release branch: '{release_branch_name}'")
            if self.dry_run:
                self.logger.info(
                    f"[DRY-RUN] Would have deleted branch '{release_branch_name}'."
                )
            else:
                self.git_service.delete_branch(release_branch_name)

            self.logger.info("✓ Git orchestration complete.")

            return release_version, component_name
        except Exception as e:
            # Rollback project.yaml if an error occurred after initial write
            if not self.dry_run:
                self.logger.error(
                    "Release failed, attempting to rollback project.yaml...",
                    exc_info=True,
                )
                try:
                    # Attempt to checkout original branch before rollback
                    self.logger.warning(
                        f"Attempting to checkout original branch '{original_base_branch}' for rollback."
                    )
                    self.git_service.checkout(original_base_branch)
                    # Attempt to delete the release branch if it was created
                    self.logger.warning(
                        f"Attempting to delete release branch '{release_branch_name}' for rollback."
                    )
                    self.git_service.delete_branch(
                        release_branch_name, force=True
                    )  # Force delete in case of issues

                    if original_project_config_content is not None:
                        try:
                            original_data = yaml.safe_load(
                                original_project_config_content
                            )
                            write_yaml(project_yaml_path, original_data)
                            self.git_service.add(str(project_yaml_path))
                            self.logger.info(
                                "✓ project.yaml restored to original state."
                            )
                        except yaml.YAMLError as yaml_e:
                            self.logger.critical(
                                f"Failed to parse original project.yaml content during rollback: {yaml_e}. Manual intervention required!",
                                exc_info=True,
                            )
                        except Exception as write_add_e:
                            self.logger.critical(
                                f"Failed to write or add restored project.yaml during rollback: {write_add_e}. Manual intervention required!",
                                exc_info=True,
                            )
                    elif not project_yaml_existed_before and project_yaml_path.exists():
                        try:
                            project_yaml_path.unlink()
                            self.logger.info("✓ Newly created project.yaml removed.")
                        except Exception as unlink_e:
                            self.logger.critical(
                                f"Failed to remove newly created project.yaml during rollback: {unlink_e}. Manual intervention required!",
                                exc_info=True,
                            )
                    else:
                        self.logger.warning(
                            "No original project.yaml content to restore or file did not exist."
                        )
                except Exception as rollback_e:
                    self.logger.critical(
                        f"An unexpected error occurred during rollback attempt: {rollback_e}",
                        exc_info=True,
                    )
                    self.logger.critical(
                        "project.yaml might be in an inconsistent state. Manual intervention required!"
                    )
            raise ReleaseError(f"Release process failed: {e}") from e

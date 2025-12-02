import os
import sys
import glob
import yaml
import hashlib
import datetime
import re
from jsonschema import validate, ValidationError as JsonSchemaValidationError # Alias for clarity
import base64
import semver
import tempfile
import logging # Import logging
from pathlib import Path # Import Path

from releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    VersionMismatchError,
    ValidationFailureError,
    SigningError,
    ReleaseError,
    VaultServiceError # Import VaultServiceError
)

# --- Helper Functions (can be considered a utility module) ---

def load_yaml(path: Path):
    """Loads a YAML file."""
    try:
        # Path objects can be passed directly to open()
        with open(path, 'r') as f:
            return yaml.safe_load(f)
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
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=path.parent, encoding='utf-8') as tmp_file:
            tmp_name = tmp_file.name
            yaml.dump(data, tmp_file, sort_keys=False, indent=2)
        
        # Atomically replace the original file with the temporary file
        os.replace(tmp_name, path) # os.replace still expects string paths
    except IOError as e:
        raise ReleaseError(f"Failed to write YAML file to {path}: {e}") from e
    except Exception as e:
        # Clean up temp file if something went wrong before os.replace
        if tmp_name and Path(tmp_name).exists(): # Use Path.exists()
            Path(tmp_name).unlink() # Use Path.unlink() for removal
        raise ReleaseError(f"An unexpected error occurred during atomic write to {path}: {e}") from e


def get_reproducible_repo_hash(git_service, tree_id):
    """
    Calculates a reproducible SHA256 hash of a given git tree object
    by hashing the deterministic tar archive provided by 'git archive'.
    This version is now pure Python for hashing, removing the openssl dependency.
    """
    try:
        # Get the raw tar archive from the GitService
        archive_bytes = git_service.archive_tree_bytes(tree_id)
        
        # The most straightforward and dependency-free way to hash in Python
        hasher = hashlib.sha256()
        hasher.update(archive_bytes)
        digest = hasher.digest()
        
        return base64.b64encode(digest).decode('utf-8')
        
    except Exception as e:
        # Wrap any unexpected error in our custom exception
        raise ReleaseError(f"Error during repo hash calculation: {e}") from e

# --- Core Logic Class ---

class ReleaseManager:
    def __init__(self, config, git_service, vault_service, project_root: Path = Path('.'), dry_run=False, logger=None):
        self.config = config
        self.git_service = git_service
        self.vault_service = vault_service
        self.project_root = project_root.resolve() # Store as resolved Path object
        self.dry_run = dry_run
        self.logger = logger if logger else logging.getLogger(__name__) # Use provided logger or create a new one
        self.release_version = None
        self.component_name = None

        # Validate essential configuration keys
        required_config_keys = ['component_name', 'meta_schema_file', 'meta_schemas_dir']
        for key in required_config_keys:
            if key not in self.config:
                raise ConfigurationError(f"Missing required configuration key '{key}' in compiler_settings of project.yaml.")

    def _path(self, relative_path):
        # Return a Path object
        return self.project_root / relative_path

    def run_validation(self):
        """Runs offline validation on all schemas."""
        try:
            meta_schema_path = self._path(self.config['meta_schema_file'])
            meta_schema = load_yaml(meta_schema_path)
        except (KeyError, ConfigurationError) as e:
            raise ConfigurationError(f"Could not load meta-schema: {e}") from e

        # Use Path.glob for more Pythonic globbing
        schema_glob_pattern = self.config['meta_schemas_dir'] + '/**/*.meta.yaml'
        schema_files = list(self.project_root.glob(schema_glob_pattern))
        
        # Filter out the meta-schema itself
        meta_schema_abs_path = meta_schema_path.resolve() # Resolve to absolute path for comparison
        schema_files = [f for f in schema_files if f.resolve() != meta_schema_abs_path]
        
        errors = []
        for schema_file in schema_files:
            try:
                schema_instance = load_yaml(schema_file)
                validate(instance=schema_instance, schema=meta_schema)
            except ConfigurationError as e: # Catch YAML/IO errors during schema loading
                errors.append(f"  - {schema_file.name}: Configuration Error - {e}")
            except JsonSchemaValidationError as e: # Catch actual JSON Schema validation errors
                errors.append(f"  - {schema_file.name}: Schema Validation Error - {e.message}")
            except Exception as e: # Catch any other unexpected errors
                errors.append(f"  - {schema_file.name}: Unexpected Error - {e}")

        if errors:
            error_str = "\n".join(errors)
            raise ValidationFailureError(f"One or more schemas failed validation:\n{error_str}")

    def _validate_release_prerequisites(self):
        """Internal method to check git state, branch, and version."""
        try:
            component_name = self.config['component_name']
        except KeyError as e:
            # This should ideally be caught by the constructor's config validation
            raise ConfigurationError("Missing 'component_name' in compiler_settings of project.yaml. This is required for release.") from e
            
        # Check for uncommitted changes in working directory
        git_status_wd = self.git_service.get_status_porcelain()
        if git_status_wd:
            raise GitStateError("Uncommitted changes detected in working directory. Please commit or stash them before releasing.")

        # Check for staged changes (index is not empty)
        # git diff-index --quiet HEAD -- (returns 1 if there are differences, 0 if clean)
        try:
            self.git_service.run(['git', 'diff-index', '--quiet', 'HEAD', '--'])
        except GitStateError as e: # git diff-index --quiet returns 1 if index is not clean
            raise GitStateError(f"Staged changes detected in Git index. Please commit them before releasing. (Details: {e})")

        current_branch = self.git_service.get_current_branch()
        release_branch_pattern = re.compile(rf"^{re.escape(component_name)}releases/v(\d+\.\d+\.\d+)$")
        match = release_branch_pattern.match(current_branch)
        if not match:
            raise GitStateError(f"Not on a valid release branch for component '{component_name}'. Expected format: '{component_name}releases/vX.Y.Z', found: '{current_branch}'")

        new_version_str = match.group(1)
        try:
            new_version = semver.Version.parse(new_version_str)
        except ValueError as e:
            raise VersionMismatchError(f"Invalid version string '{new_version_str}' parsed from branch name: {e}") from e

        tag_pattern = f"{component_name}@v*.*.*"
        existing_tags = self.git_service.get_tags(pattern=tag_pattern)

        if existing_tags:
            try:
                existing_versions = sorted([semver.Version.parse(tag.split('@v')[-1]) for tag in existing_tags])
            except ValueError as e:
                raise VersionMismatchError(f"Could not parse existing tag versions: {e}") from e
            
            latest_version = existing_versions[-1]
            is_valid_next = (
                new_version == latest_version.next_patch() or
                new_version == latest_version.next_minor() or
                new_version == latest_version.next_major()
            )
            if not is_valid_next:
                raise VersionMismatchError(f"Version '{new_version_str}' is not a valid increment. Latest is '{latest_version}'.")
        
        self.release_version = new_version_str
        self.component_name = component_name
        return new_version_str, component_name

    def run_release_check(self):
        """Performs all pre-flight checks for a release."""
        version, component = self._validate_release_prerequisites()
        return version, component

    def run_release_close(self):
        """
        Executes the final steps of a release:
        1. Creates a preliminary release block.
        2. Writes it to project.yaml.
        3. Stages project.yaml and gets a tree_id that includes the preliminary block.
        4. Signs the tree_id.
        5. Creates the final release block with signing metadata.
        6. Writes the final release block to project.yaml.
        """
        if not self.release_version or not self.component_name:
            raise ReleaseError("run_release_check() must be successfully run before closing the release.")
        
        if not self.vault_service:
            raise VaultServiceError("VaultService is not initialized. Cannot sign release.")

        project_yaml_path = self._path('project.yaml')
        original_project_config_content = None # To store original content for rollback
        project_yaml_existed_before = project_yaml_path.exists() # Use Path.exists()

        try:
            # Store original content for potential rollback
            if project_yaml_existed_before:
                original_project_config_content = project_yaml_path.read_text() # Use Path.read_text()
            
            # 1. Create preliminary release block (without signature/tree_hash yet)
            preliminary_release_block = {
                "version": self.release_version,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # 2. Write preliminary block to project.yaml (or simulate in dry-run)
            if self.dry_run:
                self.logger.info("[DRY-RUN] Simulating write of preliminary release block to project.yaml.")
                self.logger.debug(yaml.dump({'release': preliminary_release_block}, sort_keys=False, indent=2))
            else:
                full_project_config = load_yaml(project_yaml_path)
                full_project_config['release'] = preliminary_release_block
                write_yaml(project_yaml_path, full_project_config)
                self.git_service.add(str(project_yaml_path)) # git add expects string path

            # 3. Get tree_id that includes the preliminary release block
            tree_id = self.git_service.write_tree()
            digest_b64 = get_reproducible_repo_hash(self.git_service, tree_id)
            
            # 4. Sign the digest of the repository state.
            key_name = self.config.get('vault_key_name', 'cic-my-sign-key')
            signature = self.vault_service.sign(digest_b64, key_name)

            # 5. Build the complete, final release block in memory.
            final_release_block = preliminary_release_block.copy()
            final_release_block['repository_tree_hash'] = tree_id
            final_release_block['signing_metadata'] = {
                'key': key_name,
                'signature': signature,
                'hash_algorithm': 'sha256',
                'digest': digest_b64
            }

            # 6. Write the final release block to project.yaml (or simulate in dry-run)
            if self.dry_run:
                self.logger.info("[DRY-RUN] Skipping final write to project.yaml.")
                self.logger.debug(yaml.dump({'release': final_release_block}, sort_keys=False, indent=2))
            else:
                full_project_config = load_yaml(project_yaml_path) # Reload to ensure we have the latest state
                full_project_config['release'] = final_release_block
                write_yaml(project_yaml_path, full_project_config)
                # Note: We do NOT git add project.yaml again here. The tree_id was calculated
                # based on the state *after* the preliminary write and add. The final write
                # is just to update the file with the signature. The user will commit this.
            
            return self.release_version, self.component_name
        except Exception as e:
            # Rollback project.yaml if an error occurred after initial write
            if not self.dry_run:
                self.logger.error(f"Release failed, attempting to rollback project.yaml...", exc_info=True)
                try:
                    if original_project_config_content is not None:
                        # Use write_yaml for atomic rollback
                        write_yaml(project_yaml_path, yaml.safe_load(original_project_config_content))
                        self.git_service.add(str(project_yaml_path)) # Stage the restored file
                        self.logger.info("✓ project.yaml restored to original state.")
                    elif not project_yaml_existed_before and project_yaml_path.exists(): # Use Path.exists()
                        project_yaml_path.unlink() # Use Path.unlink() for removal
                        self.logger.info("✓ Newly created project.yaml removed.")
                    else:
                        self.logger.warning("No original project.yaml content to restore or file did not exist.")
                except Exception as rollback_e:
                    self.logger.critical(f"Failed to rollback project.yaml: {rollback_e}", exc_info=True)
                    self.logger.critical("project.yaml might be in an inconsistent state. Manual intervention required!")
            raise ReleaseError(f"Release process failed: {e}") from e

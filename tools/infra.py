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

def load_yaml(path):
    """Loads a YAML file."""
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ConfigurationError(f"Configuration file not found at: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML syntax error in {path}: {e}") from e


def write_yaml(path, data):
    """
    Writes data to a YAML file atomically using a temporary file.
    This prevents data corruption if the write operation is interrupted.
    """
    tmp_name = None
    try:
        # Create a temporary file in the same directory as the target file
        # This ensures that os.replace works across filesystems
        with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(path), encoding='utf-8') as tmp_file:
            tmp_name = tmp_file.name
            yaml.dump(data, tmp_file, sort_keys=False, indent=2)
        
        # Atomically replace the original file with the temporary file
        os.replace(tmp_name, path)
    except IOError as e:
        raise ReleaseError(f"Failed to write YAML file to {path}: {e}") from e
    except Exception as e:
        # Clean up temp file if something went wrong before os.replace
        if tmp_name and os.path.exists(tmp_name):
            os.remove(tmp_name)
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
    def __init__(self, config, git_service, vault_service, project_root='.', dry_run=False):
        self.config = config
        self.git_service = git_service
        self.vault_service = vault_service
        self.project_root = os.path.abspath(project_root)
        self.dry_run = dry_run
        self.release_version = None
        self.component_name = None

    def _path(self, relative_path):
        return os.path.join(self.project_root, relative_path)

    def run_validation(self):
        """Runs offline validation on all schemas."""
        try:
            meta_schema_path = self._path(self.config['meta_schema_file'])
            meta_schema = load_yaml(meta_schema_path)
        except (KeyError, ConfigurationError) as e:
            raise ConfigurationError(f"Could not load meta-schema: {e}") from e

        schema_glob_path = self._path(os.path.join(self.config['meta_schemas_dir'], '**', '*.meta.yaml'))
        schema_files = glob.glob(schema_glob_path, recursive=True)
        schema_files = [f for f in schema_files if os.path.abspath(f) != os.path.abspath(meta_schema_path)]
        
        errors = []
        for schema_file in schema_files:
            try:
                schema_instance = load_yaml(schema_file)
                validate(instance=schema_instance, schema=meta_schema)
            except ConfigurationError as e: # Catch YAML/IO errors during schema loading
                errors.append(f"  - {os.path.basename(schema_file)}: Configuration Error - {e}")
            except JsonSchemaValidationError as e: # Catch actual JSON Schema validation errors
                errors.append(f"  - {os.path.basename(schema_file)}: Schema Validation Error - {e.message}")
            except Exception as e: # Catch any other unexpected errors
                errors.append(f"  - {os.path.basename(schema_file)}: Unexpected Error - {e}")

        if errors:
            error_str = "\n".join(errors)
            raise ValidationFailureError(f"One or more schemas failed validation:\n{error_str}")

    def _validate_release_prerequisites(self):
        """Internal method to check git state, branch, and version."""
        try:
            component_name = self.config['component_name']
        except KeyError as e:
            raise ConfigurationError("Missing 'component_name' in compiler_settings of project.yaml. This is required for release.") from e
            
        git_status = self.git_service.get_status_porcelain()
        if git_status:
            raise GitStateError("Uncommitted changes detected. Please commit or stash them before releasing.")

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
            # Semver library's next_minor() and next_major() already handle setting patch/minor to 0.
            # No need for explicit checks like new_version.patch == 0.
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
        project_yaml_existed_before = os.path.exists(project_yaml_path)

        try:
            # Store original content for potential rollback
            if project_yaml_existed_before:
                with open(project_yaml_path, 'r') as f:
                    original_project_config_content = f.read()
            
            # 1. Create preliminary release block (without signature/tree_hash yet)
            preliminary_release_block = {
                "version": self.release_version,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # 2. Write preliminary block to project.yaml (or simulate in dry-run)
            if self.dry_run:
                print("[96m[DRY-RUN] Simulating write of preliminary release block to project.yaml.[0m")
                print(yaml.dump({'release': preliminary_release_block}, sort_keys=False, indent=2))
            else:
                full_project_config = load_yaml(project_yaml_path)
                full_project_config['release'] = preliminary_release_block
                write_yaml(project_yaml_path, full_project_config)
                self.git_service.add(project_yaml_path) # Stage the modified project.yaml

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
                print("[96m[DRY-RUN] Skipping final write to project.yaml.[0m")
                print("[96m[DRY-RUN] Final release block would be:[0m")
                print(yaml.dump({'release': final_release_block}, sort_keys=False, indent=2))
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
                print(f"[91m[ERROR] Release failed, attempting to rollback project.yaml...[0m")
                try:
                    if original_project_config_content is not None:
                        write_yaml(project_yaml_path, yaml.safe_load(original_project_config_content))
                        self.git_service.add(project_yaml_path) # Stage the restored file
                        print(f"[92m✓ project.yaml restored to original state.[0m")
                    elif not project_yaml_existed_before and os.path.exists(project_yaml_path):
                        os.remove(project_yaml_path)
                        print(f"[92m✓ Newly created project.yaml removed.[0m")
                    else:
                        print(f"[93m[WARNING] No original project.yaml content to restore or file did not exist.[0m")
                except Exception as rollback_e:
                    print(f"[91m[CRITICAL ERROR] Failed to rollback project.yaml: {rollback_e}[0m")
                    print(f"[91m[CRITICAL ERROR] project.yaml might be in an inconsistent state. Manual intervention required![0m")
            raise ReleaseError(f"Release process failed: {e}") from e

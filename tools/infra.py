import os
import sys
import glob
import yaml
import json
import hashlib
import requests
import subprocess
import datetime
import re
from jsonschema import validate, ValidationError
import base64
import semver

# --- Helper Functions (can be considered a utility module) ---

def load_yaml(path):
    """Loads a YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def write_yaml(path, data):
    """Writes data to a YAML file."""
    with open(path, 'w') as f:
        yaml.dump(data, f, sort_keys=False, indent=2)

def to_canonical_json(data):
    """Converts a Python object to a canonical (sorted, no whitespace) JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def get_reproducible_repo_hash(tree_id):
    """Calculates a reproducible SHA256 hash of a given git tree object."""
    try:
        archive_proc = subprocess.Popen(['git', 'archive', '--format=tar', tree_id], stdout=subprocess.PIPE)
        digest_proc = subprocess.Popen(['openssl', 'dgst', '-sha256', '-binary'], stdin=archive_proc.stdout, stdout=subprocess.PIPE)
        b64_proc = subprocess.Popen(['openssl', 'base64', '-A'], stdin=digest_proc.stdout, stdout=subprocess.PIPE, text=True)
        archive_proc.stdout.close()
        repo_hash_b64 = b64_proc.communicate()[0].strip()
        if b64_proc.returncode != 0:
            raise RuntimeError("Failed to calculate reproducible repository hash.")
        return repo_hash_b64
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise RuntimeError(f"Error during repo hash calculation: {e}")

def run_git_command(command):
    """Runs a Git command and returns its output, raising an error on failure."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Git command failed: {' '.join(command)}\n{e.stderr}")

def sign_with_vault(digest_b64, key_name, vault_addr, vault_token, vault_cacert):
    """Signs a pre-hashed, base64-encoded digest using Vault's Transit Engine."""
    if not vault_addr or not vault_token:
        raise ValueError("VAULT_ADDR and VAULT_TOKEN must be provided for signing.")

    verify_tls = vault_cacert if vault_cacert and os.path.exists(vault_cacert) else False

    try:
        response = requests.post(
            f"{vault_addr}/v1/transit/sign/{key_name}",
            headers={"X-Vault-Token": vault_token},
            json={"input": digest_b64, "prehashed": True, "hash_algorithm": "sha2-256"},
            verify=verify_tls,
            timeout=10,
        )
        response.raise_for_status()
        signature = response.json()["data"]["signature"]
        return signature
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Vault signing failed: {e}")
    except (KeyError, TypeError) as e:
        raise RuntimeError(f"Could not parse signature from Vault response: {response.text}")


# --- Core Logic Class ---

class ReleaseManager:
    def __init__(self, config, project_root='.'):
        self.config = config
        self.project_root = os.path.abspath(project_root)
        self.release_version = None
        self.component_name = None

    def _path(self, relative_path):
        return os.path.join(self.project_root, relative_path)

    def run_validation(self):
        """Runs offline validation on all schemas."""
        try:
            meta_schema_path = self._path(self.config['meta_schema_file'])
            meta_schema = load_yaml(meta_schema_path)
        except Exception as e:
            raise IOError(f"Could not load meta-schema '{self.config['meta_schema_file']}': {e}")

        schema_glob_path = self._path(os.path.join(self.config['meta_schemas_dir'], '**', '*.meta.yaml'))
        schema_files = glob.glob(schema_glob_path, recursive=True)
        schema_files = [f for f in schema_files if os.path.abspath(f) != os.path.abspath(meta_schema_path)]
        
        errors = []
        for schema_file in schema_files:
            try:
                schema_instance = load_yaml(schema_file)
                validate(instance=schema_instance, schema=meta_schema)
            except Exception as e:
                errors.append(f"  - {os.path.basename(schema_file)}: {e}")

        if errors:
            error_str = "\n".join(errors)
            raise ValidationError(f"One or more schemas failed validation:\n{error_str}")

    def _validate_release_prerequisites(self):
        """Internal method to check git state, branch, and version."""
        project_config = load_yaml(self._path('project.yaml'))['project']
        raw_component_name = project_config.get('main_branch', 'main')
        component_name = re.sub(r'main$', '', raw_component_name)

        git_status = run_git_command(['git', 'status', '--porcelain'])
        if git_status:
            raise RuntimeError("Uncommitted changes detected. Please commit or stash them before releasing.")

        current_branch = run_git_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
        release_branch_pattern = re.compile(rf"^{re.escape(component_name)}releases/v(\d+\.\d+\.\d+)$")
        match = release_branch_pattern.match(current_branch)
        if not match:
            raise ValueError(f"Not on a valid release branch. Expected format: '{component_name}releases/vX.Y.Z', found: '{current_branch}'")

        new_version_str = match.group(1)
        new_version = semver.Version.parse(new_version_str)

        tag_pattern = f"{component_name}@v*.*.*"
        git_tags_raw = run_git_command(['git', 'tag', '--list', tag_pattern])
        existing_tags = git_tags_raw.split('\n') if git_tags_raw else []

        if existing_tags:
            existing_versions = sorted([semver.Version.parse(tag.split('@v')[-1]) for tag in existing_tags])
            latest_version = existing_versions[-1]
            is_valid_next = (
                new_version == latest_version.next_patch() or
                (new_version == latest_version.next_minor() and new_version.patch == 0) or
                (new_version == latest_version.next_major() and new_version.minor == 0 and new_version.patch == 0)
            )
            if not is_valid_next:
                raise ValueError(f"Version '{new_version_str}' is not a valid increment. Latest is '{latest_version}'.")
        
        self.release_version = new_version_str
        self.component_name = component_name
        return new_version_str, component_name

    def run_release_check(self):
        """Performs all pre-flight checks for a release."""
        version, component = self._validate_release_prerequisites()
        if not os.getenv('VAULT_ADDR') or not os.getenv('VAULT_TOKEN'):
            raise EnvironmentError("VAULT_ADDR and VAULT_TOKEN environment variables must be set.")
        return version, component

    def run_release_close(self):
        """Executes the final steps of a release."""
        if not self.release_version or not self.component_name:
            raise RuntimeError("run_release_check() must be successfully run before closing the release.")

        project_yaml_path = self._path('project.yaml')
        full_project_config = load_yaml(project_yaml_path)
        if 'release' in full_project_config:
            del full_project_config['release']
        
        release_block = {
            "version": self.release_version,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        full_project_config['release'] = release_block
        write_yaml(project_yaml_path, full_project_config)

        run_git_command(['git', 'add', project_yaml_path])
        tree_id = run_git_command(['git', 'write-tree'])
        digest_b64 = get_reproducible_repo_hash(tree_id)

        key_name = self.config.get('vault_key_name', 'cic-my-sign-key')
        signature = sign_with_vault(
            digest_b64, 
            key_name,
            os.getenv('VAULT_ADDR'),
            os.getenv('VAULT_TOKEN'),
            os.getenv('VAULT_CACERT')
        )

        final_release_block = release_block.copy()
        final_release_block['repository_tree_hash'] = tree_id
        final_release_block['signing_metadata'] = {
            'key': key_name,
            'signature': signature,
            'hash_algorithm': 'sha256',
            'digest': digest_b64
        }
        
        full_project_config['release'] = final_release_block
        write_yaml(project_yaml_path, full_project_config)
        
        return self.release_version, self.component_name

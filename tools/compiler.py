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
from jsonschema import validate
import base64
import semver

# --- Configuration Loader ---

def load_project_config(full_config=False):
    """Loads the main project.yaml configuration file."""
    try:
        with open('project.yaml', 'r') as f:
            config = yaml.safe_load(f)
            return config if full_config else config['compiler_settings']
    except (IOError, KeyError, TypeError) as e:
        print(f"[FATAL] Could not load or parse compiler settings from project.yaml: {e}")
        sys.exit(1)

CONFIG = load_project_config()

# --- Helper Functions ---


def load_yaml(path):
    """Loads a YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def write_yaml(path, data):
    """Writes data to a YAML file."""
    with open(path, 'w') as f:
        yaml.dump(data, f, sort_keys=False, indent=2)


def to_canonical_json(data):
    """Converts a Python object to a canonical (sorted, no whitespace)
    JSON string."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode(
        'utf-8')


def get_sha256_hex(data_bytes):
    """Calculates the SHA256 hash and returns it as a hex digest."""
    return hashlib.sha256(data_bytes).hexdigest()


def get_sha256_b64(data_bytes):
    """Calculates the SHA256 hash and returns it as a base64 encoded string."""
    return base64.b64encode(hashlib.sha256(data_bytes).digest()).decode('utf-8')


def get_reproducible_repo_hash(tree_id):
    """
    Calculates a reproducible SHA256 hash of a given git tree object.
    It creates a normalized tar archive in memory and hashes its content,
    ensuring the hash is independent of file metadata like permissions or
    timestamps. The result is base64 encoded.
    """
    # Create a tar archive from the tree object
    archive_proc = subprocess.Popen(
        ['git', 'archive', '--format=tar', tree_id],
        stdout=subprocess.PIPE
    )
    # Hash the tar stream
    digest_proc = subprocess.Popen(
        ['openssl', 'dgst', '-sha256', '-binary'],
        stdin=archive_proc.stdout,
        stdout=subprocess.PIPE
    )
    # Base64 encode the hash
    b64_proc = subprocess.Popen(
        ['openssl', 'base64', '-A'],
        stdin=digest_proc.stdout,
        stdout=subprocess.PIPE,
        text=True
    )
    archive_proc.stdout.close()  # Allow archive_proc to receive a SIGPIPE
    
    repo_hash_b64 = b64_proc.communicate()[0].strip()
    
    if b64_proc.returncode != 0:
        print(f"[91m✗ ERROR: Failed to calculate reproducible repository hash.[0m")
        sys.exit(1)
        
    return repo_hash_b64


def run_git_command(command):
    """Runs a Git command and returns its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[91m✗ ERROR: Git command failed: {' '.join(command)}[0m")
        print(e.stderr)
        sys.exit(1)


def validate_release_prerequisites():
    """
    Ensures that all conditions for a release are met:
    1. Clean git state.
    2. Correct release branch name format.
    3. New version is the next logical increment (no gaps).
    """
    print("--- Validating Release Prerequisites ---")
    project_config = load_project_config(full_config=True)['project']
    component_name = project_config.get('main_branch', 'main')

    # 1. Check for clean git state
    git_status = run_git_command(['git', 'status', '--porcelain'])
    if git_status:
        print("[91m✗ ERROR: Uncommitted changes detected. Please commit or stash them before releasing.[0m")
        sys.exit(1)
    print("  [92m✓ Git working directory is clean.[0m")

    # 2. Validate branch name and extract version
    current_branch = run_git_command(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    release_branch_pattern = re.compile(rf"^{re.escape(component_name)}/releases/v(\d+\.\d+\.\d+)$")
    match = release_branch_pattern.match(current_branch)

    if not match:
        print(f"[91m✗ ERROR: You are not on a valid release branch for the '{component_name}' component.[0m")
        print(f"  Expected format: '{component_name}/releases/vX.Y.Z'")
        print(f"  Current branch: '{current_branch}'")
        sys.exit(1)

    new_version_str = match.group(1)
    new_version = semver.Version.parse(new_version_str)
    print(f"  [92m✓ Valid release branch found: {current_branch} (Version: {new_version_str})[0m")

    # 3. Check for strict +1 version increment (no gaps)
    tag_pattern = f"{component_name}@v*.*.*"
    git_tags_raw = run_git_command(['git', 'tag', '--list', tag_pattern])
    existing_tags = git_tags_raw.split('\n') if git_tags_raw else []

    if not existing_tags:
        if new_version.major != 0 or new_version.minor != 0 or new_version.patch != 0:
             # Allowing 0.0.0 or 0.1.0 or 1.0.0 as first release
            pass
        print("  [92m✓ No previous tags found. Proceeding with first release.[0m")
    else:
        existing_versions = sorted([semver.Version.parse(tag.split('@v')[-1]) for tag in existing_tags])
        latest_version = existing_versions[-1]

        is_valid_next = False
        # Valid next patch? (e.g., 1.2.5 -> 1.2.6)
        if new_version == latest_version.next_patch():
            is_valid_next = True
        # Valid next minor? (e.g., 1.2.5 -> 1.3.0)
        elif new_version == latest_version.next_minor() and new_version.patch == 0:
            is_valid_next = True
        # Valid next major? (e.g., 1.2.5 -> 2.0.0)
        elif new_version == latest_version.next_major() and new_version.minor == 0 and new_version.patch == 0:
            is_valid_next = True

        if not is_valid_next:
            print(f"[91m✗ ERROR: Version '{new_version_str}' is not a valid next increment.[0m")
            print(f"  The latest version is '{latest_version}'. Allowed next versions are:")
            print(f"  - Patch: '{latest_version.next_patch()}'")
            print(f"  - Minor: '{latest_version.next_minor()}'")
            print(f"  - Major: '{latest_version.next_major()}'")
            sys.exit(1)

    print(f"  [92m✓ New version '{new_version_str}' is a valid increment.[0m")


    return new_version_str, component_name


def run_validation():
    """Runs offline validation on all schemas."""
    print("--- Running Schema Validation ---")
    try:
        meta_schema = load_yaml(CONFIG['meta_schema_file'])
        print(f"Meta-schema loaded from {CONFIG['meta_schema_file']}")
    except Exception as e:
        print(f"[FATAL] Could not load meta-schema: {e}")
        sys.exit(1)

    schema_files = glob.glob(os.path.join(CONFIG['schemas_dir'], '*.yaml'))
    # Exclude the meta-schema itself from validation
    schema_files = [f for f in schema_files if f != CONFIG.get('meta_schema_file')]
    
    all_valid = True
    for schema_file in schema_files:
        print(f"  Validating {schema_file}...")
        try:
            schema_instance = load_yaml(schema_file)
            validate(instance=schema_instance, schema=meta_schema)
            print("  [92m✓ OK[0m")
        except Exception as e:
            print(f"  [91m✗ ERROR: {e}[0m")
            all_valid = False

    if not all_valid:
        print("\nValidation failed for one or more schemas.")
        sys.exit(1)
    else:
        print("\nAll schemas are valid.")


def run_release():
    """Runs the full release process: validation, checksum, signing."""
    print("--- Running Schema Release ---")
    # First, run all prerequisite checks
    release_version, component_name = validate_release_prerequisites()

    vault_addr = os.getenv('VAULT_ADDR')
    vault_token = os.getenv('VAULT_TOKEN')
    vault_cacert = os.getenv('VAULT_CACERT')  # For production TLS verification

    if not vault_addr or not vault_token:
        print("[FATAL] VAULT_ADDR and VAULT_TOKEN must be set for release.")
        sys.exit(1)

    # Set TLS verification for Vault connection
    if vault_cacert:
        verify_tls = vault_cacert
        print(f"[INFO] Using CA cert for Vault TLS verification:"
              f" {vault_cacert}")
    else:
        verify_tls = False
        print("[93m[WARNING] Vault TLS verification is disabled. "
              "Do not use in production.[0m")

    meta_schema = load_yaml(CONFIG['meta_schema_file'])
    schema_files = glob.glob(os.path.join(CONFIG['schemas_dir'], '*.yaml'))
    # Exclude the meta-schema itself from release
    schema_files = [f for f in schema_files if f != CONFIG.get('meta_schema_file')]

    if not os.path.exists(CONFIG['source_dir']):
        os.makedirs(CONFIG['source_dir'])
    
    release_count = 0
    for schema_file in schema_files:
        schema_data = load_yaml(schema_file)
        version = schema_data.get('metadata', {}).get('version', 'dev')
        if version == 'dev':
            print(f"  - Skipping dev schema: {schema_file}")
            continue

        release_count += 1
        print(f"\nProcessing schema: {schema_file}")

        # 1. Validate against meta-schema
        try:
            validate(instance=schema_data, schema=meta_schema)
            print("  - Schema is valid against meta-schema.")
        except Exception as e:
            print(f"  [91m✗ ERROR: Schema validation failed: {e}[0m")
            sys.exit(1)

        # 2. Prepare metadata for signing
        metadata_for_signing = schema_data.get('metadata', {}).copy()
        metadata_for_signing['build_timestamp'] = datetime.datetime.now(
            datetime.timezone.utc).isoformat()

        # 3. Calculate checksum from the 'spec' block
        spec_block = schema_data.get('spec', {})
        checksum = get_sha256_b64(to_canonical_json(spec_block))
        print(f"  - Calculated spec checksum: {checksum[:12]}...")

        # 4. Get signature from Vault
        digest_bytes = hashlib.sha256(to_canonical_json(
            metadata_for_signing)).digest()
        digest_to_sign_b64 = base64.b64encode(digest_bytes).decode('utf-8')

        print("  - Requesting signature from Vault...")
        try:
            vault_response = requests.post(
                f"{vault_addr}/v1/transit/sign/{CONFIG['vault_key_name']}",
                headers={"X-Vault-Token": vault_token},
                json={
                    "input": digest_to_sign_b64,
                    "prehashed": True,
                    "hash_algorithm": "sha2-256",
                },
                verify=verify_tls
            )
            vault_response.raise_for_status()
            signature = vault_response.json()['data']['signature']
            print("  - Signature received successfully.")
        except requests.exceptions.RequestException as e:
            print(f"  [91m✗ ERROR: Vault signing failed: {e}[0m")
            sys.exit(1)

        # 5. Assemble the final signed schema
        final_schema = schema_data.copy()
        final_schema['metadata']['checksum'] = checksum
        final_schema['metadata']['sign'] = signature
        final_schema['metadata']['build_timestamp'] = \
            metadata_for_signing['build_timestamp']

        # 6. Final validation of the completed schema
        try:
            validate(instance=final_schema, schema=meta_schema)
        except Exception as e:
            print(f"  [91m✗ ERROR: Final validation failed: {e}[0m")
            sys.exit(1)

        # 7. Write to source directory
        output_path = os.path.join(CONFIG['source_dir'], os.path.basename(schema_file))
        write_yaml(output_path, final_schema)
        print(f"  - Signed schema written to {output_path}")

    if release_count == 0:
        print("\nNo non-dev schemas found to release.")
    else:
        print(f"\nSuccessfully processed {release_count} schemas into '{CONFIG['source_dir']}'.")

    print("\n--- Finalizing Release Manifest (project.yaml) ---")

    # 1. Prepare project.yaml with version and timestamp
    full_project_config = load_project_config(full_config=True)
    if 'release' in full_project_config:
        del full_project_config['release'] # Clean previous release block
    
    release_block_for_hashing = {
        "version": release_version,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    full_project_config['release'] = release_block_for_hashing
    write_yaml('project.yaml', full_project_config)
    print("  - Updated project.yaml with version and timestamp.")

    # 2. Stage all changes and get the repository tree hash
    print("  - Staging all changes to calculate repository state...")
    run_git_command(['git', 'add', '.'])
    tree_id = run_git_command(['git', 'write-tree'])
    print(f"  - Staged content tree ID: {tree_id[:12]}...")
    repo_hash = get_reproducible_repo_hash(tree_id)
    print(f"  - Calculated reproducible repository hash: {repo_hash[:12]}...")

    # 3. Prepare the final release block for signing
    release_block_for_signing = release_block_for_hashing.copy()
    release_block_for_signing['repository_tree_hash'] = repo_hash

    # 4. Get signature from Vault for the release block
    digest_bytes = hashlib.sha256(to_canonical_json(
        release_block_for_signing)).digest()
    digest_to_sign_b64 = base64.b64encode(digest_bytes).decode('utf-8')

    print("  - Requesting signature for release manifest from Vault...")
    try:
        response = requests.post(
            f"{vault_addr}/v1/transit/sign/{CONFIG['vault_key_name']}",
            headers={"X-Vault-Token": vault_token},
            json={
                "input": digest_to_sign_b64,
                "prehashed": True,
                "hash_algorithm": "sha2-256"
            },
            verify=verify_tls
        )
        response.raise_for_status()
        release_signature = response.json()['data']['signature']
        print("  - Manifest signature received successfully.")
    except requests.exceptions.RequestException as e:
        print(f"  [91m✗ ERROR: Vault signing for manifest failed: {e}[0m")
        # Unstage changes to leave a clean state
        run_git_command(['git', 'reset'])
        sys.exit(1)

    # 5. Write the final, signed release block to project.yaml
    final_release_block = release_block_for_signing.copy()
    final_release_block['sign'] = release_signature
    full_project_config['release'] = final_release_block

    write_yaml('project.yaml', full_project_config)
    print("  - [92m✓ project.yaml has been finalized with the release signature.[0m")
    print(f"  - [93mACTION REQUIRED: Please commit the changes and create the tag: git tag {component_name}@v{release_version}[0m")

def main():
    """Main entrypoint for the script."""
    if len(sys.argv) < 2:
        print("Usage: python tools/compiler.py [validate|release]")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'validate':
        run_validation()
    elif command == 'release':
        run_release()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

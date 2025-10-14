import os
import sys
import glob
import yaml
import json
import hashlib
import requests
import datetime
from jsonschema import validate
import base64


# --- Configuration ---
SCHEMAS_DIR = 'schemas'
SOURCE_DIR = 'source'
META_SCHEMA_FILE = os.path.join(SCHEMAS_DIR, 'index.yaml')
VAULT_KEY_NAME = "cic-my-sign-key"  # Default key name for signing


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


# --- Core Logic ---


def run_validation():
    """Runs offline validation on all schemas."""
    print("--- Running Schema Validation ---")
    try:
        meta_schema = load_yaml(META_SCHEMA_FILE)
        print(f"Meta-schema loaded from {META_SCHEMA_FILE}")
    except Exception as e:
        print(f"[FATAL] Could not load meta-schema: {e}")
        sys.exit(1)

    schema_files = glob.glob(os.path.join(SCHEMAS_DIR, '*.yaml'))
    if META_SCHEMA_FILE in schema_files:
        schema_files.remove(META_SCHEMA_FILE)

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

    meta_schema = load_yaml(META_SCHEMA_FILE)
    schema_files = glob.glob(os.path.join(SCHEMAS_DIR, '*.yaml'))
    if META_SCHEMA_FILE in schema_files:
        schema_files.remove(META_SCHEMA_FILE)

    if not os.path.exists(SOURCE_DIR):
        os.makedirs(SOURCE_DIR)

    release_count = 0
    for schema_file in schema_files:
        schema_data = load_yaml(schema_file)
        version = schema_data.get('metadata', {}).get('version', '')

        if version.endswith('.dev'):
            continue

        release_count += 1
        print(f"\nProcessing release for {schema_file} (version {version})...")

        # 1. Calculate checksum of the 'spec' block
        spec_bytes = to_canonical_json(schema_data['spec'])
        checksum = get_sha256_hex(spec_bytes)
        print(f"  - Calculated spec checksum: {checksum[:12]}...")

        # 2. Prepare metadata for signing
        metadata_for_signing = schema_data['metadata'].copy()
        metadata_for_signing.pop('checksum', None)
        metadata_for_signing.pop('sign', None)
        metadata_for_signing['build_timestamp'] = datetime.datetime.now(
            datetime.timezone.utc).isoformat()
        metadata_for_signing['checksum'] = checksum

        # 3. Get signature from Vault
        digest_bytes = hashlib.sha256(to_canonical_json(
            metadata_for_signing)).digest()
        digest_to_sign_b64 = base64.b64encode(digest_bytes).decode('utf-8')

        print("  - Requesting signature from Vault...")
        try:
            response = requests.post(
                f"{vault_addr}/v1/transit/sign/{VAULT_KEY_NAME}",
                headers={"X-Vault-Token": vault_token},
                json={
                    "input": digest_to_sign_b64,
                    "prehashed": True,
                    "hash_algorithm": "sha2-256"
                },
                verify=verify_tls
            )
            response.raise_for_status()
            signature = response.json()['data']['signature']
            print("  - Signature received successfully.")
        except requests.exceptions.RequestException as e:
            print(f"  [91m✗ ERROR: Vault signing failed: {e}[0m")
            sys.exit(1)

        # 4. Assemble final schema
        final_schema = schema_data.copy()
        final_schema['metadata']['checksum'] = checksum
        final_schema['metadata']['sign'] = signature
        final_schema['metadata']['build_timestamp'] = \
            metadata_for_signing['build_timestamp']

        # 5. Final validation of the completed schema
        print("  - Performing final validation on signed schema...")
        try:
            validate(instance=final_schema, schema=meta_schema)
            print("  - [92m✓ Final validation passed.[0m")
        except Exception as e:
            print(f"  [91m✗ ERROR: Final validation failed: {e}[0m")
            sys.exit(1)

        # 6. Write to source directory
        output_path = os.path.join(SOURCE_DIR, os.path.basename(schema_file))
        write_yaml(output_path, final_schema)
        print(f"  - Signed schema written to {output_path}")

    if release_count == 0:
        print("\nNo non-dev schemas found to release.")
    else:
        print(f"\nSuccessfully processed {release_count} schemas.")


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

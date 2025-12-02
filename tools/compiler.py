import os
import sys
import yaml
import argparse
from infra import ReleaseManager
from releaselib.git_service import GitService
from releaselib.vault_service import VaultService
from releaselib.exceptions import ReleaseError, VaultServiceError

# --- Configuration Loader ---

def load_project_config():
    """
    Loads the main project.yaml configuration file and returns the compiler_settings.
    """
    try:
        with open('project.yaml', 'r') as f:
            return yaml.safe_load(f)['compiler_settings']
    except (IOError, KeyError, TypeError, yaml.YAMLError) as e:
        print(f"[91m[FATAL] Could not load or parse compiler settings from project.yaml: {e}[0m")
        sys.exit(1)

# --- Main Application Logic ---

def main():
    """
    Main entrypoint for the command-line tool.
    This function acts as a "wrapper" around the ReleaseManager class,
    handling user interaction, output, and error handling.
    """
    parser = argparse.ArgumentParser(description="Schema Compiler & Release Tool")
    parser.add_argument("command", choices=['validate', 'release'], help="The command to execute.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a trial run without making any changes.")
    
    args = parser.parse_args()
    
    try:
        if args.dry_run:
            print("[96m--- Starting in DRY-RUN mode. No changes will be made. ---[0m")

        # 1. Load configuration and initialize services
        config = load_project_config()
        git_service = GitService()
        
        vault_service = None
        if args.command == 'release':
            vault_addr = os.getenv('VAULT_ADDR')
            vault_token = os.getenv('VAULT_TOKEN')
            vault_cacert = os.getenv('VAULT_CACERT')

            if not args.dry_run and not vault_cacert:
                print("[93m[WARNING] Vault CA certificate not found. Proceeding without TLS verification.[0m")
            
            vault_service = VaultService(
                vault_addr=vault_addr,
                vault_token=vault_token,
                vault_cacert=vault_cacert,
                dry_run=args.dry_run
            )

        manager = ReleaseManager(
            config, 
            git_service=git_service, 
            vault_service=vault_service,
            dry_run=args.dry_run
        )

        # 2. Execute the requested command
        if args.command == 'validate':
            print("--- Running Schema Validation ---")
            manager.run_validation()
            print("\n[92m✓ All schemas are valid.[0m")

        elif args.command == 'release':
            print("--- Running Schema Release ---")
            
            print("\n[Phase 1/3] Validating schemas...")
            manager.run_validation()
            print("[92m✓ Schemas are valid.[0m")
            
            print("\n[Phase 2/3] Running pre-flight checks...")
            version, _ = manager.run_release_check()
            print(f"[92m✓ All checks passed for version {version}.[0m")
            
            print("\n[Phase 3/3] Closing release...")
            release_version, component_name = manager.run_release_close()

            if args.dry_run:
                print("[96m[DRY-RUN] Release process simulation complete. Vault signing was simulated.[0m")
            else:
                print("[92m✓ Release closed successfully. project.yaml has been finalized.[0m")
                print(f"\n[93mACTION REQUIRED: Please commit the changes and create the tag: git tag {component_name}@v{release_version}[0m")

    except ReleaseError as e:
        print(f"\n[91m[RELEASE FAILED] {e}[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()

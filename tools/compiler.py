import os
import sys
import yaml
from infra import ReleaseManager
from releaselib.git_service import GitService
from releaselib.vault_service import VaultService
from releaselib.exceptions import ReleaseError

# --- Configuration Loader ---

def load_project_config():
    """
    Loads the main project.yaml configuration file and returns the compiler_settings.
    """
    try:
        with open('project.yaml', 'r') as f:
            # We only need the compiler settings for the manager
            return yaml.safe_load(f)['compiler_settings']
    except (IOError, KeyError, TypeError, yaml.YAMLError) as e:
        # Catching more specific errors for better feedback
        print(f"[91m[FATAL] Could not load or parse compiler settings from project.yaml: {e}[0m")
        sys.exit(1)

# --- Main Application Logic ---

def main():
    """
    Main entrypoint for the command-line tool.
    This function acts as a "wrapper" around the ReleaseManager class,
    handling user interaction, output, and error handling.
    """
    if len(sys.argv) < 2:
        print("Usage: python tools/compiler.py [validate|release]")
        sys.exit(1)

    command = sys.argv[1]
    
    try:
        # 1. Load configuration and initialize services and the "engine"
        config = load_project_config()
        git_service = GitService()
        
        vault_service = None
        if command == 'release':
            vault_service = VaultService(
                vault_addr=os.getenv('VAULT_ADDR'),
                vault_token=os.getenv('VAULT_TOKEN'),
                vault_cacert=os.getenv('VAULT_CACERT')
            )

        manager = ReleaseManager(
            config, 
            git_service=git_service, 
            vault_service=vault_service
        )

        # 2. Execute the requested command
        if command == 'validate':
            print("--- Running Schema Validation ---")
            manager.run_validation()
            print("\n[92m✓ All schemas are valid.[0m")

        elif command == 'release':
            print("--- Running Schema Release ---")
            
            print("\n[Phase 1/3] Validating schemas...")
            manager.run_validation()
            print("[92m✓ Schemas are valid.[0m")
            
            print("\n[Phase 2/3] Running pre-flight checks...")
            version, _ = manager.run_release_check()
            print(f"[92m✓ All checks passed for version {version}.[0m")
            
            print("\n[Phase 3/3] Closing release...")
            release_version, component_name = manager.run_release_close()
            print("[92m✓ Release closed successfully. project.yaml has been finalized.[0m")
            print(f"\n[93mACTION REQUIRED: Please commit the changes and create the tag: git tag {component_name}@v{release_version}[0m")

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except ReleaseError as e:
        # 3. Catch our specific, expected exceptions and display them nicely
        print(f"\n[91m[RELEASE FAILED] {e}[0m")
        sys.exit(1)
    # Any other exception will now correctly produce a full stack trace for debugging


if __name__ == "__main__":
    main()

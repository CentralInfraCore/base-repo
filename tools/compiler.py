import os
import sys
import yaml
import argparse
import logging
from pathlib import Path # Import Path

from infra import ReleaseManager
from releaselib.git_service import GitService
from releaselib.vault_service import VaultService
from releaselib.exceptions import ReleaseError, VaultServiceError

# --- Logging Setup ---
LOG_FORMAT = "%(levelname)s: %(message)s"
COLOR_CODES = {
    'DEBUG': '\033[90m',    # Grey
    'INFO': '\033[0m',     # Reset
    'WARNING': '\033[93m',  # Yellow
    'ERROR': '\033[91m',    # Red
    'CRITICAL': '\033[91m', # Red
    'DRY_RUN': '\033[96m',  # Cyan
    'SUCCESS': '\033[92m',  # Green
}
RESET_CODE = '\033[0m'

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
        level_name = record.levelname
        
        # Custom handling for DRY_RUN and SUCCESS messages
        if level_name == 'INFO' and 'DRY-RUN' in log_message:
            level_name = 'DRY_RUN'
        elif level_name == 'INFO' and '✓' in log_message: # Simple heuristic for success messages
            level_name = 'SUCCESS'

        color_code = COLOR_CODES.get(level_name, RESET_CODE)
        return f"{color_code}{log_message}{RESET_CODE}"

def setup_logging(verbose=False, debug=False):
    logger = logging.getLogger(__name__)
    # Set the logger's level to the lowest possible to allow handlers to filter
    logger.setLevel(logging.DEBUG) 

    # Check if a handler with ColoredFormatter already exists to avoid duplicates
    found_handler = False
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and isinstance(handler.formatter, ColoredFormatter):
            handler.setLevel(logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING))
            found_handler = True
            break
    
    if not found_handler:
        # If no such handler exists, create and add a new one
        handler = logging.StreamHandler(sys.stdout)
        formatter = ColoredFormatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING))
        logger.addHandler(handler)
    
    # Propagate to root logger should be False to prevent duplicate messages if root logger also has handlers
    logger.propagate = False
    
    return logger

logger = logging.getLogger(__name__) # Initialize global logger for this module

# --- Configuration Loader ---

def load_project_config():
    """
    Loads the main project.yaml configuration file and returns the compiler_settings.
    """
    try:
        with open('project.yaml', 'r') as f:
            return yaml.safe_load(f)['compiler_settings']
    except (IOError, KeyError, TypeError, yaml.YAMLError) as e:
        logger.critical(f"[FATAL] Could not load or parse compiler settings from project.yaml: {e}")
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
    parser.add_argument("--git-timeout", type=int, default=60, help="Timeout for Git commands in seconds.")
    parser.add_argument("--vault-timeout", type=int, default=10, help="Timeout for Vault API calls in seconds.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output (most verbose).")
    
    args = parser.parse_args()
    
    # Setup logging based on CLI arguments
    global logger
    logger = setup_logging(args.verbose, args.debug)

    try:
        if args.dry_run:
            logger.info("--- Starting in DRY-RUN mode. No changes will be made. ---")

        # 1. Load configuration and initialize services
        config = load_project_config()
        
        # Determine project root for GitService
        project_root = Path(os.getcwd()) # Store as Path object
        
        git_service = GitService(cwd=project_root, timeout=args.git_timeout)
        
        vault_service = None
        if args.command == 'release':
            vault_addr = os.getenv('VAULT_ADDR')
            vault_token = os.getenv('VAULT_TOKEN')
            vault_cacert = os.getenv('VAULT_CACERT')

            # TLS warning is now handled by VaultService constructor if not dry-run
            
            vault_service = VaultService(
                vault_addr=vault_addr,
                vault_token=vault_token,
                vault_cacert=vault_cacert,
                dry_run=args.dry_run,
                timeout=args.vault_timeout,
                logger=logger # Pass logger to service
            )

        manager = ReleaseManager(
            config, 
            git_service=git_service, 
            vault_service=vault_service,
            project_root=project_root, # Pass project_root to ReleaseManager
            dry_run=args.dry_run,
            logger=logger # Pass logger to manager
        )

        # 2. Execute the requested command
        if args.command == 'validate':
            logger.info("--- Running Schema Validation ---")
            manager.run_validation()
            logger.info("✓ All schemas are valid.")

        elif args.command == 'release':
            logger.info("--- Running Schema Release ---")
            
            logger.info("[Phase 1/3] Validating schemas...")
            manager.run_validation()
            logger.info("✓ Schemas are valid.")
            
            logger.info("[Phase 2/3] Running pre-flight checks...")
            version, _ = manager.run_release_check()
            logger.info(f"✓ All checks passed for version {version}.")
            
            logger.info("[Phase 3/3] Closing release...")
            release_version, component_name = manager.run_release_close()

            if args.dry_run:
                logger.info("[DRY-RUN] Release process simulation complete. Vault signing was simulated.")
            else:
                logger.info("✓ Release closed successfully. project.yaml has been finalized.")
                logger.warning(f"ACTION REQUIRED: Please commit the changes and create the tag: git tag {component_name}@v{release_version}")

    except ReleaseError as e:
        logger.critical(f"[RELEASE FAILED] {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"[UNEXPECTED ERROR] An unhandled exception occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

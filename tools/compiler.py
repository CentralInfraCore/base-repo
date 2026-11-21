"""Command-line entry point of the golang flavor's release tooling (``python -m
tools.compiler``).

Subcommands: ``validate`` loads and resolves the canonical source schema
(``ReleaseManager.run_validation``; full validation is still a placeholder); ``release
--version X`` runs the release phase that matches the current branch
(``ReleaseManager.run_release_close``). The Vault token comes from ``VAULT_TOKEN`` or
the file named by ``CIC_VAULT_TOKEN_FILE``; ``--dry-run`` neither signs nor writes.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

import yaml

from .infra import ReleaseManager
from .releaselib.exceptions import ManualInterventionRequired, ReleaseError
from .releaselib.git_service import GitService
from .releaselib.vault_service import VaultService

# --- Logging Setup ---
LOG_FORMAT = "%(levelname)s: %(message)s"
COLOR_CODES = {
    "DEBUG": "\033[90m",
    "INFO": "\033[0m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[91m",
    "DRY_RUN": "\033[96m",
    "SUCCESS": "\033[92m",
    "MANUAL": "\033[94m",
}
RESET_CODE = "\033[0m"


class ColoredFormatter(logging.Formatter):
    """Log formatter that colors each line with an ANSI code chosen by its content: lines
    with ``DRY-RUN``, ``ACTION REQUIRED`` or ``✓`` get the dry-run, manual-step and
    success colors, other lines the color of their level.
    """

    def format(self, record):
        """Format the record, then wrap it in the color code and a reset."""
        log_message = super().format(record)
        level_name = record.levelname

        if "DRY-RUN" in log_message:
            level_name = "DRY_RUN"
        elif "ACTION REQUIRED" in log_message:
            level_name = "MANUAL"
        elif "✓" in log_message:
            level_name = "SUCCESS"

        color_code = COLOR_CODES.get(level_name, RESET_CODE)
        return f"{color_code}{log_message}{RESET_CODE}"


def setup_logging(verbose=False, debug=False):
    """Return this module's logger writing to stdout at the requested verbosity. The
    handler level is DEBUG with ``debug``, INFO with ``verbose``, WARNING otherwise. A
    stdout handler is added only if the logger has no stream handler yet, and
    propagation to the root logger is turned off.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        logger.addHandler(handler)

    handler = logger.handlers[0]
    handler.setLevel(
        logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    )
    logger.propagate = False
    return logger


logger = logging.getLogger(__name__)


# --- Configuration Loader ---
def load_project_config():
    """Load ``project.yaml`` from the current directory. Returns the whole document. Exits
    the process with status 1 if the file cannot be read or parsed or has no
    ``compiler_settings`` key.
    """
    try:
        with open("project.yaml", "r") as f:
            config = yaml.safe_load(f)
            if "compiler_settings" not in config:
                raise KeyError("'compiler_settings' not found in project.yaml")
            return config
    except (IOError, KeyError, TypeError, yaml.YAMLError) as e:
        logger.critical(f"[FATAL] Could not load or parse project.yaml: {e}")
        sys.exit(1)


# --- Main Application Logic ---
def main():
    """Parse the command line, build the Git and Vault services and dispatch the
    subcommand. A ``ManualInterventionRequired`` is logged as an action and exits with
    status 0; a ``ReleaseError`` or any other exception is logged as critical and exits
    with status 1.
    """
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--dry-run", action="store_true", help="Perform a trial run."
    )
    parent_parser.add_argument(
        "--git-timeout", type=int, default=60, help="Timeout for Git commands."
    )
    parent_parser.add_argument(
        "--vault-timeout", type=int, default=10, help="Timeout for Vault API calls."
    )
    parent_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output."
    )
    parent_parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug output."
    )

    parser = argparse.ArgumentParser(
        description="Schema Compiler & Release Tool", parents=[parent_parser]
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    subparsers.add_parser(
        "validate", help="Validate all schemas.", parents=[parent_parser]
    )

    release_parser = subparsers.add_parser(
        "release", help="Prepare or finalize a release.", parents=[parent_parser]
    )
    release_parser.add_argument(
        "--version",
        required=True,
        help="The semantic version to release (e.g., 1.0.0).",
    )

    args = parser.parse_args()

    global logger
    logger = setup_logging(args.verbose, args.debug)

    try:
        if args.dry_run:
            logger.info("--- Starting in DRY-RUN mode. No changes will be made. ---")

        full_config = load_project_config()
        compiler_config = full_config.get("compiler_settings", {})

        project_root = Path(os.getcwd())
        git_service = GitService(cwd=project_root, timeout=args.git_timeout)

        vault_addr = os.getenv("VAULT_ADDR")
        vault_token = os.getenv("VAULT_TOKEN")
        vault_token_file = os.getenv(
            "CIC_VAULT_TOKEN_FILE", "/var/run/secrets/vault-token"
        )
        if not vault_token and os.path.exists(vault_token_file):
            try:
                with open(vault_token_file, "r") as f:
                    vault_token = f.read().strip()
            except IOError as e:
                logger.warning(
                    f"Could not read Vault token from {vault_token_file}: {e}"
                )

        vault_cacert = os.getenv("VAULT_CACERT")
        vault_cacert_file = "/var/run/secrets/vault-ca.crt"
        if not vault_cacert and os.path.exists(vault_cacert_file):
            vault_cacert = vault_cacert_file

        vault_service = VaultService(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_cacert=vault_cacert,
            dry_run=args.dry_run,
            timeout=args.vault_timeout,
            logger=logger,
        )

        manager = ReleaseManager(
            compiler_config,
            git_service=git_service,
            vault_service=vault_service,
            project_root=project_root,
            dry_run=args.dry_run,
            logger=logger,
        )

        if args.command == "validate":
            logger.info("--- Running Schema Validation ---")
            manager.run_validation()
            logger.info("✓ All schemas are valid.")

        elif args.command == "release":
            manager.run_release_close(release_version=args.version)

    except ManualInterventionRequired as e:
        logger.info(f"[ACTION REQUIRED] {e}")
        sys.exit(0)  # Exit with 0 for manual intervention
    except ReleaseError as e:
        logger.critical(f"[RELEASE FAILED] {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(
            f"[UNEXPECTED ERROR] An unhandled exception occurred: {e}", exc_info=True
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

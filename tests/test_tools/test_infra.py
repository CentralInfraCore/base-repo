import base64
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import ANY

import pytest
import yaml

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from jsonschema import ValidationError as JsonSchemaValidationError

# Import specific functions/classes from their new locations
from tools.infra import (
    ReleaseManager,
    ValidationFailureError,
    get_reproducible_repo_hash,
    load_yaml,
    write_yaml,
    ManualInterventionRequired,
)
from tools.releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    ReleaseError,
    VaultServiceError,
    VersionMismatchError,
)
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService

# Dummy schema data for testing
DUMMY_SCHEMA_DATA = {"spec": {"type": "object"}}

@pytest.fixture
def mock_release_manager_deps(mocker):
    mock_config = {
        "meta_schema_file": "meta.yaml",
        "meta_schemas_dir": "schemas",
        "component_name": "base",
        "main_branch": "main",
        "vault_key_name": "author-key",
        "cic_root_ca_key_name": "approval-key",
    }
    mock_git_service = mocker.MagicMock(spec=GitService)
    mock_vault_service = mocker.MagicMock(spec=VaultService)
    mock_logger = mocker.MagicMock()
    mock_project_root = mocker.MagicMock(spec=Path)
    mock_project_root.resolve.return_value = mock_project_root

    def mock_truediv(other):
        path_mock = mocker.MagicMock(spec=Path)
        path_mock.name = str(other)
        path_mock.resolve.return_value = path_mock
        return path_mock

    mock_project_root.__truediv__.side_effect = mock_truediv
    mock_project_root.glob.return_value = []

    # Default mocks for git service
    mock_git_service.is_dirty.return_value = False
    mock_git_service.get_current_branch.return_value = "main"
    mock_git_service.write_tree.return_value = "dummy_tree_id"

    return (
        mock_config,
        mock_git_service,
        mock_vault_service,
        mock_logger,
        mock_project_root,
    )


class TestRunValidation:
    # These tests are fine and test the validation logic separately
    def test_runs(self, mocker, mock_release_manager_deps):
        (
            mock_config,
            mock_git_service,
            mock_vault_service,
            mock_logger,
            mock_project_root,
        ) = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger,
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name="schema_file.yaml")
        mock_schema_file.resolve.return_value = Path("schema_file.yaml")
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch("tools.infra.load_yaml", side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA])
        mocker.patch("tools.infra.validate", return_value=None)

        manager.run_validation()
        mock_logger.info.assert_any_call("✓ Schema validation passed.")


class TestCheckBaseBranchAndVersion:
    """
    Tests the internal _check_base_branch_and_version method.
    """
    def test_success(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, None, root, logger=logger)
        manager._check_base_branch_and_version("1.0.0") # Should not raise

    def test_missing_component_name(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        del config["component_name"]
        manager = ReleaseManager(config, git, None, root, logger=logger)
        with pytest.raises(ConfigurationError):
            manager._check_base_branch_and_version("1.0.0")

    def test_dirty_working_directory(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        git.is_dirty.return_value = True
        manager = ReleaseManager(config, git, None, root, logger=logger)
        with pytest.raises(GitStateError):
            manager._check_base_branch_and_version("1.0.0")

    def test_invalid_base_branch(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        git.get_current_branch.return_value = "feature/branch"
        manager = ReleaseManager(config, git, None, root, logger=logger)
        with pytest.raises(GitStateError):
            manager._check_base_branch_and_version("1.0.0")


class TestRunRelease:
    """
    New test class for the main `run_release` orchestrator method.
    """
    @pytest.fixture(autouse=True)
    def setup_mocks(self, mocker):
        mocker.patch("tools.infra.get_reproducible_repo_hash", return_value="dummy_digest_b64")
        mocker.patch("tools.infra.write_yaml")
        mocker.patch("tools.infra.load_yaml", return_value={"compiler_settings": {"component_name": "base"}})
        mocker.patch("tools.infra.validate")

    def test_happy_path(self, mock_release_manager_deps):
        """Tests the full, successful, automated release process."""
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        
        vault.sign.side_effect = ["author_signature", "approval_signature"]

        manager.run_release("1.0.1")

        # Preparation phase
        git.checkout.assert_any_call("base/releases/v1.0.1", create_new=True)
        
        # Finalization phase
        git.run.assert_any_call(["git", "tag", "-a", "base@v1.0.1", "-m", "Release base v1.0.1"])
        git.checkout.assert_any_call("main")
        git.merge.assert_called_once()
        git.delete_branch.assert_called_once_with("base/releases/v1.0.1")
        logger.info.assert_any_call("✓ Release 1.0.1 successfully finalized and merged into main.")

    def test_unhappy_path_vault_failure(self, mock_release_manager_deps):
        """Tests that manual intervention is requested when Vault fails."""
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        
        vault.sign.side_effect = VaultServiceError("Vault is down")

        with pytest.raises(ManualInterventionRequired) as excinfo:
            manager.run_release("1.0.1")
        
        assert "ACTION REQUIRED" in str(excinfo.value)
        assert "Digest (Base64): dummy_digest_b64" in str(excinfo.value)
        
        # Verify it doesn't proceed to finalize
        git.merge.assert_not_called()
        git.delete_branch.assert_not_called()

    def test_finalize_path(self, mock_release_manager_deps):
        """Tests the finalization part of the flow when run on a release branch."""
        (config, git, vault, logger, root) = mock_release_manager_deps
        
        # Simulate being on the release branch
        git.get_current_branch.return_value = "base/releases/v1.0.1"
        
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        
        manager.run_release("1.0.1")

        # Should not try to prepare, only finalize
        git.checkout.assert_any_call("main")
        git.merge.assert_called_once()
        git.delete_branch.assert_called_once_with("base/releases/v1.0.1")
        vault.sign.assert_not_called() # Shouldn't sign again

    def test_dry_run_mode(self, mock_release_manager_deps):
        """Tests that dry_run prevents any state-changing operations."""
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, dry_run=True, logger=logger)
        
        vault.sign.side_effect = ["author_signature", "approval_signature"]

        manager.run_release("1.0.1")

        # Check that no destructive/state-changing calls were made
        git.checkout.assert_not_called()
        git.run.assert_not_called()
        git.merge.assert_not_called()
        git.delete_branch.assert_not_called()
        
        # Ensure the logger was informed about dry run
        logger.info.assert_any_call("✓ Both signatures obtained. Proceeding to finalize release automatically.")
        logger.info.assert_any_call("✓ Release 1.0.1 successfully finalized and merged into main.")

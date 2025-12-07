import base64
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import ANY, mock_open

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
        path_mock.parent = mock_project_root # For write_yaml's tempfile
        return path_mock

    mock_project_root.__truediv__.side_effect = mock_truediv
    mock_project_root.glob.return_value = []

    # Default mocks for git service
    mock_git_service.is_dirty.return_value = False
    mock_git_service.get_current_branch.return_value = "main"
    mock_git_service.write_tree.return_value = "dummy_tree_id"
    mock_git_service.assert_clean_index.return_value = None
    mock_git_service.is_index_dirty.return_value = True

    return (
        mock_config,
        mock_git_service,
        mock_vault_service,
        mock_logger,
        mock_project_root,
    )


class TestRunValidation:
    def test_runs(self, mocker, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        
        mock_schema_file = mocker.MagicMock(spec=Path, name="schema_file.yaml")
        mock_schema_file.resolve.return_value = Path("schema_file.yaml")
        root.glob.return_value = [mock_schema_file]

        mocker.patch("tools.infra.load_yaml", side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA])
        mocker.patch("tools.infra.validate", return_value=None)

        manager.run_validation()
        logger.info.assert_any_call("✓ Schema validation passed.")

    def test_meta_schema_load_failure(self, mocker, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        mocker.patch("tools.infra.load_yaml", side_effect=ConfigurationError("File not found"))
        with pytest.raises(ConfigurationError):
            manager.run_validation()

    def test_empty_schema_file_in_validation(self, mocker, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        
        mock_schema_file = mocker.MagicMock(spec=Path, name="empty.yaml")
        root.glob.return_value = [mock_schema_file]

        mocker.patch("tools.infra.load_yaml", side_effect=[{"type": "object"}, None])
        
        with pytest.raises(ValidationFailureError, match="File is empty"):
            manager.run_validation()


class TestCheckBaseBranchAndVersion:
    def test_success(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, None, root, logger=logger)
        manager._check_base_branch_and_version("1.0.0")

    def test_invalid_version_string(self, mock_release_manager_deps):
        (config, git, _, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, None, root, logger=logger)
        with pytest.raises(VersionMismatchError):
            manager._check_base_branch_and_version("not-a-version")


class TestRunRelease:
    @pytest.fixture(autouse=True)
    def setup_mocks(self, mocker):
        mocker.patch("tools.infra.get_reproducible_repo_hash", return_value="dummy_digest_b64")
        mocker.patch("tools.infra.write_yaml")
        mocker.patch("tools.infra.load_yaml", return_value={"compiler_settings": {"component_name": "base"}})
        mocker.patch("tools.infra.validate")

    def test_happy_path(self, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        vault.sign.side_effect = ["author_signature", "approval_signature"]
        manager.run_release("1.0.1")
        git.checkout.assert_any_call("base/releases/v1.0.1", create_new=True)
        git.run.assert_any_call(["git", "tag", "-a", "base@v1.0.1", "-m", "Release base v1.0.1"])
        git.checkout.assert_any_call("main")
        git.merge.assert_called_once()
        git.delete_branch.assert_called_once_with("base/releases/v1.0.1")

    def test_unhappy_path_vault_failure(self, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        vault.sign.side_effect = VaultServiceError("Vault is down")
        with pytest.raises(ManualInterventionRequired):
            manager.run_release("1.0.1")
        git.merge.assert_not_called()

    def test_finalize_path(self, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        git.get_current_branch.return_value = "base/releases/v1.0.1"
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        manager.run_release("1.0.1")
        git.checkout.assert_any_call("main")
        git.merge.assert_called_once()
        vault.sign.assert_not_called()

    def test_finalize_path_with_clean_index(self, mock_release_manager_deps):
        (config, git, vault, logger, root) = mock_release_manager_deps
        git.get_current_branch.return_value = "base/releases/v1.0.1"
        git.is_index_dirty.return_value = False
        manager = ReleaseManager(config, git, vault, root, logger=logger)
        manager.run_release("1.0.1")
        logger.info.assert_any_call("Index is clean, assuming user has committed manually.")
        assert not any("commit" in call[0][0] for call in git.run.call_args_list)

    def test_finalize_path_invalid_yaml(self, mocker, mock_release_manager_deps):
        (config, git, vault, _, root) = mock_release_manager_deps
        git.get_current_branch.return_value = "base/releases/v1.0.1"
        manager = ReleaseManager(config, git, vault, root)
        mocker.patch("tools.infra.validate", side_effect=JsonSchemaValidationError("Missing signature"))
        with pytest.raises(ValidationFailureError):
            manager.run_release("1.0.1")

    def test_run_release_wrong_branch(self, mock_release_manager_deps):
        (config, git, vault, _, root) = mock_release_manager_deps
        git.get_current_branch.return_value = "feature/some-other-branch"
        manager = ReleaseManager(config, git, vault, root)
        with pytest.raises(GitStateError):
            manager.run_release("1.0.1")


class TestHelperFunctions:
    def test_load_yaml_file_not_found(self, mocker):
        mocker.patch("builtins.open", side_effect=FileNotFoundError)
        with pytest.raises(ConfigurationError):
            load_yaml(Path("nonexistent.yaml"))

    def test_load_yaml_invalid_yaml(self, mocker):
        mocker.patch("builtins.open", mock_open(read_data=": invalid yaml"))
        with pytest.raises(ConfigurationError):
            load_yaml(Path("invalid.yaml"))

    def test_write_yaml_io_error(self, mocker):
        mocker.patch("tempfile.NamedTemporaryFile", side_effect=IOError("Disk full"))
        with pytest.raises(ReleaseError):
            write_yaml(Path("any.yaml"), {})

    def test_write_yaml_cleanup_on_replace_error(self, mocker):
        mocker.patch("os.replace", side_effect=OSError("Permission denied"))
        
        # Mock tempfile to have a predictable name
        mock_tmp_file = mocker.MagicMock()
        mock_tmp_file.name = "dummy_temp_file"
        mock_tmp_file_cm = mocker.MagicMock()
        mock_tmp_file_cm.__enter__.return_value = mock_tmp_file
        mock_tmp_file_cm.__exit__.return_value = None
        mocker.patch("tools.infra.tempfile.NamedTemporaryFile", return_value=mock_tmp_file_cm)

        # Mock the Path class to control the instance created from the temp name
        mock_path_instance = mocker.MagicMock()
        mock_path_instance.exists.return_value = True
        
        # When Path() is called in tools.infra, make it return our mock instance
        # This is a bit more robust than patching the return_value of the class mock
        mock_path_class = mocker.patch("tools.infra.Path")
        mock_path_class.return_value = mock_path_instance

        with pytest.raises(ReleaseError, match="Permission denied"):
            write_yaml(Path("any.yaml"), {"data": "content"})
        
        # Assert that Path was called with our temp name
        mock_path_class.assert_any_call("dummy_temp_file")
        # Assert that exists and unlink were called on the instance
        mock_path_instance.exists.assert_called_once()
        mock_path_instance.unlink.assert_called_once()

    def test_get_reproducible_repo_hash_error(self, mocker):
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_git_service.archive_tree_bytes.side_effect = Exception("Git error")
        with pytest.raises(ReleaseError):
            get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")

import pytest
import yaml
from unittest.mock import MagicMock, patch, ANY
from pathlib import Path
import logging

# Add project root to sys.path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from tools.infra import ReleaseManager, load_yaml, write_yaml, get_reproducible_repo_hash
from tools.releaselib.exceptions import VaultServiceError, ReleaseError, ConfigurationError, GitStateError
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService

# --- Fixtures ---

@pytest.fixture
def mock_services(mocker):
    """Provides a dictionary of mocked services and configs."""
    mock_config = {
        'component_name': 'base',
        'vault_key_name': 'user-key',
        'cic_root_ca_key_name': 'cic-key',
        'vault_cert_mount': 'kv',
        'vault_cert_secret_name': 'user-cert',
        'vault_cert_secret_key': 'cert',
        'main_branch': 'main' # Added for _check_base_branch_and_version
    }
    mock_git_service = mocker.MagicMock(spec=GitService)
    mock_vault_service = mocker.MagicMock(spec=VaultService)
    mock_logger = mocker.MagicMock(spec=logging.Logger)
    
    mock_git_service.get_current_branch.return_value = "main"
    mock_git_service.write_tree.return_value = "dummy_tree_id"
    mock_git_service.is_dirty.return_value = False # Added for _check_base_branch_and_version
    mock_git_service.assert_clean_index.return_value = None # Added for _check_base_branch_and_version

    mock_vault_service.sign.return_value = "dummy-signature"
    mock_vault_service.get_certificate.return_value = "-----BEGIN CERTIFICATE-----\nDUMMY-CERT\n-----END CERTIFICATE-----"
    
    mocker.patch('tools.infra.load_yaml', return_value={
        'metadata': {
            'name': 'base',
            'description': 'Test description',
            'license': 'Test License',
            'owner': 'Test Owner',
            'tags': ['test']
        },
        'compiler_settings': mock_config
    })
    
    mocker.patch('tools.infra.write_yaml')
    mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_hash_b64")
    mocker.patch('tools.infra.requests.get') # Mock requests.get for _check_api_accessibility
    mocker.patch('sys.exit') # Mock sys.exit for _check_api_accessibility

    return {
        "config": mock_config,
        "git_service": mock_git_service,
        "vault_service": mock_vault_service,
        "logger": mock_logger,
        "project_root": Path('/fake/project'),
        "dry_run": False
    }

# --- Test Classes ---

class TestHelperFunctions:
    def test_load_yaml_file_not_found(self, mocker):
        mocker.patch("builtins.open", side_effect=FileNotFoundError)
        with pytest.raises(ConfigurationError, match="Configuration file not found"):
            load_yaml(Path("nonexistent.yaml"))

    def test_load_yaml_invalid_yaml(self, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data=": invalid yaml"))
        with pytest.raises(ConfigurationError, match="YAML syntax error"):
            load_yaml(Path("any.yaml"))

    def test_load_yaml_empty_file(self, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data=""))
        assert load_yaml(Path("empty.yaml")) is None

    def test_write_yaml_io_error(self, mocker):
        mocker.patch("tools.infra.tempfile.NamedTemporaryFile", side_effect=IOError("Disk full"))
        with pytest.raises(ReleaseError, match="Failed to write YAML file"):
            write_yaml(Path("any.yaml"), {})

    def test_write_yaml_cleanup_on_error(self, mocker):
        mock_tmp_file = MagicMock()
        mock_tmp_file.name = "/fake/dir/dummy_temp_file"
        mock_tmp_file_cm = MagicMock()
        mock_tmp_file_cm.__enter__.return_value = mock_tmp_file
        mock_tmp_file_cm.__exit__.return_value = None
        mocker.patch("tools.infra.tempfile.NamedTemporaryFile", return_value=mock_tmp_file_cm)

        mocker.patch("tools.infra.os.replace", side_effect=OSError("Permission denied"))

        mock_path_instance = MagicMock(spec=Path)
        mock_path_instance.exists.return_value = True
        mock_path_class = mocker.patch("tools.infra.Path", return_value=mock_path_instance)

        input_path = MagicMock(spec=Path)
        input_path.parent = "/fake/dir"

        with pytest.raises(ReleaseError, match="Permission denied"):
            write_yaml(input_path, {"data": "content"})

        mock_path_class.assert_called_with("/fake/dir/dummy_temp_file")
        mock_path_instance.exists.assert_called_once()
        mock_path_instance.unlink.assert_called_once()

    def test_get_reproducible_repo_hash_error(self, mocker):
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_git_service.archive_tree_bytes.side_effect = Exception("Git archive failed")
        with pytest.raises(ReleaseError, match="Error during repo hash calculation"):
            get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")

class TestReleaseManagerPhases:
    def test_developer_preparation_phase_success(self, mock_services):
        manager = ReleaseManager(**mock_services)
        manager.run_release_close(release_version="1.0.0")

        # Verify Git operations for branch creation and commit/tag
        mock_services["git_service"].checkout.assert_any_call("base/releases/v1.0.0", create_new=True)
        mock_services["git_service"].add.assert_called_once_with('/fake/project/project.yaml')
        mock_services["git_service"].run.assert_any_call(['git', 'commit', '-m', 'release: Prepare base v1.0.0 for build'])
        mock_services["git_service"].run.assert_any_call(['git', 'tag', '-a', 'base@v1.0.0-dev', '-m', 'Developer release prep for base v1.0.0'])
        
        # Verify Vault calls
        mock_services["vault_service"].get_certificate.assert_any_call("kv", "user-cert", "cert")
        mock_services["vault_service"].get_certificate.assert_any_call("kv", "CICRootCA", "cert") # Assuming 'cert' is the key for CICRootCA too

        # Verify sys.exit is called for API check
        mock_services["sys.exit"].assert_called_once_with(0)

    def test_finalization_phase_success(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "base/releases/v1.0.0"
        manager = ReleaseManager(**mock_services)
        
        manager.run_release_close(release_version="1.0.0")

        # Verify validation is called
        from tools.infra import validate
        validate.assert_called_once()

        # Verify Git operations for finalization
        mock_services["git_service"].run.assert_any_call(['git', 'commit', '-m', 'release: Finalize base v1.0.0 build artifacts'])
        mock_services["git_service"].run.assert_any_call(['git', 'tag', '-a', 'base@v1.0.0', '-m', 'Release base v1.0.0'])
        mock_services["git_service"].checkout.assert_any_call("main")
        mock_services["git_service"].merge.assert_called_once()
        mock_services["git_service"].delete_branch.assert_called_once_with("base/releases/v1.0.0")

    def test_dry_run_developer_phase(self, mock_services):
        mock_services['dry_run'] = True
        manager = ReleaseManager(**mock_services)
        
        manager.run_release_close(release_version="1.0.0")

        from tools.infra import write_yaml
        write_yaml.assert_not_called()
        mock_services["git_service"].add.assert_not_called()
        mock_services["git_service"].run.assert_not_called()
        mock_services["git_service"].checkout.assert_not_called() # No actual checkout in dry-run
        
        mock_services["logger"].info.assert_any_call("[DRY-RUN] The following data would be written to project.yaml:")
        mock_services["logger"].info.assert_any_call("[DRY-RUN] Simulating Developer Preparation Phase.")
        
        # API check still runs and exits in dry-run
        mock_services["sys.exit"].assert_called_once_with(0)

    def test_invalid_branch(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "feature/some-branch"
        manager = ReleaseManager(**mock_services)
        
        with pytest.raises(GitStateError, match="Release command must be run from the main branch"):
            manager.run_release_close(release_version="1.0.0")

    def test_api_accessibility_check_failure(self, mock_services):
        mock_services["requests.get"].side_effect = requests.exceptions.RequestException("API is down")
        manager = ReleaseManager(**mock_services)
        
        manager.run_release_close(release_version="1.0.0")
        mock_services["logger"].warning.assert_called_once_with(ANY)
        mock_services["sys.exit"].assert_called_once_with(0)

    def test_finalization_phase_validation_failure(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "base/releases/v1.0.0"
        mocker.patch('tools.infra.validate', side_effect=JsonSchemaValidationError("Validation failed"))
        manager = ReleaseManager(**mock_services)
        
        with pytest.raises(ReleaseError, match="Final project.yaml validation failed"):
            manager.run_release_close(release_version="1.0.0")

    def test_finalization_phase_dirty_repo_commit(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "base/releases/v1.0.0"
        mock_services["git_service"].is_dirty.return_value = True
        manager = ReleaseManager(**mock_services)
        
        manager.run_release_close(release_version="1.0.0")
        mock_services["git_service"].run.assert_any_call(['git', 'commit', '-m', 'release: Finalize base v1.0.0 build artifacts'])

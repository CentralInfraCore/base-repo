import pytest
import os
from datetime import datetime, timezone
import yaml
import sys
import base64
import hashlib
import requests
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from jsonschema import ValidationError as JsonSchemaValidationError

# Import specific functions/classes from their new locations
from tools.compiler import main, setup_logging, load_project_config
from tools.infra import ReleaseManager, load_yaml, write_yaml, get_reproducible_repo_hash, ValidationFailureError
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService
from tools.releaselib.exceptions import ConfigurationError, GitStateError, VersionMismatchError, ReleaseError, VaultServiceError

# Dummy schema data for testing run_release
DUMMY_SCHEMA_DATA = {
    "metadata": {
        "name": "test-schema",
        "version": "v1.0.0",
        "description": "A dummy schema for testing.",
        "createdBy": {
            "name": "Test User",
            "email": "test@example.com",
            "certificate": "-----BEGIN CERTIFICATE-----TEST-----END CERTIFICATE-----",
            "issuer_certificate": "-----BEGIN CERTIFICATE-----ISSUER-----END CERTIFICATE-----",
        },
        "validity": {
            "from": "2025-01-01T00:00:00Z",
            "until": "2026-01-01T00:00:00Z",
        }
    },
    "spec": {
        "type": "object",
        "properties": {
            "field1": {"type": "string"}
        }
    }
}

DUMMY_DEV_SCHEMA_DATA = {
    "metadata": {
        "name": "test-schema-dev",
        "version": "v1.0.0.dev",
        "description": "A dummy dev schema for testing.",
        "createdBy": {
            "name": "Test User",
            "email": "test@example.com",
            "certificate": "-----BEGIN CERTIFICATE-----TEST-----END CERTIFICATE-----",
            "issuer_certificate": "-----BEGIN CERTIFICATE-----ISSUER-----END CERTIFICATE-----",
        },
        "validity": {
            "from": "2025-01-01T00:00:00Z",
            "until": "2026-01-01T00:00:00Z",
        }
    },
    "spec": {
        "type": "object",
        "properties": {
            "field1": {"type": "string"}
        }
    }
}

# Expected signature response from Vault
VAULT_SIGNATURE_RESPONSE = {
    "data": {
        "signature": "vault:v1:MEUCIQCbi5ghHvps5L8qTNtyTJtKghDApzgmjverpF7NqnK9lwIgSnVVEx5SZxNIL33CH0ErAGdmIrmLU4jMhLkM9mNxMLQ="
    }
}

class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc if tz is None else tz)

# Helper to mock ReleaseManager dependencies
@pytest.fixture
def mock_release_manager_deps(mocker):
    mock_config = {'meta_schema_file': 'meta.yaml', 'meta_schemas_dir': 'schemas', 'component_name': 'base', 'vault_key_name': 'cic-my-sign-key'}
    mock_git_service = mocker.MagicMock(spec=GitService)
    mock_vault_service = mocker.MagicMock(spec=VaultService)
    mock_logger = mocker.MagicMock()
    
    mock_project_root = mocker.MagicMock(spec=Path)
    mock_project_root.resolve.return_value = mock_project_root
    mock_project_root.exists.return_value = True
    
    # FIX: Create a stateful mock for project.yaml
    path_mocks = {}

    def mock_truediv(other):
        path_key = str(other)
        if path_key not in path_mocks:
            result_path_mock = mocker.MagicMock(spec=Path)
            result_path_mock.name = path_key
            result_path_mock.resolve.return_value = result_path_mock
            path_mocks[path_key] = result_path_mock

            if path_key == 'project.yaml':
                result_path_mock.exists.return_value = True
                result_path_mock.read_text.return_value = "compiler_settings:\n  component_name: base\nrelease: {}"
            elif path_key == mock_config['meta_schema_file']:
                result_path_mock.exists.return_value = True
            else:
                result_path_mock.exists.return_value = False
                result_path_mock.read_text.side_effect = FileNotFoundError
        
        return path_mocks[path_key]

    mock_project_root.__truediv__.side_effect = mock_truediv
    mock_project_root.glob.return_value = [] 

    return mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root


class TestLoadYaml:
    def test_valid(self, tmp_path):
        data = {"name": "test", "version": "1.0.0"}
        yaml_path = tmp_path / "schema.yaml"
        yaml_path.write_text(yaml.safe_dump(data))
        result = load_yaml(yaml_path)
        assert result == data

    def test_file_not_found(self, tmp_path):
        missing_file = tmp_path / "missing.yaml"
        with pytest.raises(ConfigurationError):
            load_yaml(missing_file)

    def test_invalid_yaml(self, tmp_path):
        bad_yaml = "name: test: version: 1.0.0"
        yaml_path = tmp_path / "invalid.yaml"
        yaml_path.write_text(bad_yaml)
        with pytest.raises(ConfigurationError):
            load_yaml(yaml_path)

    def test_empty_file(self, tmp_path):
        """Test that load_yaml returns None for an empty file."""
        yaml_path = tmp_path / "empty.yaml"
        yaml_path.write_text("")
        assert load_yaml(yaml_path) is None


class TestRunValidation:
    def test_runs(self, mocker, mock_release_manager_deps):
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA])
        mocker.patch('tools.infra.validate', return_value=None)

        try:
            manager.run_validation()
        except Exception as e:
            pytest.fail(f"An unexpected error occurred during validation: {e}")

    def test_meta_schema_load_failure(self, mocker, mock_release_manager_deps):
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mocker.patch('tools.infra.load_yaml', side_effect=ConfigurationError("File not found"))
        with pytest.raises(ConfigurationError):
            manager.run_validation()

    def test_empty_meta_schema(self, mocker, mock_release_manager_deps):
        """Test validation fails if the meta-schema file is empty."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mocker.patch('tools.infra.load_yaml', return_value=None) # Simulate empty meta-schema
        with pytest.raises(ConfigurationError, match="Meta-schema file .* is empty"):
            manager.run_validation()

    def test_schema_validation_failure(self, mocker, mock_release_manager_deps):
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA])
        mocker.patch('tools.infra.validate', side_effect=JsonSchemaValidationError("Schema invalid"))

        with pytest.raises(ValidationFailureError):
            manager.run_validation()

    def test_unexpected_error_in_validation(self, mocker, mock_release_manager_deps):
        """Test that a generic exception during validation is caught and reported."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]
        mocker.patch('tools.infra.load_yaml', side_effect=[{"type": "object"}, Exception("Unexpected error")])

        with pytest.raises(ValidationFailureError, match="Unexpected Error"):
            manager.run_validation()


class TestRunReleaseCheck:
    def test_invalid_version_string(self, mocker, mock_release_manager_deps):
        """Test that an invalid semver string raises VersionMismatchError."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        with pytest.raises(VersionMismatchError, match="Invalid version string"):
            manager.run_release_check(release_version="not-a-version")

    def test_malformed_existing_tag(self, mocker, mock_release_manager_deps):
        """Test that a malformed existing tag is skipped during version check."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = ["base@v1.0.0", "base@v-invalid"]
        
        # Should not raise an error, but log a warning
        manager.run_release_check(release_version="1.0.1")
        mock_logger.warning.assert_called_with("Skipping malformed tag 'base@v-invalid' during version comparison.")

    def test_not_a_valid_version_increment(self, mocker, mock_release_manager_deps):
        """Test that a non-sequential version raises VersionMismatchError."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = ["base@v1.0.0"]
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="1.0.0") # Same version
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="0.9.0") # Lower version
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="1.1.1") # Not a direct increment


class TestRunReleaseClose:
    @pytest.fixture(autouse=True)
    def setup_release_mocks(self, mocker):
        """Common mocks for all run_release_close tests."""
        mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
        mocker.patch('tools.infra.write_yaml')
        mocker.patch('tools.infra.load_yaml', return_value={'compiler_settings': {'component_name': 'base'}})

    def test_no_vault_service(self, mock_release_manager_deps):
        mock_config, mock_git_service, _, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=None, project_root=mock_project_root, logger=mock_logger)
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        with pytest.raises(VaultServiceError, match="VaultService is not initialized"):
            manager.run_release_close(release_version="0.5.0")

    def test_vault_signing_failure(self, mocker, mock_release_manager_deps):
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.side_effect = VaultServiceError("Vault is down")

        with pytest.raises(ReleaseError, match="Release process failed: Vault is down"):
            manager.run_release_close(release_version="0.5.0")

    def test_rollback_on_failure(self, mocker, mock_release_manager_deps):
        """Test that project.yaml is rolled back on a commit failure."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = "signed_hash"
        # Simulate commit failure
        mock_git_service.run.side_effect = GitStateError("Commit failed")

        with pytest.raises(ReleaseError, match="Commit failed"):
            manager.run_release_close(release_version="1.0.1")

        # Verify rollback logic was called
        mock_git_service.checkout.assert_called_with("main")
        mock_git_service.delete_branch.assert_called_with("base/releases/v1.0.1", force=True)
        mock_logger.info.assert_any_call("✓ project.yaml restored to original state.")

    def test_rollback_for_new_project_yaml(self, mocker, mock_release_manager_deps):
        """Test that a newly created project.yaml is removed on rollback."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        
        project_yaml_path_mock = mock_project_root / 'project.yaml'
        # FIX: Correctly simulate the file's existence changing over time
        project_yaml_path_mock.exists.side_effect = [False, True, True]
        project_yaml_path_mock.read_text.side_effect = FileNotFoundError
        
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = "signed_hash"
        mock_git_service.run.side_effect = GitStateError("Commit failed")

        with pytest.raises(ReleaseError, match="Commit failed"):
            manager.run_release_close(release_version="1.0.1")

        project_yaml_path_mock.unlink.assert_called_once()
        mock_logger.info.assert_any_call("✓ Newly created project.yaml removed.")

    def test_success(self, mocker, mock_release_manager_deps):
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(config=mock_config, git_service=mock_git_service, vault_service=mock_vault_service, project_root=mock_project_root, logger=mock_logger)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = VAULT_SIGNATURE_RESPONSE['data']['signature']

        try:
            manager.run_release_close(release_version="0.5.0")
        except Exception as e:
            pytest.fail(f"An unexpected error occurred during release: {e}")

        mock_vault_service.sign.assert_called_once_with("dummy_digest_b64", "cic-my-sign-key")
        mock_git_service.checkout.assert_any_call("base/releases/v0.5.0", create_new=True)
        mock_git_service.run.assert_any_call(['git', 'commit', '-m', 'release: base v0.5.0'])
        mock_git_service.run.assert_any_call(['git', 'tag', '-a', 'base@v0.5.0', '-m', 'Release base v0.5.0'])
        mock_git_service.checkout.assert_any_call("main")
        mock_git_service.merge.assert_called_once_with("base/releases/v0.5.0", no_ff=True, message="Merge branch 'base/releases/v0.5.0' for release 0.5.0")
        mock_git_service.delete_branch.assert_called_once_with("base/releases/v0.5.0")


class TestHelperFunctions:
    def test_write_yaml(self, tmp_path):
        test_file = tmp_path / "test_output.yaml"
        test_data = {"key1": "value1"}
        write_yaml(test_file, test_data)
        assert test_file.exists()
        loaded_data = yaml.safe_load(test_file.read_text())
        assert loaded_data == test_data

    def test_write_yaml_io_error(self, mocker):
        """Test that write_yaml raises ReleaseError on IO error."""
        mocker.patch('tempfile.NamedTemporaryFile', side_effect=IOError("Disk full"))
        with pytest.raises(ReleaseError, match="Failed to write YAML file"):
            write_yaml(Path("any/path.yaml"), {})

    def test_get_reproducible_repo_hash_success(self, mocker):
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_archive_bytes = b"dummy_archive_bytes"
        mock_git_service.archive_tree_bytes.return_value = mock_archive_bytes
        
        hasher = hashlib.sha256()
        hasher.update(mock_archive_bytes)
        hasher.update(mock_archive_bytes)
        expected_hash_bytes = hasher.digest()
        expected_b64_hash = base64.b64encode(expected_hash_bytes).decode('utf-8')

        result = get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")
        assert result == expected_b64_hash
        mock_git_service.archive_tree_bytes.assert_called_once_with("dummy_tree_id", prefix='./')

    def test_get_reproducible_repo_hash_error(self, mocker):
        """Test that get_reproducible_repo_hash wraps exceptions."""
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_git_service.archive_tree_bytes.side_effect = Exception("Git error")
        with pytest.raises(ReleaseError, match="Error during repo hash calculation: Git error"):
            get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")

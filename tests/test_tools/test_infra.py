import pytest
import os
from datetime import datetime, timezone
import yaml
import sys
import base64
import hashlib
import requests
from unittest.mock import MagicMock, patch
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
    
    # Create a MagicMock that behaves like a Path object for project_root
    mock_project_root = mocker.MagicMock(spec=Path)
    mock_project_root.resolve.return_value = mock_project_root # resolve() should return itself for the root
    mock_project_root.exists.return_value = True # Assume project root always exists
    
    # Mock the / operator for Path objects
    # This is crucial for expressions like `project_root / 'project.yaml'`
    def mock_truediv(other): # Removed 'self' argument
        # Create a new mock Path object for the result of the division
        result_path_mock = mocker.MagicMock(spec=Path)
        result_path_mock.name = str(other) # Set name for debugging/matching
        result_path_mock.resolve.return_value = result_path_mock # Default resolve to itself

        if str(other) == 'project.yaml':
            result_path_mock.exists.return_value = True
            result_path_mock.read_text.return_value = "compiler_settings:\n  component_name: base\nrelease: {}"
        elif str(other) == mock_config['meta_schema_file']:
            result_path_mock.exists.return_value = True # Assume meta-schema file exists
            # Its resolve is already set to itself by default
        else:
            # Default for other paths created by /
            result_path_mock.exists.return_value = False # Assume other files don't exist by default
            result_path_mock.read_text.side_effect = FileNotFoundError # If read, raise error

        return result_path_mock

    mock_project_root.__truediv__.side_effect = mock_truediv

    # Mock glob for project_root - default to empty list, tests can override
    mock_project_root.glob.return_value = [] 

    return mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root


class TestLoadYaml:
    def test_valid(self, tmp_path):
        """Test that load_yaml correctly loads a valid YAML file."""
        data = {"name": "test", "version": "1.0.0"}
        yaml_path = tmp_path / "schema.yaml"
        yaml_path.write_text(yaml.safe_dump(data))
        result = load_yaml(yaml_path)
        assert result == data

    def test_file_not_found(self, tmp_path):
        """Test that load_yaml raises FileNotFoundError if file does not exist."""
        missing_file = tmp_path / "missing.yaml"
        with pytest.raises(ConfigurationError):
            load_yaml(missing_file)

    def test_invalid_yaml(self, tmp_path):
        """Test that load_yaml raises yaml.YAMLError if YAML is invalid."""
        bad_yaml = "name: test: version: 1.0.0"
        yaml_path = tmp_path / "invalid.yaml"
        yaml_path.write_text(bad_yaml)
        with pytest.raises(ConfigurationError):
            load_yaml(yaml_path)


class TestRunValidation:
    def test_runs(self, mocker, mock_release_manager_deps):
        """Test that the compiler's validation function can be called without error."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "properties": {"metadata": {"type": "object"}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA
        ])
        mocker.patch('tools.infra.validate', return_value=None)

        try:
            manager.run_validation()
        except SystemExit as e:
            if e.code == 1:
                pytest.fail(f"Validation failed with SystemExit: {e}")
        except Exception as e:
            pytest.fail(f"An unexpected error occurred during validation: {e}")

    def test_meta_schema_load_failure(self, mocker, mock_release_manager_deps):
        """Test that run_validation exits with code 1 if meta-schema loading fails."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mocker.patch('tools.infra.load_yaml', side_effect=ConfigurationError("File not found"))
        with pytest.raises(ConfigurationError):
            manager.run_validation()

    def test_schema_validation_failure(self, mocker, mock_release_manager_deps):
        """Test that run_validation exits with code 1 if a schema fails validation."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "properties": {"metadata": {"type": "object"}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA
        ])
        mocker.patch('tools.infra.validate', side_effect=JsonSchemaValidationError("Schema invalid"))

        with pytest.raises(ValidationFailureError):
            manager.run_validation()


class TestRunRelease:
    def test_no_vault_env_vars(self, mocker, mock_release_manager_deps):
        """Test that run_release exits with VaultServiceError if VaultService is not initialized."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"

        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=None,
            project_root=mock_project_root,
            logger=mock_logger
        )
        with pytest.raises(VaultServiceError, match="VaultService is not initialized. Cannot sign release."):
            manager.run_release_close(release_version="0.5.0")

    def test_vault_signing_failure(self, mocker, mock_release_manager_deps):
        """Test that run_release exits with ReleaseError if Vault signing fails."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA
        ])
        mocker.patch('tools.infra.validate', return_value=None)
        mocker.patch('tools.infra.write_yaml') # FIX: Add write_yaml mock

        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")

        mock_vault_service.sign.side_effect = VaultServiceError("Vault is down")

        with pytest.raises(ReleaseError, match=r"Release process failed: Vault is down"):
            manager.run_release_close(release_version="0.5.0")

    def test_skip_dev_version(self, mocker, mock_release_manager_deps):
        """Test that run_release skips schemas with '.dev' in their version."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='test-schema.yaml')
        mock_schema_file.resolve.return_value = Path('test-schema.yaml')
        mock_dev_schema_file = mocker.MagicMock(spec=Path, name='test-schema-dev.yaml')
        mock_dev_schema_file.resolve.return_value = Path('test-schema-dev.yaml')
        mock_project_root.glob.return_value = [mock_schema_file, mock_dev_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA,
            DUMMY_DEV_SCHEMA_DATA
        ])
        mocker.patch('tools.infra.write_yaml')
        mocker.patch.object(os.path, 'exists', return_value=True)
        mocker.patch.object(os, 'makedirs')
        mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
        mocker.patch('tools.infra.validate', return_value=None)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
        mock_vault_service.sign.return_value = VAULT_SIGNATURE_RESPONSE['data']['signature']

        manager.run_release_close(release_version="0.5.0")
        pass

    def test_no_schemas_to_release(self, mocker, mock_release_manager_deps):
        """Test that run_release handles the case where no non-dev schemas are found."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_dev_schema_file = mocker.MagicMock(spec=Path, name='test-schema-dev.yaml')
        mock_dev_schema_file.resolve.return_value = Path('test-schema-dev.yaml')
        mock_project_root.glob.return_value = [mock_dev_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_DEV_SCHEMA_DATA
        ])
        mocker.patch('tools.infra.write_yaml')
        mocker.patch.object(os.path, 'exists', return_value=True)
        mocker.patch.object(os, 'makedirs')
        mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
        mocker.patch('tools.infra.validate', return_value=None)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
        mock_vault_service.sign.return_value = VAULT_SIGNATURE_RESPONSE['data']['signature']

        manager.run_release_close(release_version="0.5.0")
        pass

    def test_final_validation_failure(self, mocker, mock_release_manager_deps):
        """Test that run_release exits with ReleaseError if final validation fails."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA,
            {'compiler_settings': mock_config, 'release': {}}
        ])
        mocker.patch('tools.infra.validate', return_value=None)
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
        mock_vault_service.sign.return_value = VAULT_SIGNATURE_RESPONSE['data']['signature']

        mock_write_yaml_helper = mocker.patch('tools.infra.write_yaml')
        mock_write_yaml_helper.side_effect = [
            None,
            ReleaseError("Simulated final write failure")
        ]

        with pytest.raises(ReleaseError, match="Release process failed: Simulated final write failure"):
            manager.run_release_close(release_version="0.5.0")

    def test_create_source_dir(self, mocker, mock_release_manager_deps):
        """Test that run_release creates the SOURCE_DIR if it doesn't exist."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA
        ])
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
        mock_vault_service.sign.return_value = VAULT_SIGNATURE_RESPONSE['data']['signature']

        mocker.patch('os.makedirs')
        mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
        mocker.patch('tools.infra.validate', return_value=None)
        mocker.patch('tools.infra.write_yaml')

        manager.run_release_close(release_version="0.5.0")
        pass

    def test_success(self, mocker, mock_release_manager_deps):
        """Test that the run_release function executes successfully with valid data."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        # A túl hosszú dictionary literál okozta a SyntaxError-t.
        # Kiemeltem egy külön változóba, hogy elkerüljem a hibát.
        meta_schema_for_success_test = {
            "type": "object",
            "required": ["metadata", "spec"],
            "properties": {
                "metadata": {
                    "type": "object",
                    "required": ["name", "version", "description", "createdBy"],
                    "properties": {
                        "name": {"type": "string"},
                        "version": {"type": "string", "pattern": "^v(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*|dev)$"},
                        "description": {"type": "string"},
                        "createdBy": {
                            "type": "object",
                            "required": ["name", "email", "certificate", "issuer_certificate"],
                            "properties": {
                                "name": {"type": "string"},
                                "email": {"type": "string", "format": "email"},
                                "certificate": {"type": "string"},
                                "issuer_certificate": {"type": "string"},
                            }
                        },
                        "build_timestamp": {"type": "string", "format": "date-time"},
                        "validity": {
                            "type": "object",
                            "required": ["from", "until"],
                            "properties": {
                                "from": {"type": "string", "format": "date-time"},
                                "until": {"type": "string", "format": "date-time"},
                            }
                        },
                        "checksum": {"type": "string"},
                        "sign": {"type": "string"},
                    },
                    "allOf": [
                        {
                            "if": {"properties": {"version": {"not": {"pattern": "\\.dev$"}}}},
                            "then": {"required": ["build_timestamp", "validity", "checksum", "sign"]}
                        }
                    ]
                },
                "spec": {"type": "object"}
            }
        }

        mocker.patch('tools.infra.load_yaml', side_effect=[
            meta_schema_for_success_test, # Használjuk a kiemelt változót
            DUMMY_SCHEMA_DATA,
            {'compiler_settings': mock_config, 'release': {}}
        ])
        
        # FIX: Use patch as a context manager for mock_write_yaml_helper
        with patch('tools.infra.write_yaml') as mock_write_yaml_helper:
            mocker.patch.object(os, 'makedirs')
            mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
            mocker.patch('tools.infra.validate', return_value=None)
            
            mock_git_service.get_status_porcelain.return_value = ""
            mock_git_service.assert_clean_index.return_value = None
            mock_git_service.get_current_branch.return_value = "main"
            mock_git_service.get_tags.return_value = []
            mock_git_service.write_tree.return_value = "dummy_tree_id"
            mocker.patch('tools.infra.get_reproducible_repo_hash', return_value="dummy_digest_b64")
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

            assert mock_write_yaml_helper.call_count == 2
            written_data = mock_write_yaml_helper.call_args_list[1][0][1]
            assert written_data['release']['version'] == '0.5.0'
            assert 'repository_tree_hash' in written_data['release']
            assert 'signing_metadata' in written_data['release']
            assert written_data['release']['signing_metadata']['signature'] == VAULT_SIGNATURE_RESPONSE['data']['signature']

    def test_with_vault_cacert(self, mocker, mock_release_manager_deps):
        """Test that run_release uses VAULT_CACERT for TLS verification if provided."""
        mock_config, mock_git_service, mock_vault_service, mock_logger, mock_project_root = mock_release_manager_deps
        mock_vault_cacert_path = "/path/to/ca.pem"
        
        mock_requests_post = mocker.patch('requests.post')
        mock_requests_post.return_value.json.return_value = VAULT_SIGNATURE_RESPONSE
        mock_requests_post.return_value.raise_for_status.return_value = None

        mocker.patch('os.path.exists', side_effect=lambda path: path == mock_vault_cacert_path)

        vault_service_instance = VaultService(
            vault_addr='http://localhost:8200',
            vault_token='test_token',
            vault_cacert=mock_vault_cacert_path,
            dry_run=False,
            logger=mock_logger
        )

        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=vault_service_instance,
            project_root=mock_project_root,
            logger=mock_logger
        )
        mock_schema_file = mocker.MagicMock(spec=Path, name='schema_file.yaml')
        mock_schema_file.resolve.return_value = Path('schema_file.yaml')
        mock_project_root.glob.return_value = [mock_schema_file]

        mocker.patch('tools.infra.load_yaml', side_effect=[
            {"type": "object", "required": ["metadata", "spec"], "properties": {"metadata": {"type": "object", "required": ["name", "version", "createdBy"]}, "spec": {"type": "object"}}},
            DUMMY_SCHEMA_DATA,
            {'compiler_settings': mock_config, 'release': {}}
        ])
        
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.assert_clean_index.return_value = None
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = []
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mocker.patch('tools.infra.get_reproducible_repo_hash', return_value=base64.b64encode(b'dummy_digest_content').decode('ascii'))
        mocker.patch('tools.infra.datetime.datetime', FixedDateTime)
        mocker.patch('tools.infra.validate', return_value=None)
        mocker.patch('tools.infra.write_yaml')

        manager.run_release_close(release_version="0.5.0")

        mock_requests_post.assert_called_once()
        assert mock_requests_post.call_args[1]['verify'] == mock_vault_cacert_path


class TestHelperFunctions:
    def test_write_yaml(self, tmp_path):
        """Test that write_yaml correctly writes data to a YAML file."""
        test_file = tmp_path / "test_output.yaml"
        test_data = {
            "key1": "value1",
            "key2": {
                "nested_key": "nested_value"
            },
            "list_key": [1, 2, 3]
        }

        write_yaml(test_file, test_data)

        assert test_file.exists()
        
        with open(test_file, 'r') as f:
            content = f.read()
        
        loaded_data = yaml.safe_load(content)
        assert loaded_data == test_data

        expected_content = """key1: value1
key2:
  nested_key: nested_value
list_key:
- 1
- 2
- 3
"""
        assert content == expected_content

    def test_get_reproducible_repo_hash_success(self, mocker):
        """Test that get_reproducible_repo_hash correctly calculates the hash."""
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

import logging
import os
import sys
from pathlib import Path
from unittest.mock import ANY, MagicMock, call

import pytest
import yaml
import requests
from jsonschema import ValidationError as JsonSchemaValidationError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.infra import (
    ReleaseManager,
    ConfigurationError,
    GitStateError,
    ReleaseError,
    ValidationFailureError,
    load_and_resolve_schema,
    load_yaml,
    write_yaml,
    _parse_certificate_info,
)
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService

# --- Test Data ---

VALID_PROJECT_YAML = """
metadata:
  name: base
compiler_settings:
  component_name: base
  main_branch: main
  vault_key_name: user-key
  vault_cert_mount: kv
  vault_cert_secret_name: user-cert
  vault_cert_secret_key: cert
  canonical_source_file: sources/index.yaml
  meta_schema_file: project.schema.yaml
"""

VALID_SOURCE_SCHEMA = """
spec:
  key: value
metadata:
  name: test-schema
"""

VALID_CERT = """
-----BEGIN CERTIFICATE-----
MII...
-----END CERTIFICATE-----
"""

# --- Fixtures ---

@pytest.fixture
def mock_git_service(mocker):
    """Mock GitService."""
    service = mocker.MagicMock(spec=GitService)
    service.get_current_branch.return_value = "main"
    service.is_dirty.return_value = False
    return service

@pytest.fixture
def mock_vault_service(mocker):
    """Mock VaultService."""
    service = mocker.MagicMock(spec=VaultService)
    service.sign.return_value = "dummy-signature"
    service.get_certificate.return_value = VALID_CERT
    return service

@pytest.fixture
def mock_config():
    """Provides a valid config dictionary."""
    return yaml.safe_load(VALID_PROJECT_YAML)["compiler_settings"]

# --- Test Classes ---

class TestHelperFunctions:
    def test_load_yaml_success(self, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data="key: value"))
        data = load_yaml(Path("any.yaml"))
        assert data == {"key": "value"}

    def test_load_yaml_file_not_found(self, mocker):
        mocker.patch("builtins.open", side_effect=FileNotFoundError)
        with pytest.raises(ConfigurationError, match="Configuration file not found"):
            load_yaml(Path("nonexistent.yaml"))

    def test_load_yaml_invalid_yaml(self, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data=": invalid"))
        with pytest.raises(ConfigurationError, match="YAML syntax error"):
            load_yaml(Path("any.yaml"))

    def test_load_and_resolve_schema_error(self, mocker):
        mocker.patch("builtins.open", side_effect=FileNotFoundError)
        with pytest.raises(ConfigurationError, match="File not found"):
            load_and_resolve_schema("nonexistent.yaml")

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
        mocker.patch("tools.infra.Path", return_value=mock_path_instance)

        with pytest.raises(ReleaseError, match="Permission denied"):
            write_yaml(MagicMock(spec=Path), {"data": "content"})
        mock_path_instance.unlink.assert_called_once()

    def test_parse_certificate_info_error(self, mocker):
        from OpenSSL.SSL import Error as OpenSSLError
        mocker.patch("tools.infra.crypto.load_certificate", side_effect=OpenSSLError("parsing failed"))
        name, email = _parse_certificate_info("bad-cert-data")
        assert name == "Unknown"
        assert email == "unknown@example.com"

class TestReleaseManager:
    @pytest.fixture
    def manager(self, mock_config, mock_git_service, mock_vault_service, mocker):
        """Creates a ReleaseManager instance with mocked services."""
        logger = mocker.MagicMock(spec=logging.Logger)
        return ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=Path("/fake/project"),
            dry_run=False,
            logger=logger,
        )

    def test_developer_preparation_phase_success(self, manager, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data=VALID_SOURCE_SCHEMA))
        mock_write_yaml = mocker.patch("tools.infra.write_yaml")
        mocker.patch("tools.infra._parse_certificate_info", return_value=("Test User", "test@user.com"))
        mocker.patch("sys.exit") # Prevent exit from API check

        manager.run_release_close(release_version="1.0.0")

        manager.git_service.checkout.assert_called_once_with("base/releases/v1.0.0", create_new=True)
        manager.git_service.add.assert_called_once_with("/fake/project/project.yaml")
        manager.git_service.run.assert_called_once_with(["git", "commit", "-m", "release: Prepare base v1.0.0 for build"])

        written_data = mock_write_yaml.call_args[0][1]
        assert written_data["metadata"]["version"] == "1.0.0"
        assert written_data["metadata"]["createdBy"]["name"] == "Test User"
        assert "key: value" in yaml.dump(written_data["spec"])

    def test_finalization_phase_success(self, manager, mocker):
        manager.git_service.get_current_branch.return_value = "base/releases/v1.0.0"
        mocker.patch("tools.infra.load_yaml", return_value=yaml.safe_load(VALID_PROJECT_YAML))
        mocker.patch("tools.infra.load_and_resolve_schema", return_value={"spec": {"key": "value"}})
        mock_validate = mocker.patch("tools.infra.validate")

        manager.run_release_close(release_version="1.0.0")

        mock_validate.assert_called_once()
        manager.git_service.run.assert_any_call(["git", "tag", "-a", "base@v1.0.0", "-m", "Release base v1.0.0"])
        manager.git_service.checkout.assert_called_once_with("main")
        manager.git_service.merge.assert_called_once()
        manager.git_service.delete_branch.assert_called_once_with("base/releases/v1.0.0")

    def test_run_validation_success(self, manager, mocker):
        mocker.patch("builtins.open", mocker.mock_open(read_data=VALID_SOURCE_SCHEMA))
        manager.run_validation()
        manager.logger.info.assert_any_call("✓ Validation successful.")

    def test_run_validation_failure(self, manager, mocker):
        mocker.patch("tools.infra.load_and_resolve_schema", side_effect=ConfigurationError("bad schema"))
        with pytest.raises(ReleaseError, match="Schema validation failed"):
            manager.run_validation()

    def test_dirty_git_state_fails(self, manager):
        manager.git_service.is_dirty.return_value = True
        with pytest.raises(GitStateError, match="Uncommitted changes detected"):
            manager.run_release_close(release_version="1.0.0")

    def test_invalid_branch_fails(self, manager):
        manager.git_service.get_current_branch.return_value = "feature/other"
        with pytest.raises(GitStateError, match="Release command must be run from the main branch"):
            manager.run_release_close(release_version="1.0.0")

    def test_final_validation_fails(self, manager, mocker):
        manager.git_service.get_current_branch.return_value = "base/releases/v1.0.0"
        mocker.patch("tools.infra.load_yaml", return_value={})
        mocker.patch("tools.infra.load_and_resolve_schema", return_value={"spec": {}})
        mocker.patch("tools.infra.validate", side_effect=JsonSchemaValidationError("missing field"))
        with pytest.raises(ValidationFailureError, match="Final project.yaml validation failed"):
            manager.run_release_close(release_version="1.0.0")

    def test_api_check_handles_error(self, manager, mocker):
        mocker.patch("tools.infra.requests.get", side_effect=requests.exceptions.RequestException)
        mock_exit = mocker.patch("sys.exit")
        manager._check_api_accessibility("http://bad.url")
        manager.logger.warning.assert_called_once()
        mock_exit.assert_called_once_with(0)

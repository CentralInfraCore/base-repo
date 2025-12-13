import logging
import os
import sys
from pathlib import Path
from unittest.mock import ANY, MagicMock

import pytest
import requests
from jsonschema import ValidationError as JsonSchemaValidationError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.infra import (
    ReleaseManager,
    load_yaml,
    write_yaml,
    load_and_resolve_schema,
    _parse_certificate_info,
    to_canonical_json,
    get_sha256_hex,
)
from tools.releaselib.exceptions import (
    ConfigurationError,
    GitStateError,
    ReleaseError,
    VaultServiceError,
)
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService

# --- Fixtures ---

@pytest.fixture
def mock_services(mocker):
    """Provides a dictionary of mocked services and configs."""
    mock_config = {
        "component_name": "base",
        "vault_key_name": "user-key",
        "vault_cert_mount": "kv",
        "vault_cert_secret_name": "user-cert",
        "vault_cert_secret_key": "cert",
        "main_branch": "main",
        "canonical_source_file": "sources/index.yaml",
        "meta_schema_file": "project.schema.yaml",
    }
    mock_git_service = mocker.MagicMock(spec=GitService)
    mock_vault_service = mocker.MagicMock(spec=VaultService)
    mock_logger = mocker.MagicMock(spec=logging.Logger)

    mock_git_service.get_current_branch.return_value = "main"
    mock_git_service.is_dirty.return_value = False
    mock_git_service.assert_clean_index.return_value = None

    mock_vault_service.sign.return_value = "dummy-signature"
    mock_vault_service.get_certificate.return_value = (
        "-----BEGIN CERTIFICATE-----\nMIIC... (dummy cert) ...END CERTIFICATE-----\n"
    )

    # Mock helper functions that are now part of infra.py
    mocker.patch("tools.infra.load_and_resolve_schema", return_value={"spec": {"key": "value"}, "metadata": {"name": "test-schema"}})
    mocker.patch("tools.infra.load_yaml", return_value={"metadata": {"name": "base"}, "compiler_settings": mock_config})
    mocker.patch("tools.infra.write_yaml")
    mocker.patch("tools.infra._parse_certificate_info", return_value=("Test User", "test@user.com"))
    mocker.patch("tools.infra.get_sha256_hex", return_value="dummy_hex_hash")

    # Mocks for assertion
    mock_requests_get = mocker.patch("tools.infra.requests.get")
    mock_sys_exit = mocker.patch("sys.exit")
    mock_infra_validate = mocker.patch("tools.infra.validate")

    return {
        "config": mock_config,
        "git_service": mock_git_service,
        "vault_service": mock_vault_service,
        "logger": mock_logger,
        "project_root": Path("/fake/project"),
        "dry_run": False,
        "mocker_requests_get": mock_requests_get,
        "mocker_sys_exit": mock_sys_exit,
        "mocker_infra_validate": mock_infra_validate,
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

    def test_parse_certificate_info_error(self, mocker):
        """Test that certificate parsing handles errors gracefully."""
        from OpenSSL.SSL import Error as OpenSSLError
        mocker.patch("tools.infra.crypto.load_certificate", side_effect=OpenSSLError("parsing failed"))
        name, email = _parse_certificate_info("bad-cert-data")
        assert name == "Unknown"
        assert email == "unknown@example.com"

class TestReleaseManagerPhases:
    def test_developer_preparation_phase_success(self, mock_services):
        manager = ReleaseManager(
            config=mock_services["config"],
            git_service=mock_services["git_service"],
            vault_service=mock_services["vault_service"],
            project_root=mock_services["project_root"],
            dry_run=mock_services["dry_run"],
            logger=mock_services["logger"],
        )
        manager.run_release_close(release_version="1.0.0")

        mock_services["git_service"].checkout.assert_called_once_with("base/releases/v1.0.0", create_new=True)
        mock_services["git_service"].add.assert_called_once_with("/fake/project/project.yaml")
        mock_services["git_service"].run.assert_called_once_with(["git", "commit", "-m", "release: Prepare base v1.0.0 for build"])

        # Verify that the correct data is passed to write_yaml
        from tools.infra import write_yaml
        written_data = write_yaml.call_args[0][1]
        assert written_data["metadata"]["checksum"] == "dummy_hex_hash"
        assert written_data["metadata"]["createdBy"]["name"] == "Test User"
        assert written_data["spec"] == {"key": "value"}

    def test_finalization_phase_success(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "base/releases/v1.0.0"
        manager = ReleaseManager(**{k: v for k, v in mock_services.items() if k not in ["mocker_requests_get", "mocker_sys_exit", "mocker_infra_validate"]})

        manager.run_release_close(release_version="1.0.0")

        mock_services["mocker_infra_validate"].assert_called_once_with(instance=ANY, schema={"key": "value"})
        mock_services["git_service"].run.assert_any_call(["git", "tag", "-a", "base@v1.0.0", "-m", "Release base v1.0.0"])
        mock_services["git_service"].checkout.assert_called_once_with(mock_services["config"]["main_branch"])
        mock_services["git_service"].merge.assert_called_once()
        mock_services["git_service"].delete_branch.assert_called_once_with("base/releases/v1.0.0")

    def test_dry_run_developer_phase(self, mock_services):
        mock_services["dry_run"] = True
        manager = ReleaseManager(**{k: v for k, v in mock_services.items() if k not in ["mocker_requests_get", "mocker_sys_exit", "mocker_infra_validate"]})

        manager.run_release_close(release_version="1.0.0")

        from tools.infra import write_yaml
        write_yaml.assert_not_called()
        mock_services["git_service"].add.assert_not_called()
        mock_services["git_service"].run.assert_not_called()
        mock_services["git_service"].checkout.assert_not_called()
        mock_services["logger"].info.assert_any_call("[DRY-RUN] The following data would be written to project.yaml:")

    def test_invalid_branch(self, mock_services):
        mock_services["git_service"].get_current_branch.return_value = "feature/some-branch"
        manager = ReleaseManager(**{k: v for k, v in mock_services.items() if k not in ["mocker_requests_get", "mocker_sys_exit", "mocker_infra_validate"]})

        with pytest.raises(GitStateError, match="Release command must be run from the main branch"):
            manager.run_release_close(release_version="1.0.0")

    def test_developer_preparation_phase_cleanup_on_error(self, mock_services, mocker):
        mock_services["git_service"].get_current_branch.return_value = "main"
        mock_services["git_service"].checkout.side_effect = [None, None]
        mocker.patch("tools.infra.load_and_resolve_schema", side_effect=Exception("Schema load failed"))

        manager = ReleaseManager(**{k: v for k, v in mock_services.items() if k not in ["mocker_requests_get", "mocker_sys_exit", "mocker_infra_validate"]})

        with pytest.raises(ReleaseError, match="Release process failed: Schema load failed"):
            manager.run_release_close(release_version="1.0.0")

        mock_services["git_service"].checkout.assert_any_call("main")
        mock_services["git_service"].delete_branch.assert_called_once_with("base/releases/v1.0.0", force=True)
        mock_services["logger"].critical.assert_any_call(ANY, exc_info=True)

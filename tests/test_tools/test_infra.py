import base64
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from jsonschema import ValidationError as JsonSchemaValidationError

# Import specific functions/classes from their new locations
from tools.infra import (ReleaseManager, ValidationFailureError,
                         get_reproducible_repo_hash, load_yaml, write_yaml)
from tools.releaselib.exceptions import (ConfigurationError, GitStateError,
                                         ReleaseError, VaultServiceError,
                                         VersionMismatchError)
from tools.releaselib.git_service import GitService
from tools.releaselib.vault_service import VaultService

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
        },
    },
    "spec": {"type": "object", "properties": {"field1": {"type": "string"}}},
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
        },
    },
    "spec": {"type": "object", "properties": {"field1": {"type": "string"}}},
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
    mock_config = {
        "meta_schema_file": "meta.yaml",
        "meta_schemas_dir": "schemas",
        "component_name": "base",
        "vault_key_name": "cic-my-sign-key",
    }
    mock_git_service = mocker.MagicMock(spec=GitService)
    mock_vault_service = mocker.MagicMock(spec=VaultService)
    mock_logger = mocker.MagicMock()

    mock_project_root = mocker.MagicMock(spec=Path)
    mock_project_root.resolve.return_value = mock_project_root
    mock_project_root.exists.return_value = True

    path_mocks = {}

    def mock_truediv(other):
        path_key = str(other)
        if path_key not in path_mocks:
            result_path_mock = mocker.MagicMock(spec=Path)
            result_path_mock.name = path_key
            result_path_mock.resolve.return_value = result_path_mock
            path_mocks[path_key] = result_path_mock

            if path_key == "project.yaml":
                result_path_mock.exists.return_value = True
                result_path_mock.read_text.return_value = (
                    "compiler_settings:\n  component_name: base\nrelease: {}"
                )
            elif path_key == mock_config["meta_schema_file"]:
                result_path_mock.exists.return_value = True
            else:
                result_path_mock.exists.return_value = False
                result_path_mock.read_text.side_effect = FileNotFoundError

        return path_mocks[path_key]

    mock_project_root.__truediv__.side_effect = mock_truediv
    mock_project_root.glob.return_value = []

    return (
        mock_config,
        mock_git_service,
        mock_vault_service,
        mock_logger,
        mock_project_root,
    )


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
        yaml_path = tmp_path / "empty.yaml"
        yaml_path.write_text("")
        assert load_yaml(yaml_path) is None


class TestRunValidation:
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

        mocker.patch(
            "tools.infra.load_yaml", side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA]
        )
        mocker.patch("tools.infra.validate", return_value=None)

        try:
            manager.run_validation()
        except Exception as e:
            pytest.fail(f"An unexpected error occurred during validation: {e}")

    def test_meta_schema_load_failure(self, mocker, mock_release_manager_deps):
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
        mocker.patch(
            "tools.infra.load_yaml", side_effect=ConfigurationError("File not found")
        )
        with pytest.raises(ConfigurationError):
            manager.run_validation()

    def test_empty_meta_schema(self, mocker, mock_release_manager_deps):
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
        mocker.patch("tools.infra.load_yaml", return_value=None)
        with pytest.raises(ConfigurationError, match="Meta-schema file .* is empty"):
            manager.run_validation()

    def test_schema_validation_failure(self, mocker, mock_release_manager_deps):
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

        mocker.patch(
            "tools.infra.load_yaml", side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA]
        )
        mocker.patch(
            "tools.infra.validate",
            side_effect=JsonSchemaValidationError("Schema invalid"),
        )

        with pytest.raises(ValidationFailureError):
            manager.run_validation()

    def test_unexpected_error_in_validation(self, mocker, mock_release_manager_deps):
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
        mock_project_root.glob.return_value = [mock_schema_file]
        mocker.patch(
            "tools.infra.load_yaml",
            side_effect=[{"type": "object"}, Exception("Unexpected error")],
        )

        with pytest.raises(ValidationFailureError, match="Unexpected Error"):
            manager.run_validation()

    def test_validation_skips_meta_schema(self, mocker, mock_release_manager_deps):
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

        meta_schema_path = mock_project_root / mock_config["meta_schema_file"]
        other_schema_path = mocker.MagicMock(spec=Path, name="other.yaml")
        other_schema_path.resolve.return_value = Path("resolved/other.yaml")

        mock_project_root.glob.return_value = [meta_schema_path, other_schema_path]

        mock_load_yaml = mocker.patch(
            "tools.infra.load_yaml", side_effect=[{"type": "object"}, DUMMY_SCHEMA_DATA]
        )
        mock_validate = mocker.patch("tools.infra.validate")

        manager.run_validation()

        assert mock_load_yaml.call_count == 2
        mock_validate.assert_called_once()


class TestRunReleaseCheck:
    def test_missing_component_name(self, mock_release_manager_deps):
        (
            mock_config,
            mock_git_service,
            mock_vault_service,
            mock_logger,
            mock_project_root,
        ) = mock_release_manager_deps
        del mock_config["component_name"]
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger,
        )
        with pytest.raises(ConfigurationError, match="Missing 'component_name'"):
            manager.run_release_check("1.0.0")

    def test_dirty_working_directory(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = "M some_file.txt"
        with pytest.raises(GitStateError, match="Uncommitted changes detected"):
            manager.run_release_check("1.0.0")

    def test_invalid_base_branch(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "feature/new-thing"
        with pytest.raises(GitStateError, match="Not on a valid base branch"):
            manager.run_release_check("1.0.0")

    def test_invalid_version_string(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        with pytest.raises(VersionMismatchError, match="Invalid version string"):
            manager.run_release_check(release_version="not-a-version")

    def test_malformed_existing_tag(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = ["base@v1.0.0", "base@v-invalid"]

        manager.run_release_check(release_version="1.0.1")
        mock_logger.warning.assert_called_with(
            "Skipping malformed tag 'base@v-invalid' during version comparison."
        )

    def test_not_a_valid_version_increment(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.get_tags.return_value = ["base@v1.0.0"]
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="1.0.0")
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="0.9.0")
        with pytest.raises(VersionMismatchError, match="is not a valid increment"):
            manager.run_release_check(release_version="1.1.1")


class TestRunReleaseClose:
    @pytest.fixture(autouse=True)
    def setup_release_mocks(self, mocker):
        mocker.patch("tools.infra.datetime.datetime", FixedDateTime)
        mocker.patch(
            "tools.infra.get_reproducible_repo_hash", return_value="dummy_digest_b64"
        )
        mocker.patch("tools.infra.write_yaml")
        mocker.patch(
            "tools.infra.load_yaml",
            return_value={"compiler_settings": {"component_name": "base"}},
        )

    def test_no_vault_service(self, mock_release_manager_deps):
        mock_config, mock_git_service, _, mock_logger, mock_project_root = (
            mock_release_manager_deps
        )
        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=None,
            project_root=mock_project_root,
            logger=mock_logger,
        )
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        with pytest.raises(VaultServiceError, match="VaultService is not initialized"):
            manager.run_release_close(release_version="0.5.0")

    def test_vault_signing_failure(self, mock_release_manager_deps):
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
        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.side_effect = VaultServiceError("Vault is down")

        with pytest.raises(ReleaseError, match="Release process failed: Vault is down"):
            manager.run_release_close(release_version="0.5.0")

    def test_rollback_on_failure(self, mock_release_manager_deps):
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

        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = "signed_hash"
        mock_git_service.run.side_effect = GitStateError("Commit failed")

        with pytest.raises(ReleaseError, match="Commit failed"):
            manager.run_release_close(release_version="1.0.1")

        mock_git_service.checkout.assert_called_with("main")
        mock_git_service.delete_branch.assert_called_with(
            "base/releases/v1.0.1", force=True
        )
        mock_logger.info.assert_any_call("✓ project.yaml restored to original state.")

    def test_rollback_for_new_project_yaml(self, mock_release_manager_deps):
        (
            mock_config,
            mock_git_service,
            mock_vault_service,
            mock_logger,
            mock_project_root,
        ) = mock_release_manager_deps

        project_yaml_path_mock = mock_project_root / "project.yaml"
        project_yaml_path_mock.exists.side_effect = [False, True, True]
        project_yaml_path_mock.read_text.side_effect = FileNotFoundError

        manager = ReleaseManager(
            config=mock_config,
            git_service=mock_git_service,
            vault_service=mock_vault_service,
            project_root=mock_project_root,
            logger=mock_logger,
        )

        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = "signed_hash"
        mock_git_service.run.side_effect = GitStateError("Commit failed")

        with pytest.raises(ReleaseError, match="Commit failed"):
            manager.run_release_close(release_version="1.0.1")

        project_yaml_path_mock.unlink.assert_called_once()
        mock_logger.info.assert_any_call("✓ Newly created project.yaml removed.")

    def test_rollback_fails_on_yaml_parse(self, mocker, mock_release_manager_deps):
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

        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.run.side_effect = GitStateError("Commit failed")
        mocker.patch("yaml.safe_load", side_effect=yaml.YAMLError("Bad YAML"))

        with pytest.raises(ReleaseError, match="Commit failed"):
            manager.run_release_close(release_version="1.0.1")

        mock_logger.critical.assert_any_call(mocker.ANY, exc_info=True)

    def test_dry_run_mode(self, mock_release_manager_deps):
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
            dry_run=True,
            logger=mock_logger,
        )

        mock_git_service.get_status_porcelain.return_value = ""
        mock_git_service.get_current_branch.return_value = "main"
        mock_git_service.write_tree.return_value = "dummy_tree_id"
        mock_vault_service.sign.return_value = "signed_hash"

        manager.run_release_close(release_version="1.0.1")

        mock_logger.info.assert_any_call(
            "[DRY-RUN] Would have created branch 'base/releases/v1.0.1' and checked it out."
        )
        mock_logger.info.assert_any_call(
            "[DRY-RUN] Would have committed with message: 'release: base v1.0.1'"
        )
        mock_git_service.run.assert_not_called()
        mock_git_service.checkout.assert_not_called()


class TestHelperFunctions:
    def test_write_yaml(self, tmp_path):
        test_file = tmp_path / "test_output.yaml"
        test_data = {"key1": "value1"}
        write_yaml(test_file, test_data)
        assert test_file.exists()
        loaded_data = yaml.safe_load(test_file.read_text())
        assert loaded_data == test_data

    def test_write_yaml_io_error(self, mocker):
        mocker.patch("tempfile.NamedTemporaryFile", side_effect=IOError("Disk full"))
        with pytest.raises(ReleaseError, match="Failed to write YAML file"):
            write_yaml(Path("any/path.yaml"), {})

    def test_write_yaml_cleanup_error(self, mocker):
        mock_tmp_file = mocker.MagicMock()
        mock_tmp_file.name = "dummy_temp_file"
        mock_tmp_file_cm = mocker.MagicMock()
        mock_tmp_file_cm.__enter__.return_value = mock_tmp_file
        mock_tmp_file_cm.__exit__.return_value = None
        mocker.patch("tempfile.NamedTemporaryFile", return_value=mock_tmp_file_cm)

        mocker.patch("os.replace", side_effect=Exception("os.replace failed"))

        mocker.patch("pathlib.Path.exists", return_value=True)
        mocker.patch("pathlib.Path.unlink", side_effect=OSError("unlink failed"))

        mock_logger = mocker.patch("logging.getLogger")

        with pytest.raises(ReleaseError, match="os.replace failed"):
            write_yaml(Path("any/path.yaml"), {})

        mock_logger().warning.assert_called_once_with(
            "Failed to clean up temporary file dummy_temp_file: unlink failed"
        )

    def test_get_reproducible_repo_hash_success(self, mocker):
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_archive_bytes = b"dummy_archive_bytes"
        mock_git_service.archive_tree_bytes.return_value = mock_archive_bytes

        hasher = hashlib.sha256()
        hasher.update(mock_archive_bytes)
        expected_hash_bytes = hasher.digest()
        expected_b64_hash = base64.b64encode(expected_hash_bytes).decode("utf-8")

        result = get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")
        assert result == expected_b64_hash
        mock_git_service.archive_tree_bytes.assert_called_once_with(
            "dummy_tree_id", prefix="./"
        )

    def test_get_reproducible_repo_hash_error(self, mocker):
        mock_git_service = mocker.MagicMock(spec=GitService)
        mock_git_service.archive_tree_bytes.side_effect = Exception("Git error")
        with pytest.raises(
            ReleaseError, match="Error during repo hash calculation: Git error"
        ):
            get_reproducible_repo_hash(mock_git_service, "dummy_tree_id")

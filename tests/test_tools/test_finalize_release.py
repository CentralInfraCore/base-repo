import logging
import sys
from pathlib import Path
from unittest.mock import ANY, MagicMock

import pytest

# Add project root to sys.path to allow importing 'tools'
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tools import finalize_release
from tools.releaselib.exceptions import VaultServiceError

# --- Fixtures ---

@pytest.fixture
def mock_args(mocker):
    """Fixture to mock argparse arguments with MagicMocks for paths."""
    args = MagicMock()
    
    # Mock filepath
    args.filepath = MagicMock(spec=Path)
    args.filepath.exists.return_value = True
    args.filepath.__str__.return_value = "project.yaml"

    # Mock cert_file
    args.cic_cert_file = MagicMock(spec=Path)
    args.cic_cert_file.exists.return_value = True
    args.cic_cert_file.__str__.return_value = "ca.crt"

    args.cic_vault_key = "test-key"
    args.cic_cert_vault_path = None
    args.dry_run = False
    args.verbose = False
    args.debug = False
    
    mocker.patch("argparse.ArgumentParser.parse_args", return_value=args)
    return args

@pytest.fixture
def mock_env(mocker):
    """Fixture to mock environment variables."""
    mocker.patch("os.getenv", side_effect=lambda var: {
        "VAULT_ADDR": "https://fake-vault.com",
        "VAULT_TOKEN": "fake-token",
    }.get(var))

@pytest.fixture
def mock_vault(mocker):
    """Fixture to mock the VaultService."""
    mock_vault_instance = MagicMock()
    mock_vault_instance.sign.return_value = "vault:v1:signed-hash"
    mock_vault_instance.get_certificate.return_value = "-----BEGIN CERT-----\nVAULT-CERT\n-----END CERT-----"
    mocker.patch("tools.finalize_release.VaultService", return_value=mock_vault_instance)
    return mock_vault_instance

@pytest.fixture
def mock_sys_exit(mocker):
    """Fixture to mock sys.exit to prevent test termination."""
    return mocker.patch("sys.exit")

@pytest.fixture(autouse=True)
def mock_logging(mocker):
    """Fixture to mock the setup_logging function to not interfere with caplog."""
    mock_logger = logging.getLogger(finalize_release.__name__)
    mocker.patch("tools.finalize_release.setup_logging", return_value=mock_logger)
    return mock_logger

@pytest.fixture
def mock_yaml_ops(mocker):
    """Fixture to mock yaml loading and writing."""
    mocker.patch("tools.finalize_release.load_yaml", return_value={
        "metadata": {"checksum": "dummy-hash", "buildHash": "dummy-hash"}
    })
    m_write = mocker.patch("tools.finalize_release.write_yaml")
    return m_write

# --- Test Class ---

class TestFinalizeRelease:
    """Test suite for the finalize_release.py script."""

    def test_main_success_with_cert_file(self, mock_args, mock_env, mock_yaml_ops, mock_vault, mocker):
        """Tests the successful execution path using a certificate file."""
        cert_content = "-----BEGIN CERT-----\nFILE-CERT\n-----END CERT-----"
        mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=cert_content))

        finalize_release.main()

        mock_open.assert_called_once_with(mock_args.cic_cert_file, 'r', encoding='utf-8')
        
        final_data = mock_yaml_ops.call_args[0][1]
        assert final_data["metadata"]["cicSignedCA"]["certificate"] == cert_content
        assert final_data["metadata"]["cicSign"] == "vault:v1:signed-hash"
        mock_yaml_ops.assert_called_once_with(mock_args.filepath, ANY)

    def test_main_success_with_vault_path(self, mock_args, mock_env, mock_yaml_ops, mock_vault):
        """Tests the successful execution path using a Vault path for the certificate."""
        mock_args.cic_cert_file = None
        mock_args.cic_cert_vault_path = "kv/data/secrets/my-cert:cert_key"

        finalize_release.main()

        mock_vault.get_certificate.assert_called_once_with("kv/data", "secrets/my-cert", "cert_key")
        final_data = mock_yaml_ops.call_args[0][1]
        assert final_data["metadata"]["cicSignedCA"]["certificate"] == mock_vault.get_certificate.return_value
        mock_yaml_ops.assert_called_once_with(mock_args.filepath, ANY)

    def test_main_dry_run(self, mock_args, mock_env, mock_yaml_ops, mock_vault, capsys, caplog, mocker):
        """Tests that --dry-run prevents writing the file and prints to stdout."""
        mock_args.dry_run = True
        mocker.patch("builtins.open", mocker.mock_open(read_data="cert-data"))
        caplog.set_level(logging.INFO) # Set level to capture INFO messages

        finalize_release.main()

        mock_yaml_ops.assert_not_called()
        
        assert "--- DRY-RUN: Final YAML content ---" in caplog.text
        
        captured = capsys.readouterr()
        assert "buildHash: dummy-hash" in captured.out

    def test_error_filepath_not_found(self, mock_args, mock_env, mock_sys_exit, caplog):
        """Tests failure when the main project.yaml file is not found."""
        mock_args.filepath.exists.return_value = False
        
        finalize_release.main()

        assert "[FAILURE] The finalization process failed: The specified file was not found" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_cert_file_not_found(self, mock_args, mock_env, mock_sys_exit, caplog):
        """Tests failure when the certificate file is not found."""
        mock_args.cic_cert_file.exists.return_value = False

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: The CIC certificate file was not found" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_checksum_mismatch(self, mock_args, mock_env, mock_sys_exit, caplog, mocker):
        """Tests failure when checksum and buildHash do not match."""
        mocker.patch("tools.finalize_release.load_yaml", return_value={
            "metadata": {"checksum": "dummy-hash", "buildHash": "different-hash"}
        })

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: Validation failed: 'checksum' and 'buildHash' do not match!" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_no_metadata_block(self, mock_args, mock_env, mock_sys_exit, caplog, mocker):
        """Tests failure when the metadata block is missing from the YAML."""
        mocker.patch("tools.finalize_release.load_yaml", return_value={"other_data": "value"})

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: The 'metadata' block was not found" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_vault_signing_fails(self, mock_args, mock_env, mock_yaml_ops, mock_vault, mock_sys_exit, caplog, mocker):
        """Tests failure when the Vault signing operation fails."""
        mocker.patch("builtins.open", mocker.mock_open(read_data="cert-data"))
        mock_vault.sign.side_effect = VaultServiceError("Vault signing failed")

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: Vault signing failed" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_vault_cert_fetch_fails(self, mock_args, mock_env, mock_yaml_ops, mock_vault, mock_sys_exit, caplog):
        """Tests failure when fetching the certificate from Vault fails."""
        mock_args.cic_cert_file = None
        mock_args.cic_cert_vault_path = "kv/data/secrets/my-cert:cert_key"
        mock_vault.get_certificate.side_effect = VaultServiceError("Vault fetch failed")

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: Could not retrieve certificate from Vault: Vault fetch failed" in caplog.text
        mock_sys_exit.assert_called_once_with(1)
        
    def test_error_invalid_vault_path_format(self, mock_args, mock_env, mock_yaml_ops, mock_vault, mock_sys_exit, caplog):
        """Tests failure for invalid Vault path format."""
        mock_args.cic_cert_file = None
        mock_args.cic_cert_vault_path = "invalid-path-format" # Missing ':'

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: Could not retrieve certificate from Vault: Vault path must be in the format 'mount/path/to/secret:key'" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_error_missing_env_vars(self, mock_args, mock_sys_exit, caplog, mocker):
        """Tests failure when VAULT_ADDR or VAULT_TOKEN are not set."""
        mocker.patch("os.getenv", side_effect=lambda var: {"VAULT_ADDR": "https://fake-vault.com"}.get(var))

        finalize_release.main()

        assert "[FAILURE] The finalization process failed: VAULT_ADDR and VAULT_TOKEN environment variables must be set" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

    def test_unexpected_error_handling(self, mock_args, mock_env, mock_sys_exit, caplog, mocker):
        """Tests the generic exception handler."""
        mocker.patch("tools.finalize_release.load_yaml", side_effect=Exception("Unexpected boom!"))

        finalize_release.main()

        assert "[UNEXPECTED ERROR] An unhandled exception occurred: Unexpected boom!" in caplog.text
        mock_sys_exit.assert_called_once_with(1)

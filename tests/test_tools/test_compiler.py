import logging
import os
import sys
from unittest.mock import mock_open

import pytest

# Project root: /app
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Always put the project root at the beginning of sys.path
if PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from tools.compiler import ColoredFormatter  # noqa: E402
from tools.compiler import load_project_config, main, setup_logging # noqa: E402
from tools.releaselib.exceptions import ReleaseError  # noqa: E402


@pytest.fixture(autouse=True)
def mock_env(mocker):
    """Auto-mock environment and services for all tests in this module."""
    mocker.patch("tools.compiler.load_project_config", return_value={"some": "config"})
    mocker.patch(
        "tools.compiler.setup_logging", return_value=logging.getLogger("test_logger")
    )
    mocker.patch("tools.compiler.GitService")
    mocker.patch("tools.compiler.VaultService")
    mocker.patch.object(os, "getenv", return_value=None)
    mocker.patch("os.path.exists", return_value=False)


class TestMainCLI:
    def test_no_arguments(self, mocker):
        """Test that main exits with code 2 if no arguments are provided."""
        mocker.patch.object(sys, "argv", ["compiler.py"])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_unknown_command(self, mocker):
        """Test that main exits with code 2 if an unknown command is provided."""
        mocker.patch.object(sys, "argv", ["compiler.py", "unknown_command"])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_validate_command_success(self, mocker):
        """Test the 'validate' command success case."""
        mocker.patch.object(sys, "argv", ["compiler.py", "validate"])
        mock_release_manager_class = mocker.patch("tools.compiler.ReleaseManager")
        mock_rm_instance = mock_release_manager_class.return_value

        main()

        mock_release_manager_class.assert_called_once()
        mock_rm_instance.run_validation.assert_called_once()
        mock_rm_instance.run_release_check.assert_not_called()
        mock_rm_instance.run_release_close.assert_not_called()

    def test_release_command_requires_version(self, mocker):
        """Test that the 'release' command exits if --version is not provided."""
        mocker.patch.object(sys, "argv", ["compiler.py", "release"])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_release_command_success(self, mocker):
        """Test the 'release' command success case."""
        mocker.patch.object(
            sys, "argv", ["compiler.py", "release", "--version", "1.2.3"]
        )
        mock_release_manager_class = mocker.patch("tools.compiler.ReleaseManager")
        mock_rm_instance = mock_release_manager_class.return_value
        mock_rm_instance.run_release_check.return_value = ("main", "main")
        mock_rm_instance.run_release_close.return_value = ("1.2.3", "main")

        main()

        mock_release_manager_class.assert_called_once()
        mock_rm_instance.run_validation.assert_called_once()
        mock_rm_instance.run_release_check.assert_called_once_with(
            release_version="1.2.3"
        )
        mock_rm_instance.run_release_close.assert_called_once_with(
            release_version="1.2.3"
        )

    def test_release_command_with_vault_files(self, mocker):
        """Test 'release' command reads Vault token and CA from files."""
        mocker.patch.object(
            sys, "argv", ["compiler.py", "release", "--version", "1.2.3"]
        )
        mock_release_manager_class = mocker.patch("tools.compiler.ReleaseManager")
        mock_rm_instance = mock_release_manager_class.return_value
        # FIX: Add missing mocks for ReleaseManager methods
        mock_rm_instance.run_release_check.return_value = ("main", "main")
        mock_rm_instance.run_release_close.return_value = ("1.2.3", "main")

        mock_vault_service = mocker.patch("tools.compiler.VaultService")

        mocker.patch(
            "os.path.exists",
            side_effect=lambda path: path
            in ["/var/run/secrets/vault-token", "/var/run/secrets/vault-ca.crt"],
        )
        mocker.patch("builtins.open", mock_open(read_data="file-token"))

        main()

        args, kwargs = mock_vault_service.call_args
        assert kwargs.get("vault_token") == "file-token"
        assert kwargs.get("vault_cacert") == "/var/run/secrets/vault-ca.crt"

    def test_main_handles_release_error(self, mocker):
        """Test that main catches ReleaseError and exits with 1."""
        mocker.patch.object(sys, "argv", ["compiler.py", "validate"])
        mock_release_manager_class = mocker.patch("tools.compiler.ReleaseManager")
        mock_rm_instance = mock_release_manager_class.return_value
        mock_rm_instance.run_validation.side_effect = ReleaseError("Test error")

        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1

    def test_main_handles_unexpected_error(self, mocker):
        """Test that main catches generic exceptions and exits with 1."""
        mocker.patch.object(sys, "argv", ["compiler.py", "validate"])
        mocker.patch(
            "tools.compiler.load_project_config", side_effect=Exception("Unexpected")
        )

        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1

    def test_main_entrypoint_call(self, mocker):
        """Test that calling main with valid args completes successfully."""
        # FIX: Replace brittle `__main__` guard test with a simple, effective test of the main function.
        mocker.patch.object(sys, "argv", ["compiler.py", "validate"])
        mock_rm_class = mocker.patch("tools.compiler.ReleaseManager")

        try:
            main()
        except SystemExit as e:
            pytest.fail(f"main() exited unexpectedly with code {e.code}")

        mock_rm_class.assert_called_once()


class TestConfigLoader:
    @pytest.fixture(autouse=False)  # Disable autouse fixture for this class
    def mock_env(self, mocker):
        # This class tests load_project_config, so we don't want to mock it globally.
        pass

    def test_load_project_config_io_error(self, mocker):
        """Test load_project_config exits on IOError."""
        mocker.patch("builtins.open", side_effect=IOError("File not found"))
        with pytest.raises(SystemExit) as excinfo:
            load_project_config()
        assert excinfo.value.code == 1

    def test_load_project_config_key_error(self, mocker):
        """Test load_project_config exits on KeyError."""
        mocker.patch("builtins.open", mock_open(read_data="{}"))
        mocker.patch("yaml.safe_load", return_value={})  # Missing 'compiler_settings'
        with pytest.raises(SystemExit) as excinfo:
            load_project_config()
        assert excinfo.value.code == 1


class TestLogging:
    @pytest.fixture(autouse=True)
    def unpatch_logging(self, mocker):
        """Fixture to undo the global logging mock for this test class."""
        mocker.stopall()

    def test_setup_logging_levels(self):
        """Test that logging level is set correctly."""
        logger = logging.getLogger("tools.compiler")
        logger.handlers = []
        handler = setup_logging(verbose=True).handlers[0]
        assert handler.level == logging.INFO
        logger.handlers = []
        handler = setup_logging(debug=True).handlers[0]
        assert handler.level == logging.DEBUG
        logger.handlers = []
        handler = setup_logging().handlers[0]
        assert handler.level == logging.WARNING
        logger.handlers = []

    def test_colored_formatter(self):
        """Test the ColoredFormatter applies the correct colors."""
        formatter = ColoredFormatter("%(message)s")

        # DRY-RUN
        dry_run_record = logging.LogRecord(
            "test", logging.INFO, "", 0, "DRY-RUN: test", None, None
        )
        assert "\033[96m" in formatter.format(dry_run_record)

        # SUCCESS
        success_record = logging.LogRecord(
            "test", logging.INFO, "", 0, "✓ Success", None, None
        )
        assert "\033[92m" in formatter.format(success_record)

        # ERROR
        error_record = logging.LogRecord(
            "test", logging.ERROR, "", 0, "Error message", None, None
        )
        assert "\033[91m" in formatter.format(error_record)

        # REGULAR INFO
        info_record = logging.LogRecord(
            "test", logging.INFO, "", 0, "Info message", None, None
        )
        formatted_msg = formatter.format(info_record)
        assert "\033[0m" in formatted_msg
        assert "\033[96m" not in formatted_msg
        assert "\033[92m" not in formatted_msg

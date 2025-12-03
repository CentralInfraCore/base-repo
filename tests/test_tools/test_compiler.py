import pytest
import sys
import os
import logging

# Project root: /app
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))

# Always put the project root at the beginning of sys.path
if PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from tools.compiler import main, setup_logging, ColoredFormatter
from tools.releaselib.exceptions import ReleaseError


@pytest.fixture(autouse=True)
def mock_env(mocker):
    """Auto-mock environment and services for all tests in this module."""
    mocker.patch('tools.compiler.load_project_config', return_value={'some': 'config'})
    mocker.patch('tools.compiler.setup_logging', return_value=logging.getLogger('test_logger'))
    mocker.patch('tools.compiler.GitService')
    mocker.patch('tools.compiler.VaultService')
    mocker.patch.object(os, 'getenv', return_value=None)
    mocker.patch('os.path.exists', return_value=False)


class TestMainCLI:
    def test_no_arguments(self, mocker):
        """Test that main exits with code 2 if no arguments are provided."""
        mocker.patch.object(sys, 'argv', ['compiler.py'])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_unknown_command(self, mocker):
        """Test that main exits with code 2 if an unknown command is provided."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'unknown_command'])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_validate_command_success(self, mocker):
        """Test the 'validate' command success case."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'validate'])
        mock_release_manager_class = mocker.patch('tools.compiler.ReleaseManager')
        mock_rm_instance = mock_release_manager_class.return_value

        main()

        mock_release_manager_class.assert_called_once()
        mock_rm_instance.run_validation.assert_called_once()
        mock_rm_instance.run_release_check.assert_not_called()
        mock_rm_instance.run_release_close.assert_not_called()

    def test_release_command_requires_version(self, mocker):
        """Test that the 'release' command exits if --version is not provided."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'release'])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_release_command_success(self, mocker):
        """Test the 'release' command success case."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'release', '--version', '1.2.3'])
        mock_release_manager_class = mocker.patch('tools.compiler.ReleaseManager')
        mock_rm_instance = mock_release_manager_class.return_value
        mock_rm_instance.run_release_check.return_value = ('main', 'main')
        mock_rm_instance.run_release_close.return_value = ('1.2.3', 'main')  # Fix: Provide return value

        main()

        mock_release_manager_class.assert_called_once()
        mock_rm_instance.run_validation.assert_called_once()
        mock_rm_instance.run_release_check.assert_called_once_with(release_version='1.2.3')
        mock_rm_instance.run_release_close.assert_called_once_with(release_version='1.2.3')

    def test_release_command_dry_run(self, mocker):
        """Test the 'release' command with --dry-run."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'release', '--version', '1.2.3', '--dry-run'])
        mock_release_manager_class = mocker.patch('tools.compiler.ReleaseManager')
        mock_rm_instance = mock_release_manager_class.return_value
        mock_rm_instance.run_release_check.return_value = ('main', 'main')
        mock_rm_instance.run_release_close.return_value = ('1.2.3', 'main')  # Fix: Provide return value

        main()

        # Check if ReleaseManager was initialized with dry_run=True
        args, kwargs = mock_release_manager_class.call_args
        assert kwargs.get('dry_run') is True
        mock_rm_instance.run_validation.assert_called_once()
        mock_rm_instance.run_release_check.assert_called_once_with(release_version='1.2.3')
        mock_rm_instance.run_release_close.assert_called_once_with(release_version='1.2.3')

    def test_main_handles_release_error(self, mocker):
        """Test that main catches ReleaseError and exits with 1."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'validate'])
        mock_release_manager_class = mocker.patch('tools.compiler.ReleaseManager')
        mock_rm_instance = mock_release_manager_class.return_value
        mock_rm_instance.run_validation.side_effect = ReleaseError("Test error")

        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1

    def test_main_handles_unexpected_error(self, mocker):
        """Test that main catches generic exceptions and exits with 1."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'validate'])
        mocker.patch('tools.compiler.load_project_config', side_effect=Exception("Unexpected"))

        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 1


class TestLogging:
    @pytest.fixture(autouse=True)
    def unpatch_logging(self, mocker):
        """Fixture to undo the global logging mock for this test class."""
        mocker.stopall()

    def test_setup_logging_returns_logger(self):
        """Test that setup_logging returns a logger instance."""
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)
        logger.handlers = [] # Clean up

    def test_setup_logging_levels(self):
        """Test that logging level is set correctly."""
        logger = logging.getLogger('tools.compiler')

        logger.handlers = []
        handler = setup_logging(verbose=True).handlers[0]
        assert handler.level == logging.INFO

        logger.handlers = []
        handler = setup_logging(debug=True).handlers[0]
        assert handler.level == logging.DEBUG

        logger.handlers = []
        handler = setup_logging().handlers[0]
        assert handler.level == logging.WARNING
        
        logger.handlers = [] # Clean up

    def test_setup_logging_adds_handler_once(self):
        """Test that setup_logging doesn't add duplicate handlers."""
        logger = logging.getLogger('tools.compiler')
        logger.handlers = []  # Ensure clean state

        setup_logging()
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, ColoredFormatter)

        setup_logging()  # Call again
        assert len(logger.handlers) == 1  # Should still be 1
        
        logger.handlers = [] # Clean up

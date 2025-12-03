import pytest
import sys
import os
from unittest.mock import MagicMock
import inspect


# Projekt gyökér: /app
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))

# Mindig tedd a projekt gyökerét a sys.path elejére
if PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

print(">>> PROJECT_ROOT:", PROJECT_ROOT)
print(">>> sys.path[0:5]:", sys.path[0:5])

try:
    import tools
    print(">>> tools module file:", getattr(tools, '__file__', 'NO __file__'))
except Exception as e:
    print(">>> failed to import tools:", e)

from tools.compiler import main





class TestMainCLI:
    def test_no_arguments(self, mocker):
        """Test that main exits with code 1 if no arguments are provided."""
        mocker.patch.object(sys, 'argv', ['compiler.py'])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

    def test_unknown_command(self, mocker):
        """Test that main exits with code 1 if an unknown command is provided."""
        mocker.patch.object(sys, 'argv', ['compiler.py', 'unknown_command'])
        with pytest.raises(SystemExit) as excinfo:
            main()
        assert excinfo.value.code == 2

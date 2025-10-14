import pytest
from tools import compiler
import os
from datetime import datetime, timezone
import yaml
import sys
from jsonschema import ValidationError

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

# Expected signature response from Vault
VAULT_SIGNATURE_RESPONSE = {
    "data": {
        "signature": "vault:v1:MEUCIQCbi5ghHvps5L8qTNtyTJtKghDApzgmjverpF7NqnK9lwIgSnVVEx5SZxNIL33CH0ErAGdmIrmLU4jMhLkM9mNxMLQ="
    }
}

def test_placeholder():
    """A placeholder test to ensure pytest is running correctly."""
    assert True

def test_compiler_validation_runs(mocker):
    """Test that the compiler's validation function can be called without error."""
    mocker.patch('glob.glob', return_value=['schemas/test-schema.yaml'])
    mock_load_yaml = mocker.patch('tools.compiler.load_yaml')
    mock_load_yaml.side_effect = [
        # Meta-schema
        {
            "type": "object",
            "properties": {"metadata": {"type": "object"}, "spec": {"type": "object"}}
        },
        # Dummy schema
        DUMMY_SCHEMA_DATA
    ]
    mocker.patch('tools.compiler.validate', return_value=None)

    try:
        compiler.run_validation()
    except SystemExit as e:
        if e.code == 1:
            pytest.fail(f"Validation failed with SystemExit: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during validation: {e}")

def test_run_validation_meta_schema_load_failure(mocker):
    """Test that run_validation exits with code 1 if meta-schema loading fails."""
    mocker.patch('tools.compiler.load_yaml', side_effect=IOError("File not found"))
    with pytest.raises(SystemExit) as excinfo:
        compiler.run_validation()
    assert excinfo.value.code == 1

def test_run_validation_schema_validation_failure(mocker):
    """Test that run_validation exits with code 1 if a schema fails validation."""
    mocker.patch('glob.glob', return_value=['schemas/test-schema.yaml'])
    mock_load_yaml = mocker.patch('tools.compiler.load_yaml')
    mock_load_yaml.side_effect = [
        # Meta-schema
        {
            "type": "object",
            "properties": {"metadata": {"type": "object"}, "spec": {"type": "object"}}
        },
        # Dummy schema
        DUMMY_SCHEMA_DATA
    ]
    mocker.patch('tools.compiler.validate', side_effect=ValidationError("Schema invalid"))

    with pytest.raises(SystemExit) as excinfo:
        compiler.run_validation()
    assert excinfo.value.code == 1

def test_main_no_arguments(mocker):
    """Test that main exits with code 1 if no arguments are provided."""
    mocker.patch.object(sys, 'argv', ['compiler.py'])
    with pytest.raises(SystemExit) as excinfo:
        compiler.main()
    assert excinfo.value.code == 1

def test_main_unknown_command(mocker):
    """Test that main exits with code 1 if an unknown command is provided."""
    mocker.patch.object(sys, 'argv', ['compiler.py', 'unknown_command'])
    with pytest.raises(SystemExit) as excinfo:
        compiler.main()
    assert excinfo.value.code == 1

def test_run_release_success(mocker):
    """Test that the run_release function executes successfully with valid data."""
    # Mock os.getenv for VAULT_ADDR and VAULT_TOKEN
    mocker.patch.object(os, 'getenv', side_effect=lambda x: {
        'VAULT_ADDR': 'http://localhost:8200',
        'VAULT_TOKEN': 'test_token',
        'VAULT_CACERT': None # No CA cert for testing
    }.get(x))

    # Mock requests.post for Vault signing
    mock_requests_post = mocker.patch('requests.post')
    mock_requests_post.return_value.raise_for_status.return_value = None
    mock_requests_post.return_value.json.return_value = VAULT_SIGNATURE_RESPONSE

    # Mock glob.glob to return a dummy schema file
    mocker.patch('glob.glob', return_value=['schemas/test-schema.yaml'])

    # Mock compiler.load_yaml to return the dummy schema data and meta-schema
    # Need to handle both the meta-schema and the dummy schema
    mock_load_yaml = mocker.patch('tools.compiler.load_yaml')
    mock_load_yaml.side_effect = [
        # First call for meta-schema (compiler.META_SCHEMA_FILE)
        {
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
        },
        # Second call for the dummy schema file
        DUMMY_SCHEMA_DATA
    ]

    # Mock compiler.write_yaml to prevent actual file writing
    mock_write_yaml = mocker.patch('tools.compiler.write_yaml')

    # Mock os.path.exists and os.makedirs for SOURCE_DIR
    mocker.patch.object(os.path, 'exists', return_value=True) # Assume SOURCE_DIR exists or is created
    mocker.patch.object(os, 'makedirs')

    # Mock datetime.now to control build_timestamp
    mock_dt = mocker.patch('tools.compiler.datetime.datetime')
    mock_dt.now.return_value = datetime(2025, 10, 26, 10, 0, 0, tzinfo=timezone.utc)

    # Call the function under test
    try:
        compiler.run_release()
    except SystemExit as e:
        if e.code == 1:
            pytest.fail(f"Release failed with SystemExit: {e}")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred during release: {e}")

    # Assertions
    # Check if Vault was called correctly
    mock_requests_post.assert_called_once()
    assert mock_requests_post.call_args[0][0] == 'http://localhost:8200/v1/transit/sign/cic-my-sign-key'
    assert 'input' in mock_requests_post.call_args[1]['json']
    assert 'prehashed' in mock_requests_post.call_args[1]['json']
    assert 'hash_algorithm' in mock_requests_post.call_args[1]['json']

    # Check if the final schema was written
    mock_write_yaml.assert_called_once()
    written_data = mock_write_yaml.call_args[0][1]
    assert written_data['metadata']['version'] == 'v1.0.0'
    assert 'checksum' in written_data['metadata']
    assert 'sign' in written_data['metadata']
    assert written_data['metadata']['sign'] == VAULT_SIGNATURE_RESPONSE['data']['signature']
    assert written_data['metadata']['build_timestamp'] == '2025-10-26T10:00:00+00:00'

def test_write_yaml(tmp_path):
    """Test that write_yaml correctly writes data to a YAML file."""
    test_file = tmp_path / "test_output.yaml"
    test_data = {
        "key1": "value1",
        "key2": {
            "nested_key": "nested_value"
        },
        "list_key": [1, 2, 3]
    }

    compiler.write_yaml(str(test_file), test_data)

    assert test_file.exists()
    
    with open(test_file, 'r') as f:
        content = f.read()
    
    # Verify content by loading it back with yaml
    loaded_data = yaml.safe_load(content)
    assert loaded_data == test_data

    # Verify content as string (indent=2, sort_keys=False)
    expected_content = """key1: value1
key2:
  nested_key: nested_value
list_key:
- 1
- 2
- 3
"""
    assert content == expected_content

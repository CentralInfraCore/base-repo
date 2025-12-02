class ReleaseError(Exception):
    """Base class for all custom exceptions in the release process."""
    pass

class ConfigurationError(ReleaseError):
    """Indicates an error in the project's configuration (e.g., project.yaml)."""
    pass

class GitStateError(ReleaseError):
    """Indicates an error related to the state of the Git repository (e.g., dirty working directory)."""
    pass

class VersionMismatchError(ReleaseError):
    """Indicates that a version number is not a valid or expected increment."""
    pass

class SigningError(ReleaseError):
    """Indicates a failure during the Vault signing process."""
    pass

class ValidationFailureError(ReleaseError):
    """Indicates that schema validation failed."""
    pass

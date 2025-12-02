class ReleaseError(Exception):
    """Base class for all custom exceptions in the release process."""
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.cause = cause

    def __str__(self):
        if self.cause:
            return f"{self.args[0]} (Caused by: {self.cause.__class__.__name__}: {self.cause})"
        return self.args[0]

# --- Service-level Errors ---

class GitServiceError(ReleaseError):
    """Indicates an error originating from the GitService."""
    pass

class VaultServiceError(ReleaseError):
    """Indicates an error originating from the VaultService."""
    pass

# --- Workflow-level Errors ---

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

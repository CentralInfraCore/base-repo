"""Service layer of the release tooling.

``GitService`` and ``VaultService`` wrap the git CLI and the Vault HTTP API so
``tools.infra.ReleaseManager`` can be tested with mocks; ``exceptions`` holds the
``ReleaseError`` hierarchy every release failure is reported through.
"""

# This file makes the 'releaselib' directory a Python package.

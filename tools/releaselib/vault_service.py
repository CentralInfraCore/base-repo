import base64
import logging  # Import logging
import os

import requests

from .exceptions import VaultServiceError


class VaultService:
    """
    A service class to abstract Vault operations, specifically signing.
    """

    def __init__(
        self,
        vault_addr,
        vault_token,
        vault_cacert=None,
        dry_run=False,
        timeout=10,
        logger=None,
    ):
        self.dry_run = dry_run
        self.timeout = timeout
        self.logger = (
            logger if logger else logging.getLogger(__name__)
        )  # Use provided logger or create a new one

        if not self.dry_run:
            if not vault_addr or not vault_token:
                raise VaultServiceError(
                    "Vault address and token must be provided for a live run."
                )

            # Strict TLS enforcement:
            # If vault_cacert is provided, it MUST exist.
            # If not provided, requests will use its default CA bundle (secure by default).
            if vault_cacert:
                if not os.path.exists(vault_cacert):
                    raise VaultServiceError(
                        f"Provided Vault CA certificate file not found: {vault_cacert}"
                    )
                self.verify_tls = vault_cacert
            else:
                self.verify_tls = (
                    True  # Use requests' default CA bundle for verification
                )

        self.vault_addr = vault_addr
        self.vault_token = vault_token
        # In dry-run, verify_tls is not used, but we set it to True for consistency
        if self.dry_run:
            self.verify_tls = True

    def sign(self, digest_b64, key_name):
        """
        Signs a pre-hashed, base64-encoded digest using Vault's Transit Engine.
        In dry-run mode, returns a placeholder signature without making a network call.
        """
        if self.dry_run:
            self.logger.info(
                "[DRY-RUN] Skipping Vault signing. Returning a placeholder signature."
            )
            return "vault:v1:dry-run-placeholder-signature"

        # Validate digest_b64 format
        try:
            decoded_digest = base64.b64decode(digest_b64, validate=True)
            # While we expect SHA256, the Vault API handles various hash algorithms.
            # The length check is a good sanity check for typical digests like SHA256.
            if len(decoded_digest) != 32:  # SHA256 produces 32 bytes
                self.logger.warning(
                    f"Digest length is not 32 bytes (SHA256 expected), got {len(decoded_digest)}. Proceeding but this might indicate an issue."
                )
        except (TypeError, ValueError) as e:
            raise VaultServiceError(f"Invalid Base64 digest format: {e}") from e

        response = None  # Initialize response to None
        try:
            self.logger.debug(
                f"Requesting signature from Vault at {self.vault_addr} for key {key_name}..."
            )
            response = requests.post(
                f"{self.vault_addr}/v1/transit/sign/{key_name}",
                headers={"X-Vault-Token": self.vault_token},
                json={
                    "input": digest_b64,
                    "prehashed": True,
                    "hash_algorithm": "sha2-256",
                },
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)

            response_data = response.json()
            signature = response_data.get("data", {}).get("signature")

            if (
                not signature
                or not isinstance(signature, str)
                or not signature.startswith("vault:v1:")
            ):
                raise VaultServiceError(
                    f"Invalid or missing signature in Vault response. Raw response: {response.text}"
                )
            self.logger.debug("Signature received successfully.")
            return signature
        except requests.exceptions.RequestException as e:
            raise VaultServiceError(f"Vault signing request failed: {e}", cause=e)
        except ValueError as e:  # Added for non-JSON responses
            # Ensure response.text is not None before accessing it
            raw_response_text = (
                response.text if response else "No response text available."
            )
            raise VaultServiceError(
                f"Invalid JSON in Vault response: {e}. Raw response: {raw_response_text}",
                cause=e,
            )
        except (KeyError, TypeError) as e:
            # Ensure response.text is not None before accessing it
            raw_response_text = (
                response.text if response else "No response text available."
            )
            raise VaultServiceError(
                f"Could not parse signature from Vault response: {e}. Raw response: {raw_response_text}",
                cause=e,
            )

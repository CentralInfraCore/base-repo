import os
import requests
from .exceptions import VaultServiceError

class VaultService:
    """
    A service class to abstract Vault operations, specifically signing.
    """
    def __init__(self, vault_addr, vault_token, vault_cacert=None, dry_run=False):
        self.dry_run = dry_run
        
        if not self.dry_run and (not vault_addr or not vault_token):
            raise VaultServiceError("Vault address and token must be provided for a live run.")
            
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.verify_tls = vault_cacert if vault_cacert and os.path.exists(vault_cacert) else False

    def sign(self, digest_b64, key_name):
        """
        Signs a pre-hashed, base64-encoded digest using Vault's Transit Engine.
        In dry-run mode, returns a placeholder signature without making a network call.
        """
        if self.dry_run:
            return "vault:v1:dry-run-placeholder-signature"

        # Removed the print statement for TLS warning. This should be handled by the caller (CLI).

        try:
            response = requests.post(
                f"{self.vault_addr}/v1/transit/sign/{key_name}",
                headers={"X-Vault-Token": self.vault_token},
                json={
                    "input": digest_b64,
                    "prehashed": True,
                    "hash_algorithm": "sha2-256",
                },
                verify=self.verify_tls,
                timeout=10,
            )
            response.raise_for_status()
            signature = response.json().get("data", {}).get("signature")
            if not signature:
                 raise VaultServiceError(f"Signature not found in Vault response: {response.text}")
            return signature
        except requests.exceptions.RequestException as e:
            raise VaultServiceError(f"Vault signing request failed: {e}")
        except (KeyError, TypeError) as e:
            raise VaultServiceError(f"Could not parse signature from Vault response: {e}")

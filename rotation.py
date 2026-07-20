import time


class RotationManager:
    """Base class for rotating secrets before revocation."""

    def rotate(self, provider: str, fingerprint: str, dry_run: bool = False) -> bool:
        """
        Provision a new secret, update the secret store, and return True if successful.
        If False is returned, the subsequent revocation should be aborted.
        """
        raise NotImplementedError


class MockVaultRotator(RotationManager):
    """A mock rotator for demonstration purposes."""

    def rotate(self, provider: str, fingerprint: str, dry_run: bool = False) -> bool:
        print(f"      [MockVault] Attempting rotation for {provider} (fp: {fingerprint})")
        if not dry_run:
            print("      [MockVault] ⏳ Provisioning new credential...")
            time.sleep(1)
            print("      [MockVault] 🔄 Updating Vault KV store...")
            time.sleep(0.5)
        print("      [MockVault] ✅ Rotation successful. Old key is safe to revoke.")
        return True

ROTATORS = {
    "mock-vault": MockVaultRotator()
}

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class RevocationResult:
    provider: str
    fingerprint: str
    success: bool
    detail: str
    dry_run: bool = False


class Revoker(Protocol):
    provider: str

    def check_live(self, secret: str) -> bool:
        """Cheap, read-only call to confirm the secret is still active before revoking."""
        ...

    def revoke(self, secret: str, fingerprint: str, dry_run: bool = True) -> RevocationResult:
        """Call the provider's revocation endpoint. dry_run=True by default — logs intent only."""
        ...

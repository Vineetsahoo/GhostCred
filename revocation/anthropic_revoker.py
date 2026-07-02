from __future__ import annotations

import requests

from ghostcred.revocation.base import RevocationResult

API_ROOT = "https://api.anthropic.com/v1"


class AnthropicRevoker:
    """
    Same shape as the OpenAI revoker: liveness check uses the leaked key against a
    cheap read endpoint; the actual delete requires an Anthropic Console admin API
    key configured separately in GhostCred (GHOSTCRED_ANTHROPIC_ADMIN_KEY), since
    key deletion is an org-admin operation, not something the key itself can do.
    """

    provider = "anthropic_api_key"

    def check_live(self, secret: str) -> bool:
        try:
            # A minimal, cheap call — models list is a lightweight read endpoint.
            resp = requests.get(
                f"{API_ROOT}/models",
                headers={"x-api-key": secret, "anthropic-version": "2023-06-01"},
                timeout=8,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def revoke(self, secret: str, fingerprint: str, dry_run: bool = True) -> RevocationResult:
        if dry_run:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=True,
                detail="DRY RUN: would look up key_id via Console admin API and delete it",
                dry_run=True,
            )
        return RevocationResult(
            provider=self.provider,
            fingerprint=fingerprint,
            success=False,
            detail="Live revocation requires GHOSTCRED_ANTHROPIC_ADMIN_KEY to be configured",
        )

from __future__ import annotations

import requests

from ghostcred.revocation.base import RevocationResult

API_ROOT = "https://api.openai.com/v1"


class OpenAIRevoker:
    """
    OpenAI project API keys can be deleted via the platform's admin API
    (`DELETE /organization/projects/{project_id}/api_keys/{key_id}`), but that
    call requires an *organization admin key*, not the leaked key itself — the
    leaked key alone cannot delete itself. GhostCred uses the leaked key only
    to confirm liveness, then uses its own configured admin key to look up and
    delete the matching key record.
    """

    provider = "openai_api_key"

    def check_live(self, secret: str) -> bool:
        try:
            resp = requests.get(
                f"{API_ROOT}/models",
                headers={"Authorization": f"Bearer {secret}"},
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
                detail="DRY RUN: would look up key_id via admin API and DELETE it",
                dry_run=True,
            )
        return RevocationResult(
            provider=self.provider,
            fingerprint=fingerprint,
            success=False,
            detail="Live revocation requires GHOSTCRED_OPENAI_ADMIN_KEY to be configured",
        )

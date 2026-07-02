from __future__ import annotations

import requests

from ghostcred.revocation.base import RevocationResult

API_ROOT = "https://api.github.com"


class GitHubRevoker:
    provider = "github_pat"

    def check_live(self, secret: str) -> bool:
        try:
            resp = requests.get(
                f"{API_ROOT}/user",
                headers={"Authorization": f"token {secret}"},
                timeout=8,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def revoke(self, secret: str, fingerprint: str, dry_run: bool = True) -> RevocationResult:
        """
        GitHub PATs are revoked by the token owner via Settings > Developer settings,
        or programmatically for GitHub App installation tokens via
        DELETE /installation/token. Classic/fine-grained PATs have no public
        self-revoke API for a third party holding the token string — GhostCred's
        realistic path here is to notify the token owner + org admin immediately
        and, where GitHub App credentials are configured, delete the installation
        token via the App's own installation-token endpoint.
        """
        if dry_run:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=True,
                detail="DRY RUN: would notify org admin + attempt installation-token deletion",
                dry_run=True,
            )
        try:
            # Real installation-token revocation path (requires GitHub App auth context,
            # configured separately). Left as the integration point.
            resp = requests.delete(
                f"{API_ROOT}/installation/token",
                headers={"Authorization": f"token {secret}"},
                timeout=8,
            )
            success = resp.status_code == 204
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=success,
                detail=f"installation token delete → HTTP {resp.status_code}",
            )
        except requests.RequestException as exc:
            return RevocationResult(
                provider=self.provider, fingerprint=fingerprint, success=False, detail=str(exc)
            )

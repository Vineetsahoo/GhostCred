"""
OpenAI Revoker
==============
Liveness check uses the leaked key itself (cheap GET /models).
Live revocation requires an organisation admin key configured as
GHOSTCRED_OPENAI_ADMIN_KEY — the leaked key cannot delete itself.

Service layer wires the env var through automatically so no manual
credential passing is needed in production CI.
"""
from __future__ import annotations

import os

import requests

from ghostcred.revocation.base import RevocationResult

# Points to the mock provider in demo mode, real API in production.
# Override with GHOSTCRED_OPENAI_API_ROOT for self-hosted / proxy setups.
_API_ROOT = os.environ.get("GHOSTCRED_OPENAI_API_ROOT", "https://api.openai.com/v1")


class OpenAIRevoker:
    provider = "openai_api_key"

    # ── service layer: reads credentials from environment at call time ────────
    @staticmethod
    def _admin_key() -> str | None:
        return os.environ.get("GHOSTCRED_OPENAI_ADMIN_KEY")

    def check_live(self, secret: str) -> bool:
        """
        Cheap, read-only check: GET /models with the leaked key.
        200 → still live. Anything else → inactive or invalid.
        """
        try:
            resp = requests.get(
                f"{_API_ROOT}/models",
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
                detail=(
                    "DRY RUN: would list org API keys via admin API, "
                    "match by prefix, then DELETE /organization/api_keys/{id}"
                ),
                dry_run=True,
            )

        admin_key = self._admin_key()
        if not admin_key:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=False,
                detail=(
                    "Live revocation requires GHOSTCRED_OPENAI_ADMIN_KEY "
                    "(organisation admin key). Set it in .env or as a CI secret."
                ),
            )

        # Step 1: list all project keys with the admin key to find the matching key_id
        try:
            list_resp = requests.get(
                f"{_API_ROOT}/organization/api_keys",
                headers={"Authorization": f"Bearer {admin_key}"},
                timeout=10,
            )
            if list_resp.status_code != 200:
                return RevocationResult(
                    provider=self.provider,
                    fingerprint=fingerprint,
                    success=False,
                    detail=f"Failed to list API keys: HTTP {list_resp.status_code}",
                )

            keys = list_resp.json().get("data", [])
            # Match by the first 10 chars of the secret (keys are partially masked in the API)
            secret_prefix = secret[:10]
            key_id = next(
                (k["id"] for k in keys if k.get("value", "").startswith(secret_prefix)),
                None,
            )

            if not key_id:
                return RevocationResult(
                    provider=self.provider,
                    fingerprint=fingerprint,
                    success=False,
                    detail="Could not find matching key_id — key may already be deleted",
                )

            # Step 2: delete the key by ID
            del_resp = requests.delete(
                f"{_API_ROOT}/organization/api_keys/{key_id}",
                headers={"Authorization": f"Bearer {admin_key}"},
                timeout=10,
            )
            success = del_resp.status_code in (200, 204)
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=success,
                detail=f"DELETE /organization/api_keys/{key_id} → HTTP {del_resp.status_code}",
            )

        except requests.RequestException as exc:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=False,
                detail=f"Request error during revocation: {exc}",
            )

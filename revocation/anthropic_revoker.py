"""
Anthropic Revoker
=================
Liveness check uses the leaked key itself (GET /v1/models).
Live revocation requires an admin Console API key configured as
GHOSTCRED_ANTHROPIC_ADMIN_KEY — same pattern as the OpenAI revoker.

Service layer wires the env var through automatically.
"""
from __future__ import annotations

import os

import requests

from ghostcred.revocation.base import RevocationResult

_API_ROOT = os.environ.get("GHOSTCRED_ANTHROPIC_API_ROOT", "https://api.anthropic.com/v1")
_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicRevoker:
    provider = "anthropic_api_key"

    @staticmethod
    def _admin_key() -> str | None:
        return os.environ.get("GHOSTCRED_ANTHROPIC_ADMIN_KEY")

    def check_live(self, secret: str) -> bool:
        """
        Cheap read-only check: GET /models with the leaked key.
        Returns True only on HTTP 200.
        """
        try:
            resp = requests.get(
                f"{_API_ROOT}/models",
                headers={
                    "x-api-key": secret,
                    "anthropic-version": _ANTHROPIC_VERSION,
                },
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
                    "DRY RUN: would list API keys via Console admin API, "
                    "match by prefix, then DELETE /api-keys/{id}"
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
                    "Live revocation requires GHOSTCRED_ANTHROPIC_ADMIN_KEY "
                    "(Console admin API key). Set it in .env or as a CI secret."
                ),
            )

        # Step 1: list all API keys using the admin key
        try:
            list_resp = requests.get(
                f"{_API_ROOT}/api-keys",
                headers={
                    "x-api-key": admin_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                },
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
                    detail="Could not match key_id — key may already be deleted",
                )

            # Step 2: delete the matching key
            del_resp = requests.delete(
                f"{_API_ROOT}/api-keys/{key_id}",
                headers={
                    "x-api-key": admin_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                },
                timeout=10,
            )
            success = del_resp.status_code in (200, 204)
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=success,
                detail=f"DELETE /api-keys/{key_id} → HTTP {del_resp.status_code}",
            )

        except requests.RequestException as exc:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=False,
                detail=f"Request error during revocation: {exc}",
            )

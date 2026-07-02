from __future__ import annotations

from ghostcred.revocation.base import RevocationResult


class AWSRevoker:
    """
    AWS has no endpoint that lets an arbitrary caller revoke a key using only the
    leaked key itself (by design — that would be a huge security hole). Real
    revocation requires an IAM principal with `iam:UpdateAccessKey` /
    `iam:DeleteAccessKey` permissions on the account that owns the leaked key,
    which GhostCred must be configured with separately (its own scoped IAM role).

    This revoker therefore:
      1. Uses the leaked key only for a read-only `get_caller_identity` liveness
         check (never for the revoke call itself).
      2. Performs the actual `update_access_key(Status='Inactive')` call using
         GhostCred's own configured boto3 session/role, targeting the leaked
         key's AccessKeyId.
    """

    provider = "aws_access_key"

    def check_live(self, secret: str) -> bool:
        try:
            import boto3

            # `secret` here is the AccessKeyId; the matching secret key is not
            # required for get_caller_identity's STS call to fail/succeed cleanly.
            sts = boto3.client("sts", aws_access_key_id=secret, aws_secret_access_key="")
            sts.get_caller_identity()
            return True
        except Exception:  # noqa: BLE001 - liveness probe, any failure means "can't confirm live"
            return False

    def revoke(self, secret: str, fingerprint: str, dry_run: bool = True) -> RevocationResult:
        if dry_run:
            return RevocationResult(
                provider=self.provider,
                fingerprint=fingerprint,
                success=True,
                detail="DRY RUN: would call iam.update_access_key(Status='Inactive') via GhostCred's own IAM role",
                dry_run=True,
            )
        try:
            import boto3

            iam = boto3.client("iam")  # uses GhostCred's own configured credentials, not the leaked key
            iam.update_access_key(AccessKeyId=secret, Status="Inactive")
            return RevocationResult(
                provider=self.provider, fingerprint=fingerprint, success=True, detail="access key set to Inactive"
            )
        except Exception as exc:  # noqa: BLE001
            return RevocationResult(
                provider=self.provider, fingerprint=fingerprint, success=False, detail=str(exc)
            )

# Revocation

This directory contains the automated credential revocation logic for GhostCred.

## Overview
When GhostCred detects a leaked secret, finding it is only half the battle. This module is responsible for verifying the secret is still active (live) and, if configured, automatically calling the provider's API to revoke the credential before an attacker can use it.

## Files
- `base.py`: Defines the `Revoker` protocol and the `RevocationResult` data class.
- `default_plugins.py`: Registers the built-in revokers using `pluggy`.
- `github_revoker.py`: Revokes GitHub Classic and Fine-Grained Personal Access Tokens via the GitHub REST API.
- `openai_revoker.py`: Experimental interface for revoking OpenAI API keys.
- `anthropic_revoker.py`: Experimental interface for revoking Anthropic API keys.

## Extensibility
GhostCred uses `pluggy` for its revocation engine. You can build proprietary revokers for your internal services by creating a plugin package that implements the `ghostcred_register_revokers` hook, returning a dictionary mapping the provider name to your custom `Revoker` class.

## Supported providers

| Provider | Detection | Liveness check | Auto-revoke |
|---|---|---|---|
| GitHub PAT (classic + fine-grained) | Yes | Yes | Yes, dry-run or live |
| OpenAI API key | Yes | Yes | Dry-run supported; live requires admin key |
| Anthropic API key | Yes | Yes | Dry-run supported; live requires admin key |
| AWS access key | Detected | No | Pending AWS deployment |
| Stripe key | Detected | No | No |
| Slack token | Detected | No | No |
| Google API key | Detected | No | No |
| Private key block (RSA / EC / OPENSSH) | Detected | No | No |
| Generic bearer token | Detected at low confidence | No | No |

## Runtime flow

1. Scan finds a candidate secret.
2. The revoker checks whether the secret is still live.
3. Optional rotation can run before revocation.
4. The revoker executes in dry-run or live mode.
5. Webhook reporting can publish the result to downstream systems.

## Safety notes

- Dry-run remains the default for destructive operations.
- Live revocation should only be used with tightly scoped, short-lived credentials.
- The `revoke` and `scan --revoke-live` paths both support webhook reporting for audit pipelines.

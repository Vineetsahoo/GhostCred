# Revocation

This directory contains the automated credential revocation logic for GhostCred.

## Overview
When GhostCred detects a leaked secret, finding it is only half the battle. This module is responsible for verifying the secret is still active (live) and, if configured, automatically calling the provider's API to revoke the credential before an attacker can use it.

## Files
- `base.py`: Defines the `Revoker` protocol and the `RevocationResult` data class. All custom revokers must implement this protocol.
- `default_plugins.py`: Registers the built-in revokers (GitHub, OpenAI, Anthropic) using `pluggy`.
- `github_revoker.py`: Revokes GitHub Classic and Fine-Grained Personal Access Tokens via the GitHub REST API.
- `openai_revoker.py`: (Mocked/Experimental) Interface for revoking OpenAI API keys.
- `anthropic_revoker.py`: (Mocked/Experimental) Interface for revoking Anthropic API keys.

## Extensibility
GhostCred uses `pluggy` for its revocation engine. You can build proprietary revokers for your internal services by creating a plugin package that implements the `ghostcred_register_revokers` hook, returning a dictionary mapping the provider name to your custom `Revoker` class.

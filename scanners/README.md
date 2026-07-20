# Scanners

This directory contains the core detection engine for GhostCred.

## Overview
GhostCred uses a hybrid approach to finding secrets. Instead of relying purely on entropy or brute-force regex matches, it combines high-fidelity regex patterns with contextual clues (e.g., surrounding keywords like `api_key`) and structural analysis of the codebase.

## Files
- `patterns.py`: Defines the regex patterns and contextual keywords for various providers (AWS, GitHub, Stripe, OpenAI, Anthropic, etc.). Now loaded via `pluggy` hooks.
- `base.py`: Contains the foundational models (`Finding`, `SecretPattern`) and the text/file scanning logic.
- `code_scanner.py`: Scans traditional source code repositories for secrets (ignores `.git` and `node_modules`).
- `ai_toolchain_scanner.py`: A specialized scanner designed to inspect AI developer tools (VS Code/Cursor MCP configs, shell histories, etc.) where secrets are often leaked inadvertently via prompt injections or automated tool usage.

## Extensibility
Scanners use the `pluggy` framework. You can define new patterns by writing a plugin that implements the `ghostcred_register_patterns` hook and returning a list of `SecretPattern` objects.

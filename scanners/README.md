# Scanners

This directory contains the core detection engine for GhostCred.

## Overview
GhostCred uses a hybrid approach to finding secrets. Instead of relying purely on entropy or brute-force regex matches, it combines high-fidelity regex patterns with contextual clues and structural analysis of the codebase.

## Files
- `patterns.py`: Defines the regex patterns and contextual keywords for providers such as GitHub, OpenAI, Anthropic, Stripe, Slack, Google, and AWS.
- `base.py`: Contains the `Finding` model plus the text and file scanning logic.
- `code_scanner.py`: Scans source code, build files, and common secret-bearing paths.
- `ai_toolchain_scanner.py`: Scans AI developer tool surfaces where secrets are often leaked accidentally.

## Extensibility
Scanners use the `pluggy` framework. You can define new patterns by writing a plugin that implements the `ghostcred_register_patterns` hook and returning a list of `SecretPattern` objects.

## What the scanner covers

### Baseline code paths

- `.env` files and source code
- Dockerfiles and build context
- Common repository-local secret files

### AI toolchain blind spots

| Path | Why it matters |
|---|---|
| `%APPDATA%\Claude\claude_desktop_config.json` (Windows) | MCP server `env` blocks frequently contain raw API keys |
| `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | Same risk on local desktop setups |
| `~/.config/Claude/claude_desktop_config.json` (Linux) | Same risk on Linux developer workstations |
| `**/.cursor/mcp.json`, `**/.cursor/settings.json` | Cursor MCP and model provider keys |
| `**/.vscode/settings.json`, `**/.vscode/mcp.json`, `*.code-workspace` | Extension tokens and workspace-level MCP servers |
| `**/.continue/config.json` | Continue.dev configuration with embedded credentials |
| `**/.windsurf/mcp.json` | Windsurf MCP config files |
| `~/.zsh_history`, `~/.bash_history`, `~/.zsh_sessions/*` | Secrets typed into shell prompts |
| `~/.aws/credentials`, `~/.config/gh/hosts.yml` | Legacy credential stores worth cross-checking |
| `**/mcp.json`, `**/*.mcp.json` | Project-local MCP configs, a common accidental-commit vector |

## Scanner behavior

- Context keywords can raise confidence when a pattern match appears near labels such as `api_key` or `Authorization`.
- Low-confidence generic bearer-style matches are filtered unless the surrounding context is strong enough.
- Findings are deduplicated by fingerprint and source path so the same secret remains visible across different files.

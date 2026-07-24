"""
Regex + contextual signatures for known secret providers.

Each pattern includes a confidence baseline. Confidence is bumped when the match
also appears near a contextual keyword (e.g. "api_key", "token", "secret") and
lowered for generic high-entropy patterns with no provider prefix.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    provider: str
    regex: re.Pattern
    base_confidence: float
    revocable: bool  # whether ghostcred has a Revoker implementation for this provider


PATTERNS: list[SecretPattern] = [
    SecretPattern(
        provider="github_pat",
        regex=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        base_confidence=0.95,
        revocable=True,
    ),
    SecretPattern(
        provider="github_fine_grained_pat",
        regex=re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
        base_confidence=0.95,
        revocable=True,
    ),
    SecretPattern(
        provider="aws_access_key",
        regex=re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        base_confidence=0.9,
        revocable=True,
    ),
    SecretPattern(
        provider="aws_secret_key",
        # Only matched with contextual keyword nearby (aws_secret_access_key=...) — see scan logic.
        regex=re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        base_confidence=0.4,
        revocable=True,
    ),
    SecretPattern(
        provider="openai_api_key",
        # Negative lookahead excludes sk-ant-... so this never swallows Anthropic keys,
        # which share the sk- prefix.
        regex=re.compile(r"sk-(proj-)?(?!ant-)[A-Za-z0-9_-]{20,200}"),
        base_confidence=0.92,
        revocable=True,
    ),
    SecretPattern(
        provider="anthropic_api_key",
        regex=re.compile(r"sk-ant-(api03|admin01)-[A-Za-z0-9_-]{80,120}"),
        base_confidence=0.95,
        revocable=True,
    ),
    SecretPattern(
        provider="slack_token",
        regex=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,72}"),
        base_confidence=0.9,
        revocable=True,
    ),
    SecretPattern(
        provider="stripe_key",
        regex=re.compile(r"(sk|rk)_(live|test)_[A-Za-z0-9]{24,99}"),
        base_confidence=0.93,
        revocable=False,
    ),
    SecretPattern(
        provider="google_api_key",
        regex=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        base_confidence=0.85,
        revocable=False,
    ),
    SecretPattern(
        provider="private_key_block",
        regex=re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        base_confidence=0.98,
        revocable=False,
    ),
    SecretPattern(
        provider="generic_bearer_token",
        regex=re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,500}=*"),
        base_confidence=0.5,
        revocable=False,
    ),
    SecretPattern(
        provider="prompt_injection",
        regex=re.compile(r"(?i)(ignore previous instructions|you are a helpful assistant|system prompt:)"),
        base_confidence=0.8,
        revocable=False,
    ),
    SecretPattern(
        provider="jwt_token",
        regex=re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        base_confidence=0.85,
        revocable=False,
    ),
    SecretPattern(
        provider="database_uri",
        regex=re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|rediss|amqp|amqps)://[a-zA-Z0-9_.-]+:[^@/\s]+@[a-zA-Z0-9_.-]+(?::\d+)?(?:/[a-zA-Z0-9_.-]+)?"),
        base_confidence=0.9,
        revocable=False,
    ),
    SecretPattern(
        provider="malicious_mcp_config",
        regex=re.compile(r"(?i)(bash -i|nc -e|curl .* \| bash)"),
        base_confidence=0.9,
        revocable=False,
    ),
]

# Keywords that boost confidence when found within ~40 chars of a candidate match.
CONTEXT_KEYWORDS = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|credential|auth|bearer|access[_-]?key)"
)

# File globs that mark a location as an "AI toolchain" blind spot rather than plain code.
AI_TOOLCHAIN_GLOBS = [
    "**/claude_desktop_config.json",
    "**/.cursor/settings.json",
    "**/.cursor/mcp.json",
    "**/.vscode/settings.json",
    "**/.vscode/mcp.json",
    "*.code-workspace",
    "**/mcp.json",
    "**/*.mcp.json",
    "**/.continue/config.json",
    "**/.windsurf/mcp.json",
]

SHELL_HISTORY_FILES = [
    "~/.zsh_history",
    "~/.bash_history",
    "~/.local/share/fish/fish_history",
]

from ghostcred.plugin_specs import hookimpl

@hookimpl
def ghostcred_register_patterns():
    return PATTERNS

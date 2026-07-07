"""
AI Toolchain-Aware Scanning — the thing Gitleaks, TruffleHog, and detect-secrets don't do.

Covers the credential surface introduced by AI coding tools:
  - Claude Desktop / Cursor / Windsurf / Continue MCP server configs (often contain raw
    API keys in an `env` block, per common quickstart docs)
  - VS Code workspace + settings files (extension tokens, workspace-level MCP servers)
  - Shell history files (`export OPENAI_API_KEY=sk-...` typed at a prompt, later reused
    by an agent shelling out on the developer's behalf)
"""
from __future__ import annotations

import fnmatch
import os
import platform
from pathlib import Path

from ghostcred.scanners.base import Finding, scan_file
from ghostcred.scanners.patterns import AI_TOOLCHAIN_GLOBS, SHELL_HISTORY_FILES


def _platform_ai_config_paths() -> list[Path]:
    """Well-known, OS-specific locations for AI desktop app configs."""
    home = Path.home()
    system = platform.system()
    candidates: list[Path] = []

    if system == "Darwin":
        candidates.append(
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
        candidates.append(home / "Library" / "Application Support" / "Cursor" / "User" / "settings.json")
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))
        candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        candidates.append(Path(appdata) / "Cursor" / "User" / "settings.json")
    else:  # Linux and friends
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")
        candidates.append(home / ".config" / "Cursor" / "User" / "settings.json")

    return [p for p in candidates if p.exists()]


def _project_local_ai_configs(root: Path, ignore_paths: list[str] | None = None) -> list[Path]:
    """Project-committed MCP/IDE configs — the most common accidental-commit vector."""
    ignore_paths = ignore_paths or []
    matches: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = path.name
            
        if any(fnmatch.fnmatch(rel, pat) for pat in ignore_paths):
            continue
            
        for pattern in AI_TOOLCHAIN_GLOBS:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.lstrip("*").lstrip("/")):
                matches.append(path)
                break
            p = Path(pattern)
            pattern_name = p.name
            pattern_parent = str(p.parent)
            name_only_pattern = pattern_parent in ("**", ".")
            if name_only_pattern and "*" not in pattern_name and fnmatch.fnmatch(path.name, pattern_name):
                matches.append(path)
                break
    return matches


def _shell_history_files() -> list[Path]:
    paths = []
    for pattern in SHELL_HISTORY_FILES:
        expanded = Path(pattern).expanduser()
        if expanded.exists():
            paths.append(expanded)
    return paths


def scan_ai_toolchain(
    root: Path, salt: str, include_global_configs: bool = True, ignore_paths: list[str] | None = None
) -> list[Finding]:
    """
    Scan the AI dev toolchain blind spots:
      1. Global desktop-app configs (Claude Desktop, Cursor, etc.) — off by default
         in most other scanners because they live outside the repo entirely.
      2. Project-local MCP/IDE config files.
      3. Shell history for exported credentials.
    """
    findings: list[Finding] = []

    if include_global_configs:
        for path in _platform_ai_config_paths():
            findings.extend(scan_file(path, source_kind="mcp_config", salt=salt))

    for path in _project_local_ai_configs(root, ignore_paths=ignore_paths):
        kind = "mcp_config" if "mcp" in path.name.lower() or "claude" in path.name.lower() else "ide_config"
        findings.extend(scan_file(path, source_kind=kind, salt=salt))

    for path in _shell_history_files():
        # Shell history can be large; cap generously but skip if absurd.
        findings.extend(scan_file(path, source_kind="shell_history", salt=salt, max_bytes=20_000_000))

    return findings

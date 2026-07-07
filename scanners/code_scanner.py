from __future__ import annotations

import fnmatch
from pathlib import Path

from ghostcred.scanners.base import Finding, scan_file
from ghostcred.scanners.patterns import AI_TOOLCHAIN_GLOBS

# Directories we never descend into — build/cache noise, not source of truth.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox", "target", ".next",
}

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".rs", ".c", ".cpp",
    ".sh", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".env", ".txt", ".md",
    ".dockerfile", ".tf", ".tfvars",
}

ENV_FILENAMES = {".env", ".env.local", ".env.production", ".env.development", ".env.staging"}


def _is_ai_toolchain_file(path: Path, root: Path) -> bool:
    """Files owned by the AI-toolchain scanner are excluded here to avoid double-counting
    and mislabeling — e.g. `.cursor/mcp.json` should be reported as `mcp_config`, not `code`."""
    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        rel = path.name

    for pattern in AI_TOOLCHAIN_GLOBS:
        # Check against both the full glob pattern and a stripped version for root files.
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.lstrip("*").lstrip("/")):
            return True

        # Filename-only shortcut: only safe when the pattern has no directory component
        # (e.g. "**/mcp.json" → name "mcp.json", parent is just "**").
        # Patterns like "**/.continue/config.json" have a meaningful directory, so the
        # file name alone is not a safe discriminator — skip the shortcut for those.
        p = Path(pattern)
        pattern_name = p.name
        pattern_parent = str(p.parent)  # e.g. "**" or "**/.cursor"
        name_only_pattern = pattern_parent in ("**", ".")  # no real directory constraint
        if name_only_pattern and "*" not in pattern_name and fnmatch.fnmatch(path.name, pattern_name):
            return True

    return False


def _iter_candidate_files(root: Path, ignore_paths: list[str] | None = None):
    ignore_paths = ignore_paths or []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if _is_ai_toolchain_file(path, root):
            continue
        # Check against ignore_paths globs (relative to root, forward slashes)
        try:
            rel = str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = path.name
        if any(fnmatch.fnmatch(rel, pat) for pat in ignore_paths):
            continue
        if path.name in ENV_FILENAMES or path.suffix.lower() in CODE_EXTENSIONS:
            yield path
        elif path.name.lower() == "dockerfile" or path.name.startswith("Dockerfile"):
            yield path


def scan_codebase(root: Path, salt: str, ignore_paths: list[str] | None = None) -> list[Finding]:
    """Baseline scan of source + .env files — parity with Gitleaks/TruffleHog coverage."""
    findings: list[Finding] = []
    for path in _iter_candidate_files(root, ignore_paths=ignore_paths):
        kind = "env" if path.name in ENV_FILENAMES else "code"
        findings.extend(scan_file(path, source_kind=kind, salt=salt))
    return findings

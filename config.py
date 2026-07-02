from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONFIG_FILENAMES = (".ghostcred.yml", ".ghostcred.yaml")


@dataclass
class GhostCredConfig:
    min_confidence: float = 0.6
    include_ai_toolchain: bool = True
    include_global_configs: bool = True  # scan Claude Desktop / Cursor configs outside the repo
    auto_revoke: bool = False
    dry_run_revocations: bool = True
    metrics_port: int = 9308
    ignore_paths: list[str] = field(default_factory=list)
    ci_log_dir: str | None = None
    docker_image_tags: list[str] = field(default_factory=list)
    salt: str = field(default_factory=lambda: os.environ.get("GHOSTCRED_SALT") or secrets.token_hex(16))

    @classmethod
    def load(cls, root: Path) -> "GhostCredConfig":
        for name in DEFAULT_CONFIG_FILENAMES:
            candidate = root / name
            if candidate.exists():
                data = yaml.safe_load(candidate.read_text()) or {}
                return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()

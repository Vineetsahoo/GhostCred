"""
Secret Lineage Tracker — builds a blast-radius graph for a detected secret.

Given a fingerprint, this walks likely propagation destinations (docker build logs,
CI run logs, test-output artifacts, git history) and checks whether the SAME secret
reappears there. It never persists the raw secret — it exists in memory only for the
duration of one scan run.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ghostcred.scanners.base import Finding

# Destination "weight" reflects how exposed/shared that surface is.
# A CI log visible to an entire org scores far worse than a local pytest cache.
DESTINATION_WEIGHTS = {
    "docker_build_log": 25,
    "docker_image_layer": 30,
    "github_actions_log": 40,
    "test_output": 10,
    "git_history_blob": 35,
    "aws_credentials_file": 20,
    "shell_history_propagation": 15,
}


@dataclass
class Propagation:
    kind: str
    path: str
    weight: int


@dataclass
class LineageResult:
    origin: Finding
    propagations: list[Propagation] = field(default_factory=list)

    @property
    def blast_radius_score(self) -> int:
        base = 10  # origin file itself always counts for something
        return min(100, base + sum(p.weight for p in self.propagations))

    def to_public_dict(self) -> dict:
        return {
            "origin": self.origin.to_public_dict(),
            "propagations": [p.__dict__ for p in self.propagations],
            "blast_radius_score": self.blast_radius_score,
        }


def _grep_for_secret(raw_secret: str, path: Path) -> bool:
    try:
        if not path.exists() or path.stat().st_size > 20_000_000:
            return False
        return raw_secret in path.read_text(errors="ignore")
    except OSError:
        return False


def trace_docker_logs(raw_secret: str, root: Path) -> list[Propagation]:
    props = []
    for log_path in root.rglob("*.log"):
        if "docker" not in log_path.name.lower() and "build" not in log_path.name.lower():
            continue
        if _grep_for_secret(raw_secret, log_path):
            props.append(Propagation("docker_build_log", str(log_path), DESTINATION_WEIGHTS["docker_build_log"]))
    return props


def trace_docker_image_layers(raw_secret: str, image_tags: list[str] | None = None) -> list[Propagation]:
    """Best-effort: inspect local docker image history for the secret if docker CLI is available."""
    props: list[Propagation] = []
    if not image_tags:
        return props
    for tag in image_tags:
        try:
            result = subprocess.run(
                ["docker", "history", "--no-trunc", tag],
                capture_output=True, text=True, timeout=15,
            )
            if raw_secret in result.stdout:
                props.append(Propagation("docker_image_layer", tag, DESTINATION_WEIGHTS["docker_image_layer"]))
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
    return props


def trace_github_actions_logs(raw_secret: str, log_dir: Path | None) -> list[Propagation]:
    """Scan locally-downloaded `gh run view --log` output (fetching is left to the CI wrapper)."""
    props = []
    if not log_dir or not log_dir.exists():
        return props
    for log_path in log_dir.rglob("*.txt"):
        if _grep_for_secret(raw_secret, log_path):
            props.append(Propagation("github_actions_log", str(log_path), DESTINATION_WEIGHTS["github_actions_log"]))
    return props


def trace_test_output(raw_secret: str, root: Path) -> list[Propagation]:
    props = []
    for pattern in ("**/junit*.xml", "**/coverage.xml", "**/.pytest_cache/**", "**/test-results/**"):
        for path in root.glob(pattern):
            if path.is_file() and _grep_for_secret(raw_secret, path):
                props.append(Propagation("test_output", str(path), DESTINATION_WEIGHTS["test_output"]))
    return props


def trace_git_history(raw_secret: str, root: Path) -> list[Propagation]:
    """
    Search git history for the raw secret using `git log -S`.
    -S finds commits that added/removed the string — this catches secrets baked into
    a commit even after the file is cleaned up, which is the most critical exposure
    vector (the secret is permanently in the repo history until a force-push rewrite).
    """
    props = []
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "log", "--oneline", "-S", raw_secret, "--all"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            # One or more commits contain this secret — extremely high severity.
            for line in result.stdout.strip().splitlines():
                commit_hash = line.split()[0] if line else "unknown"
                props.append(
                    Propagation(
                        "git_history_blob",
                        f"git:commit:{commit_hash}",
                        DESTINATION_WEIGHTS["git_history_blob"],
                    )
                )
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return props


def trace_well_known_credential_files(raw_secret: str) -> list[Propagation]:
    """Check well-known local credential stores (AWS credentials, gh config, etc.)."""
    from pathlib import Path

    props = []
    well_known = [
        Path.home() / ".aws" / "credentials",
        Path.home() / ".config" / "gh" / "hosts.yml",
        Path.home() / ".netrc",
    ]
    for path in well_known:
        if _grep_for_secret(raw_secret, path):
            props.append(
                Propagation("aws_credentials_file", str(path), DESTINATION_WEIGHTS["aws_credentials_file"])
            )
    return props


def build_lineage(
    finding: Finding,
    root: Path,
    ci_log_dir: Path | None = None,
    docker_image_tags: list[str] | None = None,
) -> LineageResult:
    result = LineageResult(origin=finding)
    result.propagations.extend(trace_docker_logs(finding.raw_secret, root))
    result.propagations.extend(trace_docker_image_layers(finding.raw_secret, docker_image_tags))
    result.propagations.extend(trace_github_actions_logs(finding.raw_secret, ci_log_dir))
    result.propagations.extend(trace_test_output(finding.raw_secret, root))
    result.propagations.extend(trace_git_history(finding.raw_secret, root))
    result.propagations.extend(trace_well_known_credential_files(finding.raw_secret))
    return result

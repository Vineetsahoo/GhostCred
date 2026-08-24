"""
DAST-style Runtime Integration Tests
=====================================
These tests start the mock provider as a live subprocess, inject secrets
at runtime, run actual GhostCred scan + liveness check + revocation, and
verify the system responds correctly to dynamic environmental changes.

Unlike unit tests, these exercise the running system end-to-end:
  - Mock provider starts as a real HTTP server (subprocess)
  - Secrets are written to a temp directory at runtime (not pre-committed)
  - GhostCred scan runs against the live filesystem state
  - Liveness check calls the live HTTP endpoint
  - Revocation calls the live HTTP endpoint and verifies state change
  - A second scan confirms finding is still reported (GhostCred detects,
    doesn't remove the file — that's the user's job)

Run:
    pytest tests/test_dast_runtime.py -v

Prerequisites:
    pip install flask requests pytest
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).parent.parent.resolve()
MOCK_PROVIDER_SCRIPT = REPO_ROOT / "scripts" / "mock_provider.py"
SALT = "dast-test-salt"

# Demo token — matches mock_provider.py tokens dict
DEMO_GITHUB_TOKEN = "ghp_fakeDemoToken1234567890abcdefghijABCD"
DEMO_OPENAI_TOKEN = "sk-proj-FAKEKEYFORTHISDEMOONLYNOTREAL1234"
MOCK_URL = "http://localhost:5001"


# ── helpers ───────────────────────────────────────────────────────────────────

def _wait_for_port(port: int, timeout: float = 8.0) -> bool:
    """Block until the port is accepting connections or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("localhost", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _provider_ready() -> bool:
    try:
        r = requests.get(f"{MOCK_URL}/status", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mock_provider():
    """Start the mock provider as a subprocess for the duration of this module."""
    proc = subprocess.Popen(
        [sys.executable, str(MOCK_PROVIDER_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not _wait_for_port(5001, timeout=10):
        proc.terminate()
        pytest.skip("Mock provider failed to start on port 5001")
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def runtime_repo(tmp_path: Path):
    """
    Create a fresh directory with secrets injected at runtime.
    This is the DAST equivalent of a live environment — secrets exist
    only in memory / temp files, not pre-committed to the repo.
    """
    (tmp_path / ".env").write_text(
        f"GITHUB_TOKEN={DEMO_GITHUB_TOKEN}\n"
        f"OPENAI_API_KEY={DEMO_OPENAI_TOKEN}\n"
    )
    (tmp_path / "config.py").write_text(
        f'GITHUB_TOKEN = "{DEMO_GITHUB_TOKEN}"\n'
    )
    ci_logs = tmp_path / "ci-logs"
    ci_logs.mkdir()
    (ci_logs / "run-latest.txt").write_text(
        f"::set-env name=GITHUB_TOKEN::{DEMO_GITHUB_TOKEN}\n"
    )
    return tmp_path


# ── DAST tests ────────────────────────────────────────────────────────────────

class TestDastRuntimeScan:
    """
    D1 — Scanner detects a secret injected at runtime (not pre-committed).
    Confirms GhostCred works against dynamically created files, not just
    files that existed when the process started.
    """

    def test_detects_runtime_injected_secret(self, runtime_repo: Path):
        from ghostcred.scanners import scan_codebase

        # Inject a new secret AFTER the fixture created the directory
        new_file = runtime_repo / "runtime_config.py"
        new_file.write_text(f'API_KEY = "{DEMO_GITHUB_TOKEN}"\n')

        findings = scan_codebase(runtime_repo, salt=SALT)
        providers = [f.provider for f in findings]
        assert "github_pat" in providers, "Should detect GitHub PAT in dynamically created file"

    def test_detects_secret_added_to_existing_env_file(self, runtime_repo: Path):
        """Simulate a developer appending a secret to .env mid-session."""
        from ghostcred.scanners import scan_codebase

        env_file = runtime_repo / ".env"
        # Append a new secret to the already-existing .env at runtime
        with env_file.open("a") as f:
            f.write(f'STRIPE_KEY=sk_live_{"x" * 24}\n')

        findings = scan_codebase(runtime_repo, salt=SALT)
        assert any(f.provider == "stripe_key" for f in findings)

    def test_scan_reflects_file_deletion(self, runtime_repo: Path):
        """After deleting a file, a new scan should not find its secrets."""
        from ghostcred.scanners import scan_codebase

        leaked = runtime_repo / "leaked.py"
        leaked.write_text(f'TOKEN = "{DEMO_GITHUB_TOKEN}"\n')

        before = scan_codebase(runtime_repo, salt=SALT)
        assert any(f.source_path == str(leaked) for f in before)

        leaked.unlink()  # simulate the developer removing the file

        after = scan_codebase(runtime_repo, salt=SALT)
        assert not any(f.source_path == str(leaked) for f in after), (
            "After file deletion, scan should not report secrets from deleted file"
        )


class TestDastLivenessCheck:
    """
    D2 — Liveness check against running mock provider.
    Confirms the HTTP check actually works against a live endpoint,
    not just a mocked return value.
    """

    def test_github_token_is_live_against_running_provider(self, mock_provider):
        from ghostcred.revocation.github_revoker import GitHubRevoker

        revoker = GitHubRevoker()
        assert revoker.check_live(DEMO_GITHUB_TOKEN) is True

    def test_unknown_token_is_not_live(self, mock_provider):
        from ghostcred.revocation.github_revoker import GitHubRevoker

        revoker = GitHubRevoker()
        assert revoker.check_live("ghp_" + "z" * 37) is False

    def test_liveness_returns_false_when_provider_is_down(self):
        """Without the provider running, check_live must return False, not raise."""
        from ghostcred.revocation.github_revoker import GitHubRevoker
        import unittest.mock as mock
        import requests as req_module

        revoker = GitHubRevoker()
        # Patch at the module where requests is used, and raise requests.RequestException
        with mock.patch(
            "ghostcred.revocation.github_revoker.requests.get",
            side_effect=req_module.RequestException("connection refused"),
        ):
            result = revoker.check_live(DEMO_GITHUB_TOKEN)
        assert result is False


class TestDastRevocationFlow:
    """
    D3 — Full revocation flow against the live mock provider.
    Confirms state transitions: LIVE → revoked → 401.
    """

    def test_revocation_changes_token_state(self, mock_provider):
        """Token is live, revoke it, confirm it's dead — all against the real HTTP server."""
        from ghostcred.revocation.github_revoker import GitHubRevoker

        revoker = GitHubRevoker()

        # Confirm live
        assert revoker.check_live(DEMO_GITHUB_TOKEN) is True

        # Revoke
        result = revoker.revoke(DEMO_GITHUB_TOKEN, fingerprint="dast-test-fp", dry_run=False)
        assert result.success is True

        # Confirm dead
        assert revoker.check_live(DEMO_GITHUB_TOKEN) is False

    def test_status_endpoint_reflects_revocation(self, mock_provider):
        """The /status endpoint should show REVOKED after revocation."""
        # Token was revoked in the previous test — check the status endpoint
        r = requests.get(f"{MOCK_URL}/status")
        assert r.status_code == 200
        status_map = r.json()
        # Find the entry for our token (displayed truncated)
        demo_entry = next(
            (v for k, v in status_map.items() if DEMO_GITHUB_TOKEN[:20] in k),
            None,
        )
        assert demo_entry == "REVOKED", f"Expected REVOKED, got: {status_map}"

    def test_dry_run_does_not_change_token_state(self, mock_provider, tmp_path):
        """
        Dry run on the OpenAI token — state must not change.
        Specifically tests that dry_run=True never calls DELETE.
        """
        from ghostcred.revocation.openai_revoker import OpenAIRevoker

        revoker = OpenAIRevoker()

        # Check initial state via status endpoint
        r_before = requests.get(f"{MOCK_URL}/status").json()
        openai_before = next(
            (v for k, v in r_before.items() if DEMO_OPENAI_TOKEN[:20] in k), None
        )

        # Dry run — must not call DELETE
        result = revoker.revoke(DEMO_OPENAI_TOKEN, fingerprint="dry-test", dry_run=True)
        assert result.dry_run is True
        assert result.success is True

        # State must be unchanged
        r_after = requests.get(f"{MOCK_URL}/status").json()
        openai_after = next(
            (v for k, v in r_after.items() if DEMO_OPENAI_TOKEN[:20] in k), None
        )
        assert openai_before == openai_after, "Dry run must not change token state"


class TestDastLineageRuntime:
    """
    D4 — Lineage tracking against files created at runtime.
    Confirms the blast radius grows correctly as secrets propagate
    into new locations during a live session.
    """

    def test_blast_radius_grows_as_secret_propagates(self, runtime_repo: Path):
        from ghostcred.scanners import scan_codebase
        from ghostcred.lineage import build_lineage

        findings = scan_codebase(runtime_repo, salt=SALT)
        github_finding = next(
            (f for f in findings if f.provider == "github_pat"), None
        )
        assert github_finding is not None

        # Initial lineage — ci-log exists in the fixture
        lin1 = build_lineage(github_finding, root=runtime_repo, ci_log_dir=runtime_repo / "ci-logs")
        score1 = lin1.blast_radius_score

        # Simulate secret propagating into a docker build log at runtime
        (runtime_repo / "docker-build.log").write_text(
            f"Step 3: ENV GITHUB_TOKEN={DEMO_GITHUB_TOKEN}\n"
        )

        # Re-run lineage — score must be higher
        lin2 = build_lineage(github_finding, root=runtime_repo, ci_log_dir=runtime_repo / "ci-logs")
        score2 = lin2.blast_radius_score

        assert score2 > score1, (
            f"Blast radius should increase after secret propagates to docker log "
            f"(was {score1}, got {score2})"
        )

    def test_blast_radius_score_range(self, runtime_repo: Path):
        from ghostcred.scanners import scan_codebase
        from ghostcred.lineage import build_lineage

        findings = scan_codebase(runtime_repo, salt=SALT)
        github_finding = next(f for f in findings if f.provider == "github_pat")
        lin = build_lineage(github_finding, root=runtime_repo)

        assert 0 <= lin.blast_radius_score <= 100

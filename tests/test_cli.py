"""
CLI tests — exercises every command via Click's CliRunner so no subprocess is spawned
and stdout/exit codes are directly inspectable.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ghostcred.cli import main


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def clean_dir(tmp_path: Path):
    """A temp directory with NO secrets — used to test clean-scan paths."""
    (tmp_path / "app.py").write_text("print('hello world')\n")
    return tmp_path


@pytest.fixture()
def dirty_dir(tmp_path: Path):
    """A temp directory with ONE obvious secret."""
    (tmp_path / ".env").write_text("GITHUB_TOKEN=ghp_" + "X" * 36 + "\n")
    return tmp_path


# ---------------------------------------------------------------------------
# ghostcred scan — basic behaviour
# ---------------------------------------------------------------------------

class TestScanCommand:
    def test_clean_scan_exits_zero(self, runner, clean_dir):
        result = runner.invoke(main, [
            "scan", "--path", str(clean_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
        ])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_dirty_scan_reports_finding(self, runner, dirty_dir):
        result = runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
        ])
        assert result.exit_code == 0
        assert "github_pat" in result.output

    def test_fail_on_finding_exits_nonzero(self, runner, dirty_dir):
        result = runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--fail-on-finding",
        ])
        assert result.exit_code == 1
        assert "blocking" in result.output

    def test_clean_scan_with_fail_on_finding_exits_zero(self, runner, clean_dir):
        result = runner.invoke(main, [
            "scan", "--path", str(clean_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--fail-on-finding",
        ])
        assert result.exit_code == 0

    def test_min_confidence_override_filters_low_confidence(self, runner, tmp_path):
        # generic_bearer_token has base_confidence=0.5; even with the 'auth' keyword
        # boost (+0.15 → 0.65), it stays below a threshold of 0.8.
        (tmp_path / "request.py").write_text(
            'headers = {"Authorization": "Bearer ' + "s" * 25 + '"}\n'
        )
        result = runner.invoke(main, [
            "scan", "--path", str(tmp_path),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--min-confidence", "0.8",
        ])
        assert result.exit_code == 0
        assert "generic_bearer_token" not in result.output

    def test_min_confidence_low_includes_finding(self, runner, dirty_dir):
        result = runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--min-confidence", "0.5",
        ])
        assert "github_pat" in result.output

    def test_json_out_creates_valid_report(self, runner, dirty_dir):
        report_path = dirty_dir / "report.json"
        result = runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--json-out", str(report_path),
        ])
        assert result.exit_code == 0
        assert report_path.exists()
        data = json.loads(report_path.read_text())
        assert "findings" in data
        assert "revocations" in data
        assert "duration_seconds" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1

    def test_json_report_never_contains_raw_secret(self, runner, dirty_dir):
        """The most important safety invariant — raw secrets must never hit disk."""
        raw_secret = "ghp_" + "X" * 36
        report_path = dirty_dir / "report.json"
        runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--json-out", str(report_path),
        ])
        report_text = report_path.read_text()
        assert raw_secret not in report_text

    def test_json_report_finding_schema(self, runner, dirty_dir):
        report_path = dirty_dir / "report.json"
        runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--json-out", str(report_path),
        ])
        data = json.loads(report_path.read_text())
        f = data["findings"][0]
        required_keys = {"provider", "fingerprint", "redacted", "source_path",
                         "source_kind", "line", "confidence", "revocable", "detected_at"}
        assert required_keys.issubset(set(f.keys()))
        assert "raw_secret" not in f

    def test_lineage_included_in_json_report(self, runner, dirty_dir):
        report_path = dirty_dir / "report.json"
        runner.invoke(main, [
            "scan", "--path", str(dirty_dir),
            "--no-ai-toolchain", "--lineage", "--no-metrics",
            "--json-out", str(report_path),
        ])
        data = json.loads(report_path.read_text())
        assert "lineage" in data["findings"][0]
        lineage = data["findings"][0]["lineage"]
        assert "blast_radius_score" in lineage
        assert "propagations" in lineage
        assert "origin" in lineage

    def test_ai_toolchain_flag_included(self, runner, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(
            json.dumps({"env": {"OPENAI_API_KEY": "sk-proj-" + "y" * 40}})
        )
        result = runner.invoke(main, [
            "scan", "--path", str(tmp_path),
            "--ai-toolchain", "--no-global-configs", "--no-lineage", "--no-metrics",
        ])
        assert "openai_api_key" in result.output
        assert "AI-TOOLCHAIN" in result.output

    def test_no_ai_toolchain_skips_mcp_files(self, runner, tmp_path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(
            json.dumps({"env": {"OPENAI_API_KEY": "sk-proj-" + "y" * 40}})
        )
        result = runner.invoke(main, [
            "scan", "--path", str(tmp_path),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
        ])
        assert "openai_api_key" not in result.output

    def test_revoke_live_with_dead_secret_skips_revocation(self, runner, dirty_dir):
        with patch("ghostcred.cli.REVOKER_REGISTRY") as mock_reg:
            mock_revoker = MagicMock()
            mock_revoker.check_live.return_value = False
            mock_reg.__contains__ = lambda self, x: True
            mock_reg.__getitem__ = lambda self, x: mock_revoker
            result = runner.invoke(main, [
                "scan", "--path", str(dirty_dir),
                "--no-ai-toolchain", "--no-lineage", "--no-metrics",
                "--revoke-live", "--no-dry-run",
            ])
        assert "already inactive" in result.output

    def test_revoke_live_with_live_secret_calls_revoke(self, runner, dirty_dir):
        with patch("ghostcred.cli.REVOKER_REGISTRY") as mock_reg:
            mock_revoker = MagicMock()
            mock_revoker.check_live.return_value = True
            mock_revoker.revoke.return_value = MagicMock(
                success=True, detail="revoked ok", dry_run=False
            )
            mock_reg.__contains__ = lambda self, x: True
            mock_reg.__getitem__ = lambda self, x: mock_revoker
            result = runner.invoke(main, [
                "scan", "--path", str(dirty_dir),
                "--no-ai-toolchain", "--no-lineage", "--no-metrics",
                "--revoke-live", "--no-dry-run",
            ])
        assert "revocation" in result.output


# ---------------------------------------------------------------------------
# ghostcred revoke — manual revoke command
# ---------------------------------------------------------------------------

class TestRevokeCommand:
    def test_revoke_dry_run_inactive_secret(self, runner):
        with patch("ghostcred.cli.REVOKER_REGISTRY") as mock_reg:
            mock_revoker = MagicMock()
            mock_revoker.check_live.return_value = False
            mock_reg.__contains__ = lambda self, x: True
            mock_reg.__getitem__ = lambda self, x: mock_revoker
            mock_reg.keys.return_value = ["github_pat"]
            result = runner.invoke(main, [
                "revoke", "ghp_fake_secret_value",
                "--provider", "github_pat",
                "--dry-run",
            ])
        assert result.exit_code == 0
        assert "inactive" in result.output

    def test_revoke_dry_run_live_secret(self, runner):
        with patch("ghostcred.cli.REVOKER_REGISTRY") as mock_reg:
            mock_revoker = MagicMock()
            mock_revoker.check_live.return_value = True
            mock_revoker.revoke.return_value = MagicMock(
                success=True, detail="DRY RUN: would revoke", dry_run=True
            )
            mock_reg.__contains__ = lambda self, x: True
            mock_reg.__getitem__ = lambda self, x: mock_revoker
            mock_reg.keys.return_value = ["github_pat"]
            result = runner.invoke(main, [
                "revoke", "ghp_live_secret_value",
                "--provider", "github_pat",
                "--dry-run",
            ])
        assert result.exit_code == 0
        assert "✅" in result.output or "DRY RUN" in result.output

    def test_revoke_failed_shows_error_icon(self, runner):
        with patch("ghostcred.cli.REVOKER_REGISTRY") as mock_reg:
            mock_revoker = MagicMock()
            mock_revoker.check_live.return_value = True
            mock_revoker.revoke.return_value = MagicMock(
                success=False, detail="admin key not configured", dry_run=False
            )
            mock_reg.__contains__ = lambda self, x: True
            mock_reg.__getitem__ = lambda self, x: mock_revoker
            mock_reg.keys.return_value = ["openai_api_key"]
            result = runner.invoke(main, [
                "revoke", "sk-fake",
                "--provider", "openai_api_key",
                "--no-dry-run",
            ])
        assert "❌" in result.output


# ---------------------------------------------------------------------------
# ghostcred list-providers
# ---------------------------------------------------------------------------

class TestListProvidersCommand:
    def test_lists_active_providers(self, runner):
        result = runner.invoke(main, ["list-providers"])
        assert result.exit_code == 0
        assert "github_pat" in result.output
        assert "openai_api_key" in result.output
        assert "anthropic_api_key" in result.output

    def test_aws_not_in_providers(self, runner):
        result = runner.invoke(main, ["list-providers"])
        assert "aws_access_key" not in result.output


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_secret_in_two_files_deduped(self, runner, tmp_path):
        """Same fingerprint from two files should only appear once, keeping the higher-confidence hit."""
        secret = "ghp_" + "D" * 36
        (tmp_path / "a.py").write_text(f"TOKEN = '{secret}'\n")
        (tmp_path / "b.py").write_text(f"TOKEN = '{secret}'\n")
        report_path = tmp_path / "report.json"
        runner.invoke(main, [
            "scan", "--path", str(tmp_path),
            "--no-ai-toolchain", "--no-lineage", "--no-metrics",
            "--json-out", str(report_path),
        ])
        data = json.loads(report_path.read_text())
        pat_findings = [f for f in data["findings"] if f["provider"] == "github_pat"]
        assert len(pat_findings) == 1, "Same secret in two files should be deduped to one finding"

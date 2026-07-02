"""
GhostCred test suite — scanners, lineage, revocation, and CLI smoke tests.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostcred.scanners import scan_ai_toolchain, scan_codebase
from ghostcred.scanners.base import Finding, fingerprint, redact, scan_text

SALT = "test-salt"


# ---------------------------------------------------------------------------
# Pattern / detection tests
# ---------------------------------------------------------------------------

class TestCodeScanner:
    def test_detects_openai_key_in_env_file(self, tmp_path: Path):
        (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx1234567890AB\n")
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "openai_api_key" for f in findings)

    def test_detects_anthropic_key_in_code(self, tmp_path: Path):
        (tmp_path / "main.py").write_text(
            'client = Anthropic(api_key="sk-ant-api03-' + "a" * 95 + '")\n'
        )
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "anthropic_api_key" for f in findings)

    def test_detects_github_pat_in_yaml(self, tmp_path: Path):
        (tmp_path / "config.yml").write_text("github_token: ghp_" + "A" * 36 + "\n")
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "github_pat" for f in findings)

    def test_detects_aws_access_key(self, tmp_path: Path):
        (tmp_path / "terraform.tfvars").write_text('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "aws_access_key" for f in findings)

    def test_detects_stripe_key_in_python(self, tmp_path: Path):
        (tmp_path / "payments.py").write_text('stripe.api_key = "sk_live_' + "x" * 24 + '"\n')
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "stripe_key" for f in findings)

    def test_detects_private_key_block(self, tmp_path: Path):
        # Use a .py extension so code_scanner picks it up (`.pem` is not in CODE_EXTENSIONS).
        (tmp_path / "utils.py").write_text("PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----'\n")
        findings = scan_codebase(tmp_path, salt=SALT)
        assert any(f.provider == "private_key_block" for f in findings)

    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('const key = "ghp_' + "A" * 36 + '";\n')
        findings = scan_codebase(tmp_path, salt=SALT)
        assert not findings

    def test_skips_dotgit_directory(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-push").write_text("GITHUB_TOKEN=ghp_" + "A" * 36 + "\n")
        findings = scan_codebase(tmp_path, salt=SALT)
        assert not findings


class TestAIToolchainScanner:
    def test_catches_mcp_config_gitleaks_would_miss(self, tmp_path: Path):
        """Core differentiator: project-local MCP config with a raw API key."""
        proj = tmp_path / "project"
        proj.mkdir()
        mcp_config = {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_" + "a" * 36},
                }
            }
        }
        (proj / "mcp.json").write_text(json.dumps(mcp_config))
        findings = scan_ai_toolchain(tmp_path, salt=SALT, include_global_configs=False)
        assert any(f.provider == "github_pat" and f.source_kind == "mcp_config" for f in findings)

    def test_catches_cursor_settings_file(self, tmp_path: Path):
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "mcp.json").write_text(
            json.dumps({"env": {"OPENAI_API_KEY": "sk-proj-" + "x" * 40}})
        )
        findings = scan_ai_toolchain(tmp_path, salt=SALT, include_global_configs=False)
        assert any(f.provider == "openai_api_key" for f in findings)

    def test_catches_vscode_settings_file(self, tmp_path: Path):
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "settings.json").write_text(
            json.dumps({"github.token": "ghp_" + "B" * 36})
        )
        findings = scan_ai_toolchain(tmp_path, salt=SALT, include_global_configs=False)
        assert any(f.provider == "github_pat" for f in findings)

    def test_shell_history_scanning(self, tmp_path: Path):
        history_file = tmp_path / ".zsh_history"
        history_file.write_text(
            ": 1700000000:0;export ANTHROPIC_API_KEY=sk-ant-api03-" + "a" * 95 + "\n"
        )
        with patch("ghostcred.scanners.ai_toolchain_scanner._shell_history_files", return_value=[history_file]):
            findings = scan_ai_toolchain(tmp_path, salt=SALT, include_global_configs=False)
        assert any(f.provider == "anthropic_api_key" and f.source_kind == "shell_history" for f in findings)

    def test_mcp_findings_not_double_counted_in_code_scan(self, tmp_path: Path):
        """MCP configs must be excluded from code_scanner to avoid duplicate findings."""
        (tmp_path / "mcp.json").write_text(
            json.dumps({"env": {"OPENAI_API_KEY": "sk-proj-" + "x" * 40}})
        )
        code_findings = scan_codebase(tmp_path, salt=SALT)
        ai_findings = scan_ai_toolchain(tmp_path, salt=SALT, include_global_configs=False)
        # code_scanner should not report the mcp.json key
        assert not any(
            f.source_kind == "mcp_config" for f in code_findings
        ), "code_scanner should not label files as mcp_config"
        # ai_toolchain_scanner should
        assert any(f.source_kind == "mcp_config" for f in ai_findings)


# ---------------------------------------------------------------------------
# Redaction / safety tests
# ---------------------------------------------------------------------------

class TestRedactionAndSafety:
    def test_redaction_never_leaks_full_secret(self):
        text = "token = 'ghp_" + "b" * 36 + "'"
        findings = scan_text(text, "inline.py", "code", SALT)
        assert findings
        for f in findings:
            assert f.raw_secret not in f.redacted
            assert f.redacted.count("*") > 0

    def test_redact_short_secret(self):
        assert redact("short") == "*****"

    def test_redact_preserves_prefix_and_suffix(self):
        secret = "abcdef" + "x" * 15 + "1234"
        result = redact(secret)
        assert result.startswith("abcdef")
        assert result.endswith("1234")
        assert "*" in result

    def test_fingerprint_is_deterministic(self):
        s = "some-secret"
        assert fingerprint(s, "salt1") == fingerprint(s, "salt1")

    def test_fingerprint_differs_with_different_salt(self):
        s = "some-secret"
        assert fingerprint(s, "salt1") != fingerprint(s, "salt2")

    def test_finding_to_public_dict_excludes_raw_secret(self):
        text = "OPENAI_API_KEY=sk-proj-" + "y" * 40
        findings = scan_text(text, "test.env", "env", SALT)
        assert findings
        for f in findings:
            d = f.to_public_dict()
            assert "raw_secret" not in d

    def test_low_confidence_aws_generic_is_filtered(self):
        # aws_secret_key pattern without contextual keyword must be dropped
        text = "just some random 40 character looking string " + "a" * 40
        findings = scan_text(text, "noise.txt", "code", SALT)
        assert not any(f.provider == "aws_secret_key" for f in findings)


# ---------------------------------------------------------------------------
# Lineage tests
# ---------------------------------------------------------------------------

class TestLineageTracker:
    def test_lineage_detects_secret_in_docker_log(self, tmp_path: Path):
        from ghostcred.lineage import build_lineage
        secret = "ghp_" + "c" * 36
        log_file = tmp_path / "docker-build.log"
        log_file.write_text(f"Step 3/5 : RUN echo {secret}\n ---> Running in abc\n")
        # create a minimal Finding
        findings = scan_text(f"token = '{secret}'", "test.py", "code", SALT)
        assert findings
        result = build_lineage(findings[0], tmp_path)
        assert any(p.kind == "docker_build_log" for p in result.propagations)
        assert result.blast_radius_score > 10

    def test_lineage_blast_radius_increases_with_more_propagations(self, tmp_path: Path):
        from ghostcred.lineage import build_lineage, LineageResult, Propagation
        from ghostcred.scanners.base import Finding
        import time

        f = Finding(
            provider="github_pat",
            fingerprint="abc123",
            redacted="ghp_****",
            source_path="test.py",
            source_kind="code",
            line=1,
            confidence=0.95,
            revocable=True,
            raw_secret="ghp_" + "d" * 36,
            detected_at=time.time(),
        )
        result = LineageResult(origin=f)
        assert result.blast_radius_score == 10  # just the base
        result.propagations.append(Propagation("docker_build_log", "build.log", 25))
        assert result.blast_radius_score == 35
        result.propagations.append(Propagation("github_actions_log", "ci.log", 40))
        assert result.blast_radius_score == 75

    def test_lineage_score_capped_at_100(self, tmp_path: Path):
        from ghostcred.lineage import LineageResult, Propagation
        from ghostcred.scanners.base import Finding
        import time

        f = Finding(
            provider="github_pat",
            fingerprint="xyz",
            redacted="ghp_****",
            source_path="x.py",
            source_kind="code",
            line=1,
            confidence=0.9,
            revocable=True,
            raw_secret="ghp_" + "e" * 36,
            detected_at=time.time(),
        )
        result = LineageResult(origin=f, propagations=[
            Propagation("docker_image_layer", "img", 30),
            Propagation("github_actions_log", "ci.log", 40),
            Propagation("git_history_blob", "git:abc", 35),
        ])
        assert result.blast_radius_score == 100

    def test_lineage_public_dict_has_no_raw_secret(self, tmp_path: Path):
        from ghostcred.lineage import build_lineage
        secret = "ghp_" + "f" * 36
        findings = scan_text(f"x='{secret}'", "test.py", "code", SALT)
        result = build_lineage(findings[0], tmp_path)
        d = result.to_public_dict()
        assert secret not in json.dumps(d)


# ---------------------------------------------------------------------------
# Revocation tests (mocked)
# ---------------------------------------------------------------------------

class TestRevocationMocked:
    def test_github_revoker_dry_run_always_succeeds(self):
        from ghostcred.revocation.github_revoker import GitHubRevoker
        revoker = GitHubRevoker()
        result = revoker.revoke("ghp_fake", "fp123", dry_run=True)
        assert result.success
        assert result.dry_run

    def test_openai_revoker_dry_run(self):
        from ghostcred.revocation.openai_revoker import OpenAIRevoker
        revoker = OpenAIRevoker()
        result = revoker.revoke("sk-proj-fake", "fp456", dry_run=True)
        assert result.success
        assert result.dry_run

    def test_anthropic_revoker_dry_run(self):
        from ghostcred.revocation.anthropic_revoker import AnthropicRevoker
        revoker = AnthropicRevoker()
        result = revoker.revoke("sk-ant-api03-fake", "fp789", dry_run=True)
        assert result.success
        assert result.dry_run

    def test_github_check_live_returns_false_on_request_error(self):
        from ghostcred.revocation.github_revoker import GitHubRevoker
        import requests
        revoker = GitHubRevoker()
        with patch("ghostcred.revocation.github_revoker.requests.get") as mock_get:
            mock_get.side_effect = requests.RequestException("timeout")
            assert revoker.check_live("ghp_fake") is False
        from ghostcred.revocation import REVOKER_REGISTRY
        # AWS is excluded until the AWS account deployment is set up.
        expected = {"github_pat", "github_fine_grained_pat", "openai_api_key", "anthropic_api_key"}
        assert expected.issubset(set(REVOKER_REGISTRY.keys()))
        assert "aws_access_key" not in REVOKER_REGISTRY


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_default_config_loads_without_file(self, tmp_path: Path):
        from ghostcred.config import GhostCredConfig
        cfg = GhostCredConfig.load(tmp_path)
        assert cfg.min_confidence == 0.6
        assert cfg.dry_run_revocations is True

    def test_config_loaded_from_yml(self, tmp_path: Path):
        from ghostcred.config import GhostCredConfig
        (tmp_path / ".ghostcred.yml").write_text("min_confidence: 0.8\nauto_revoke: true\n")
        cfg = GhostCredConfig.load(tmp_path)
        assert cfg.min_confidence == 0.8
        assert cfg.auto_revoke is True

    def test_salt_from_env(self, tmp_path: Path, monkeypatch):
        from ghostcred.config import GhostCredConfig
        monkeypatch.setenv("GHOSTCRED_SALT", "my-custom-salt")
        cfg = GhostCredConfig.load(tmp_path)
        assert cfg.salt == "my-custom-salt"

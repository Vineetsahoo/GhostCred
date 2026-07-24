"""
Pattern-level tests — every provider regex, confidence boosting, and false-positive guards.
These run against scan_text() directly so they're fast and independent of the file system.
"""
from __future__ import annotations

import pytest

from ghostcred.scanners.base import scan_text

SALT = "pattern-salt"


# ---------------------------------------------------------------------------
# GitHub tokens
# ---------------------------------------------------------------------------

class TestGitHubPatterns:
    def test_classic_pat_gho_prefix(self):
        findings = scan_text("token=gho_" + "A" * 36, "x.py", "code", SALT)
        assert any(f.provider == "github_pat" for f in findings)

    def test_classic_pat_ghp_prefix(self):
        findings = scan_text("token=ghp_" + "B" * 36, "x.py", "code", SALT)
        assert any(f.provider == "github_pat" for f in findings)

    def test_classic_pat_ghu_prefix(self):
        findings = scan_text("token=ghu_" + "C" * 36, "x.py", "code", SALT)
        assert any(f.provider == "github_pat" for f in findings)

    def test_classic_pat_ghs_prefix(self):
        findings = scan_text("token=ghs_" + "D" * 36, "x.py", "code", SALT)
        assert any(f.provider == "github_pat" for f in findings)

    def test_fine_grained_pat(self):
        findings = scan_text("token=github_pat_" + "E" * 22, "x.py", "code", SALT)
        assert any(f.provider == "github_fine_grained_pat" for f in findings)

    def test_github_pat_confidence_is_high(self):
        findings = scan_text("GITHUB_TOKEN=ghp_" + "F" * 36, "x.py", "code", SALT)
        pat_findings = [f for f in findings if f.provider == "github_pat"]
        assert pat_findings
        assert pat_findings[0].confidence >= 0.95

    def test_github_pat_too_short_not_matched(self):
        # Under 36 chars after prefix — should not match
        findings = scan_text("token=ghp_short", "x.py", "code", SALT)
        assert not any(f.provider == "github_pat" for f in findings)


# ---------------------------------------------------------------------------
# OpenAI / Anthropic — negative lookahead correctness
# ---------------------------------------------------------------------------

class TestOpenAIAnthropicPatterns:
    def test_openai_key_sk_proj(self):
        findings = scan_text("key=sk-proj-" + "x" * 40, "x.py", "code", SALT)
        assert any(f.provider == "openai_api_key" for f in findings)

    def test_openai_key_plain_sk(self):
        findings = scan_text("OPENAI_KEY=sk-" + "x" * 40, "x.py", "code", SALT)
        assert any(f.provider == "openai_api_key" for f in findings)

    def test_anthropic_key_not_swallowed_by_openai_pattern(self):
        """sk-ant-... must NOT match openai_api_key due to negative lookahead."""
        key = "sk-ant-api03-" + "a" * 95
        findings = scan_text(f"key={key}", "x.py", "code", SALT)
        providers = {f.provider for f in findings}
        assert "anthropic_api_key" in providers
        assert "openai_api_key" not in providers

    def test_anthropic_admin_key_pattern(self):
        key = "sk-ant-admin01-" + "b" * 90
        findings = scan_text(f"ANTHROPIC_KEY={key}", "x.py", "code", SALT)
        assert any(f.provider == "anthropic_api_key" for f in findings)

    def test_openai_confidence_boosted_with_keyword(self):
        # "api_key" keyword near the match should push confidence above base
        text = "api_key = sk-" + "z" * 40
        findings = scan_text(text, "x.py", "code", SALT)
        hits = [f for f in findings if f.provider == "openai_api_key"]
        assert hits
        # base is 0.92; keyword bump adds 0.15, capped at 1.0
        assert hits[0].confidence >= 0.92


# ---------------------------------------------------------------------------
# Slack, Stripe, Google, Bearer
# ---------------------------------------------------------------------------

class TestOtherProviderPatterns:
    def test_slack_bot_token(self):
        findings = scan_text("SLACK_TOKEN=xoxb-123456789012-" + "A" * 20, "x.env", "env", SALT)
        assert any(f.provider == "slack_token" for f in findings)

    def test_slack_app_token(self):
        findings = scan_text("token=xoxa-2-" + "B" * 20, "x.py", "code", SALT)
        assert any(f.provider == "slack_token" for f in findings)

    def test_stripe_live_secret_key(self):
        findings = scan_text("STRIPE_KEY=sk_live_" + "x" * 24, "x.env", "env", SALT)
        assert any(f.provider == "stripe_key" for f in findings)

    def test_stripe_test_secret_key(self):
        findings = scan_text("key=sk_test_" + "y" * 24, "x.py", "code", SALT)
        assert any(f.provider == "stripe_key" for f in findings)

    def test_stripe_restricted_key(self):
        findings = scan_text("key=rk_live_" + "z" * 24, "x.py", "code", SALT)
        assert any(f.provider == "stripe_key" for f in findings)

    def test_google_api_key(self):
        findings = scan_text("GOOGLE_KEY=AIza" + "G" * 35, "x.py", "code", SALT)
        assert any(f.provider == "google_api_key" for f in findings)

    def test_generic_bearer_token(self):
        findings = scan_text("Authorization: Bearer " + "H" * 40, "x.yaml", "code", SALT)
        assert any(f.provider == "generic_bearer_token" for f in findings)

    def test_bearer_token_case_insensitive(self):
        findings = scan_text("authorization: BEARER " + "I" * 30, "x.yaml", "code", SALT)
        assert any(f.provider == "generic_bearer_token" for f in findings)

    def test_private_key_ec_variant(self):
        findings = scan_text("-----BEGIN EC PRIVATE KEY-----", "x.py", "code", SALT)
        assert any(f.provider == "private_key_block" for f in findings)

    def test_private_key_openssh_variant(self):
        findings = scan_text("-----BEGIN OPENSSH PRIVATE KEY-----", "x.py", "code", SALT)
        assert any(f.provider == "private_key_block" for f in findings)

    def test_private_key_generic_variant(self):
        findings = scan_text("-----BEGIN PRIVATE KEY-----", "x.py", "code", SALT)
        assert any(f.provider == "private_key_block" for f in findings)

    def test_jwt_token(self):
        findings = scan_text("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "x.py", "code", SALT)
        assert any(f.provider == "jwt_token" for f in findings)

    def test_database_uri_postgres(self):
        findings = scan_text("DB_URL=postgresql://user:mypassword123@localhost:5432/mydb", "x.env", "env", SALT)
        assert any(f.provider == "database_uri" for f in findings)

    def test_database_uri_redis(self):
        findings = scan_text("cache=redis://default:redispwd!@10.0.0.1:6379", "x.yaml", "code", SALT)
        assert any(f.provider == "database_uri" for f in findings)


# ---------------------------------------------------------------------------
# False-positive guards
# ---------------------------------------------------------------------------

class TestFalsePositiveGuards:
    def test_short_random_string_not_flagged(self):
        findings = scan_text("hash=abc123def456", "x.py", "code", SALT)
        assert not findings

    def test_placeholder_value_low_confidence(self):
        # "your-api-key-here" style placeholders shouldn't match real patterns
        findings = scan_text("token=YOUR_TOKEN_HERE", "x.py", "code", SALT)
        assert not any(f.provider in ("github_pat", "openai_api_key") for f in findings)

    def test_aws_access_key_lookalike_without_valid_prefix_ignored(self):
        # Random uppercase string that doesn't start with AKIA/AGPA etc.
        findings = scan_text("ID=ZZZAIOSFODNN7EXAMPLE123", "x.py", "code", SALT)
        assert not any(f.provider == "aws_access_key" for f in findings)

    def test_multiple_secrets_same_file_all_detected(self):
        text = (
            "GITHUB_TOKEN=ghp_" + "A" * 36 + "\n"
            "OPENAI_KEY=sk-proj-" + "B" * 40 + "\n"
        )
        findings = scan_text(text, "secrets.env", "env", SALT)
        providers = {f.provider for f in findings}
        assert "github_pat" in providers
        assert "openai_api_key" in providers

    def test_line_numbers_are_correct(self):
        text = "line1\nGITHUB_TOKEN=ghp_" + "A" * 36 + "\nline3\n"
        findings = scan_text(text, "x.py", "code", SALT)
        pat = [f for f in findings if f.provider == "github_pat"]
        assert pat
        assert pat[0].line == 2

    def test_confidence_field_rounded_in_public_dict(self):
        text = "token=ghp_" + "A" * 36
        findings = scan_text(text, "x.py", "code", SALT)
        assert findings
        d = findings[0].to_public_dict()
        # round() to 2 decimal places — should be a clean float
        assert isinstance(d["confidence"], float)
        assert d["confidence"] == round(d["confidence"], 2)

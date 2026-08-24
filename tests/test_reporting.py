"""
ReportService tests — generation point, SARIF output, diff, and delivery.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ghostcred.reporting import ReportService, ScanReport
from ghostcred.revocation.base import RevocationResult
from ghostcred.scanners.base import Finding, fingerprint

SALT = "report-test-salt"


def _make_finding(
    provider: str = "github_pat",
    source_kind: str = "code",
    source_path: str = "src/app.py",
    line: int = 10,
    confidence: float = 0.95,
    secret: str = "ghp_" + "A" * 36,
) -> Finding:
    return Finding(
        provider=provider,
        fingerprint=fingerprint(secret, SALT),
        redacted=f"{secret[:6]}****{secret[-4:]}",
        source_path=source_path,
        source_kind=source_kind,
        line=line,
        confidence=confidence,
        revocable=True,
        raw_secret=secret,
        detected_at=time.time(),
    )


def _make_revocation(provider: str = "github_pat", success: bool = True) -> RevocationResult:
    return RevocationResult(
        provider=provider,
        fingerprint="fp-test-123",
        success=success,
        detail="DRY RUN: would revoke",
        dry_run=True,
    )


# ── build() ──────────────────────────────────────────────────────────────────

class TestReportServiceBuild:
    def test_build_returns_scan_report(self):
        svc = ReportService()
        f = _make_finding()
        report = svc.build(root="/project", findings=[f], duration_seconds=1.5)
        assert isinstance(report, ScanReport)
        assert report.root == "/project"
        assert report.duration_seconds == 1.5
        assert len(report.findings) == 1

    def test_build_embeds_lineage_from_map(self):
        svc = ReportService()
        f = _make_finding()
        lineage_data = {"blast_radius_score": 65, "propagations": [{"kind": "docker_build_log"}]}
        svc.build(root="/p", findings=[f], lineage_map={f.fingerprint: lineage_data})
        assert svc._report.findings[0]["lineage"]["blast_radius_score"] == 65

    def test_build_finding_without_lineage_has_no_lineage_key(self):
        svc = ReportService()
        f = _make_finding()
        svc.build(root="/p", findings=[f])
        assert "lineage" not in svc._report.findings[0]

    def test_build_accepts_revocationresult_objects(self):
        svc = ReportService()
        f = _make_finding()
        r = _make_revocation()
        svc.build(root="/p", findings=[f], revocations=[r])
        assert len(svc._report.revocations) == 1
        assert svc._report.revocations[0]["success"] is True

    def test_build_accepts_revocation_dicts(self):
        """Service layer must handle plain dicts as well as RevocationResult objects."""
        svc = ReportService()
        f = _make_finding()
        rev_dict = {"provider": "github_pat", "fingerprint": "fp", "success": True,
                    "detail": "ok", "dry_run": True}
        svc.build(root="/p", findings=[f], revocations=[rev_dict])
        assert svc._report.revocations[0]["success"] is True

    def test_build_with_empty_findings(self):
        svc = ReportService()
        report = svc.build(root="/p", findings=[])
        assert report.findings == []
        assert report.revocations == []

    def test_metadata_stored_in_report(self):
        svc = ReportService()
        svc.build(root="/p", findings=[], metadata={"dry_run": True, "threshold": 0.7})
        assert svc._report.metadata["dry_run"] is True
        assert svc._report.metadata["threshold"] == 0.7

    def test_to_dict_has_all_required_keys(self):
        svc = ReportService()
        f = _make_finding()
        svc.build(root="/p", findings=[f])
        d = svc._report.to_dict()
        assert {"root", "generated_at", "duration_seconds", "findings", "revocations", "metadata"} \
               == set(d.keys())


# ── write() ──────────────────────────────────────────────────────────────────

class TestReportServiceWrite:
    def test_write_creates_json_file(self, tmp_path: Path):
        out = tmp_path / "report.json"
        svc = ReportService(report_path=out)
        f = _make_finding()
        svc.build(root=str(tmp_path), findings=[f])
        result = svc.write()
        assert result == out
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data["findings"]) == 1

    def test_write_returns_none_when_no_path(self):
        svc = ReportService()
        svc.build(root="/p", findings=[_make_finding()])
        assert svc.write() is None

    def test_write_returns_none_when_no_report_built(self, tmp_path: Path):
        svc = ReportService(report_path=tmp_path / "r.json")
        assert svc.write() is None

    def test_written_report_contains_raw_secret(self, tmp_path: Path):
        """raw_secret must be present in the on-disk report for downstream redaction."""
        secret = "ghp_" + "B" * 36
        out = tmp_path / "report.json"
        svc = ReportService(report_path=out)
        svc.build(root=str(tmp_path), findings=[_make_finding(secret=secret)])
        svc.write()
        assert secret in out.read_text()

    def test_written_report_duration_seconds(self, tmp_path: Path):
        out = tmp_path / "report.json"
        svc = ReportService(report_path=out)
        svc.build(root=str(tmp_path), findings=[], duration_seconds=4.2)
        svc.write()
        data = json.loads(out.read_text())
        assert data["duration_seconds"] == 4.2


# ── write_sarif() ─────────────────────────────────────────────────────────────

class TestReportServiceSarif:
    def test_sarif_file_is_valid_structure(self, tmp_path: Path):
        sarif_path = tmp_path / "results.sarif"
        svc = ReportService(sarif_path=sarif_path)
        f = _make_finding(confidence=0.95)
        svc.build(root=str(tmp_path), findings=[f])
        svc.write_sarif()
        data = json.loads(sarif_path.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 1

    def test_sarif_high_confidence_is_error_level(self, tmp_path: Path):
        sarif_path = tmp_path / "r.sarif"
        svc = ReportService(sarif_path=sarif_path)
        svc.build(root=str(tmp_path), findings=[_make_finding(confidence=0.95)])
        svc.write_sarif()
        result = json.loads(sarif_path.read_text())["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_sarif_low_confidence_is_warning_level(self, tmp_path: Path):
        sarif_path = tmp_path / "r.sarif"
        svc = ReportService(sarif_path=sarif_path)
        svc.build(root=str(tmp_path), findings=[_make_finding(confidence=0.75)])
        svc.write_sarif()
        result = json.loads(sarif_path.read_text())["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_sarif_returns_none_when_no_path(self):
        svc = ReportService()
        svc.build(root="/p", findings=[_make_finding()])
        assert svc.write_sarif() is None

    def test_sarif_location_points_to_correct_file(self, tmp_path: Path):
        sarif_path = tmp_path / "r.sarif"
        svc = ReportService(sarif_path=sarif_path)
        f = _make_finding(source_path=str(tmp_path / "src" / "app.py"))
        svc.build(root=str(tmp_path), findings=[f])
        svc.write_sarif()
        location = json.loads(sarif_path.read_text())["runs"][0]["results"][0] \
            ["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "app.py" in location


# ── print_summary() ──────────────────────────────────────────────────────────

class TestReportServiceSummary:
    def test_summary_shows_finding_count(self, capsys):
        svc = ReportService()
        svc.build(root="/p", findings=[_make_finding(), _make_finding(provider="openai_api_key")])
        svc.print_summary()
        out = capsys.readouterr().out
        assert "2 finding(s)" in out

    def test_summary_shows_clean_when_no_findings(self, capsys):
        svc = ReportService()
        svc.build(root="/p", findings=[])
        svc.print_summary()
        out = capsys.readouterr().out
        assert "No secrets found" in out

    def test_summary_shows_blast_radius(self, capsys):
        svc = ReportService()
        f = _make_finding()
        svc.build(
            root="/p",
            findings=[f],
            lineage_map={f.fingerprint: {"blast_radius_score": 75, "propagations": []}},
        )
        svc.print_summary()
        out = capsys.readouterr().out
        assert "75" in out

    def test_summary_handles_no_report(self, capsys):
        svc = ReportService()
        svc.print_summary()
        out = capsys.readouterr().out
        assert "No report" in out


# ── deliver() ────────────────────────────────────────────────────────────────

class TestReportServiceDeliver:
    def test_deliver_calls_webhook(self):
        svc = ReportService(webhook_url="https://example.com/hook")
        svc.build(root="/p", findings=[_make_finding()])
        # Patch at the point where deliver() imports it
        with patch("ghostcred.reporting.send_webhook_report", return_value=True) as mock_send:
            result = svc.deliver()
        assert result is True
        assert mock_send.called
        # The full dict (with raw_secret) is passed to send_webhook_report;
        # redaction is handled inside that function, not before the call.
        payload = mock_send.call_args[0][0]
        assert "findings" in payload

    def test_deliver_returns_false_when_no_webhook(self):
        svc = ReportService()
        svc.build(root="/p", findings=[_make_finding()])
        assert svc.deliver() is False

    def test_deliver_returns_false_when_no_report(self):
        svc = ReportService(webhook_url="https://example.com/hook")
        assert svc.deliver() is False

    def test_deliver_handles_webhook_failure(self):
        svc = ReportService(webhook_url="https://example.com/hook")
        svc.build(root="/p", findings=[_make_finding()])
        with patch("ghostcred.integrations.send_webhook_report", return_value=False):
            result = svc.deliver()
        assert result is False


# ── diff() ────────────────────────────────────────────────────────────────────

class TestReportServiceDiff:
    def _write_report(self, path: Path, findings: list[dict]) -> None:
        path.write_text(json.dumps({"findings": findings}))

    def test_diff_detects_new_finding(self, tmp_path: Path):
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        self._write_report(old, [])
        self._write_report(new, [{"fingerprint": "abc", "provider": "github_pat",
                                   "lineage": {"blast_radius_score": 10}}])
        result = ReportService.diff(old, new)
        assert len(result["new_findings"]) == 1
        assert result["new_findings"][0]["fingerprint"] == "abc"

    def test_diff_detects_resolved_finding(self, tmp_path: Path):
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        self._write_report(old, [{"fingerprint": "abc", "provider": "github_pat",
                                   "lineage": {"blast_radius_score": 10}}])
        self._write_report(new, [])
        result = ReportService.diff(old, new)
        assert len(result["resolved_findings"]) == 1

    def test_diff_detects_escalated_blast_radius(self, tmp_path: Path):
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        self._write_report(old, [{"fingerprint": "abc", "provider": "github_pat",
                                   "lineage": {"blast_radius_score": 25}}])
        self._write_report(new, [{"fingerprint": "abc", "provider": "github_pat",
                                   "lineage": {"blast_radius_score": 75}}])
        result = ReportService.diff(old, new)
        assert len(result["escalated_blast_radius"]) == 1

    def test_diff_no_change_returns_empty_lists(self, tmp_path: Path):
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        finding = {"fingerprint": "abc", "provider": "github_pat",
                   "lineage": {"blast_radius_score": 25}}
        self._write_report(old, [finding])
        self._write_report(new, [finding])
        result = ReportService.diff(old, new)
        assert result["new_findings"] == []
        assert result["resolved_findings"] == []
        assert result["escalated_blast_radius"] == []

    def test_diff_handles_missing_old_report(self, tmp_path: Path):
        """Missing old report should treat all new findings as new."""
        old = tmp_path / "nonexistent.json"
        new = tmp_path / "new.json"
        self._write_report(new, [{"fingerprint": "xyz", "provider": "openai_api_key",
                                   "lineage": {"blast_radius_score": 10}}])
        result = ReportService.diff(old, new)
        assert len(result["new_findings"]) == 1

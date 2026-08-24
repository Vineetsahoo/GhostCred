"""
GhostCred Reporting Service
============================
Post-scan data integration layer. Handles:
  - Structured JSON report generation (findings + lineage + revocations)
  - Summary table output to stdout
  - Automatic SIEM/webhook delivery with raw_secret redacted
  - SARIF format output for GitHub Advanced Security / code scanning UI
  - Report diff: compare two reports and surface new or resolved findings

This is the "generation point" layer — every scan produces a complete,
machine-readable artefact regardless of how GhostCred was invoked.

Usage (programmatic):
    from ghostcred.reporting import ReportService
    svc = ReportService(report_path="ghostcred-report.json", webhook_url="https://...")
    svc.write(findings, revocations, duration_seconds=4.2)
    svc.deliver()          # posts to webhook if configured
    svc.print_summary()    # human-readable table to stdout

Usage (from CLI):
    Called automatically by cli.py — no manual wiring needed.
"""
from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghostcred.integrations import send_webhook_report
from ghostcred.scanners.base import Finding
from ghostcred.revocation.base import RevocationResult


# ── Report dataclass ──────────────────────────────────────────────────────────

@dataclass
class ScanReport:
    root: str
    findings: list[dict]
    revocations: list[dict]
    duration_seconds: float
    generated_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "generated_at": self.generated_at,
            "duration_seconds": self.duration_seconds,
            "findings": self.findings,
            "revocations": self.revocations,
            "metadata": self.metadata,
        }


# ── Report Service ─────────────────────────────────────────────────────────────

class ReportService:
    """
    Central data integration point between the scanner, lineage tracker,
    revocation layer, and downstream consumers (SIEM, GitHub, Grafana).
    """

    def __init__(
        self,
        report_path: str | Path | None = None,
        webhook_url: str | None = None,
        sarif_path: str | Path | None = None,
    ):
        self.report_path = Path(report_path) if report_path else None
        self.webhook_url = webhook_url or os.environ.get("GHOSTCRED_WEBHOOK_URL")
        self.sarif_path = Path(sarif_path) if sarif_path else None
        self._report: ScanReport | None = None

    # ── Build ─────────────────────────────────────────────────────────────────

    def build(
        self,
        root: str,
        findings: list[Finding],
        revocations: list[RevocationResult] | list[dict] | None = None,
        duration_seconds: float = 0.0,
        lineage_map: dict[str, Any] | None = None,
        metadata: dict | None = None,
    ) -> ScanReport:
        """
        Assemble a complete ScanReport from raw scan outputs.
        lineage_map: fingerprint → LineageResult.to_public_dict()
        revocations: accepts RevocationResult objects or plain dicts (both are serialised to dict).
        """
        revocations = revocations or []
        lineage_map = lineage_map or {}

        finding_records = []
        for f in findings:
            record = f.to_public_dict()
            if f.fingerprint in lineage_map:
                record["lineage"] = lineage_map[f.fingerprint]
            finding_records.append(record)

        # Normalise revocations — accept both RevocationResult objects and dicts
        revocation_dicts = []
        for r in revocations:
            revocation_dicts.append(r.__dict__ if hasattr(r, "__dict__") else dict(r))

        self._report = ScanReport(
            root=root,
            findings=finding_records,
            revocations=revocation_dicts,
            duration_seconds=duration_seconds,
            metadata=metadata or {},
        )
        return self._report

    # ── Write ─────────────────────────────────────────────────────────────────

    def write(self) -> Path | None:
        """Write the JSON report to disk. Returns the path written, or None."""
        if not self._report or not self.report_path:
            return None
        self.report_path.write_text(
            json.dumps(self._report.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        return self.report_path

    def write_sarif(self) -> Path | None:
        """
        Write a SARIF 2.1.0 report for GitHub Advanced Security / code scanning.
        Each finding becomes a SARIF result with location and severity.
        """
        if not self._report or not self.sarif_path:
            return None

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GhostCred",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/Vineetsahoo/GhostCred",
                            "rules": [
                                {
                                    "id": f"GHOSTCRED-{f['provider'].upper().replace('_', '-')}",
                                    "name": f['provider'],
                                    "shortDescription": {
                                        "text": f"Exposed {f['provider']} credential"
                                    },
                                    "defaultConfiguration": {
                                        "level": "error" if f["confidence"] >= 0.9 else "warning"
                                    },
                                }
                                for f in {x["provider"]: x for x in self._report.findings}.values()
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f"GHOSTCRED-{f['provider'].upper().replace('_', '-')}",
                            "level": "error" if f["confidence"] >= 0.9 else "warning",
                            "message": {
                                "text": (
                                    f"{f['provider']} credential found in {f['source_kind']} "
                                    f"(confidence: {f['confidence']:.0%}). "
                                    f"Redacted value: {f['redacted']}"
                                )
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": _relative_uri(f["source_path"], self._report.root)
                                        },
                                        "region": {"startLine": f["line"] or 1},
                                    }
                                }
                            ],
                        }
                        for f in self._report.findings
                    ],
                }
            ],
        }

        self.sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return self.sarif_path

    # ── Deliver ───────────────────────────────────────────────────────────────

    def deliver(self) -> bool:
        """
        POST the report to the configured webhook URL with raw_secret redacted.
        Returns True on success, False on failure. Never raises.
        """
        if not self._report or not self.webhook_url:
            return False
        return send_webhook_report(self._report.to_dict(), self.webhook_url)

    # ── Summary ───────────────────────────────────────────────────────────────

    def print_summary(self) -> None:
        """Print a human-readable findings table to stdout."""
        if not self._report:
            print("No report generated.")
            return

        findings = self._report.findings
        print(f"\n{'─'*70}")
        print(f"  GhostCred Scan Summary  |  {len(findings)} finding(s)  |  "
              f"{self._report.duration_seconds:.1f}s")
        print(f"{'─'*70}")

        if not findings:
            print("  ✅  No secrets found above confidence threshold.")
        else:
            print(f"  {'PROVIDER':<25} {'KIND':<12} {'CONF':>5}  {'BLAST':>5}  LOCATION")
            print(f"  {'─'*25} {'─'*12} {'─'*5}  {'─'*5}  {'─'*20}")
            for f in findings:
                lin = f.get("lineage", {})
                blast = str(lin.get("blast_radius_score", "—"))
                loc = _short_path(f["source_path"])
                line = f.get("line") or ""
                print(
                    f"  {f['provider']:<25} {f['source_kind']:<12} "
                    f"{f['confidence']:>4.0%}  {blast:>5}  {loc}:{line}"
                )
        print(f"{'─'*70}\n")

    # ── Diff ─────────────────────────────────────────────────────────────────

    @staticmethod
    def diff(old_path: Path, new_path: Path) -> dict:
        """
        Compare two JSON reports and return new findings, resolved findings,
        and findings whose blast radius increased since the last run.
        Useful for CI to only alert on changes, not re-alert on known issues.
        """
        def _load(p: Path) -> dict:
            try:
                return json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                return {"findings": []}

        old = {f["fingerprint"]: f for f in _load(old_path).get("findings", [])}
        new = {f["fingerprint"]: f for f in _load(new_path).get("findings", [])}

        new_findings = [f for fp, f in new.items() if fp not in old]
        resolved = [f for fp, f in old.items() if fp not in new]
        escalated = [
            f for fp, f in new.items()
            if fp in old
            and f.get("lineage", {}).get("blast_radius_score", 0)
            > old[fp].get("lineage", {}).get("blast_radius_score", 0)
        ]

        return {
            "new_findings": new_findings,
            "resolved_findings": resolved,
            "escalated_blast_radius": escalated,
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def _relative_uri(path: str, root: str) -> str:
    try:
        return str(Path(path).relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def _short_path(path: str) -> str:
    parts = Path(path).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else path

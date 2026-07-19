from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import click

from ghostcred.config import GhostCredConfig
from ghostcred.lineage import build_lineage
from ghostcred.metrics import (
    record_blast_radius,
    record_finding,
    record_revocation,
    record_scan_duration,
    record_ttr,
    serve_metrics,
)
from ghostcred.revocation import REVOKER_REGISTRY
from ghostcred.rotation import ROTATORS
from ghostcred.scanners import Finding, scan_ai_toolchain, scan_codebase

def _print_impact_analysis(lineage) -> None:
    if not lineage.propagations:
        return
    click.echo("\n      ⚠️  Blast Radius Impact Warning:")
    for prop in lineage.propagations:
        click.echo(f"         - Will break {prop.kind}: {prop.path} (Weight: {prop.weight})")
    click.echo("      Proceeding with revocation may cause active systems to fail.\n")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.fingerprint, f.source_path)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def _run_scan(
    root: Path,
    cfg: GhostCredConfig,
    ai_toolchain: bool,
    global_configs: bool,
    lineage: bool,
    revoke_live: bool,
    dry_run: bool,
    threshold: float,
    json_out: str | None,
    fail_on_finding: bool,
    metrics: bool,
    rotate_manager: str | None = None,
    grace_period: int = 0,
    notify_only: bool = False,
    webhook_url: str | None = None,
    compliance_report: bool = False,
) -> int:
    """Core scan logic. Returns the number of findings above threshold."""
    effective_dry_run = not revoke_live or dry_run

    start = time.time()
    click.echo(f"🔍 Scanning {root} ...")

    findings = scan_codebase(root, salt=cfg.salt, ignore_paths=cfg.ignore_paths)
    if ai_toolchain:
        findings.extend(
            scan_ai_toolchain(
                root,
                salt=cfg.salt,
                include_global_configs=global_configs,
                ignore_paths=cfg.ignore_paths,
            )
        )

    findings = [f for f in findings if f.confidence >= threshold]
    findings = _dedupe(findings)

    click.echo(f"Found {len(findings)} candidate secret(s) above confidence {threshold}.\n")

    report: dict = {"root": str(root), "findings": [], "revocations": []}
    revoked_fingerprints: set[str] = set()

    for f in findings:
        if metrics:
            record_finding(f.provider, f.source_kind)
        tag = "🧩 AI-TOOLCHAIN" if f.source_kind in ("mcp_config", "ide_config", "shell_history") else "📄 code"
        click.echo(f"  [{tag}] {f.provider} ({f.confidence:.2f}) — {f.source_path}:{f.line} — {f.redacted}")

        finding_record = f.to_public_dict()
        
        if compliance_report:
            from ghostcred.compliance import map_finding_to_compliance
            violations = map_finding_to_compliance(f.source_kind)
            finding_record["compliance_violations"] = violations
            if violations:
                click.echo(f"      🛡️  Compliance violations: {', '.join(violations)}")

        lin = None
        if lineage:
            lin = build_lineage(
                f, root,
                ci_log_dir=Path(cfg.ci_log_dir) if cfg.ci_log_dir else None,
                docker_image_tags=cfg.docker_image_tags,
            )
            finding_record["lineage"] = lin.to_public_dict()
            if lin.propagations:
                click.echo(
                    f"      ↳ blast radius: {lin.blast_radius_score}/100 across "
                    f"{len(lin.propagations)} location(s)"
                )
            if metrics:
                record_blast_radius(f.fingerprint, lin.blast_radius_score)

        report["findings"].append(finding_record)

        if revoke_live and f.provider in REVOKER_REGISTRY and f.fingerprint not in revoked_fingerprints:
            revoked_fingerprints.add(f.fingerprint)
            revoker = REVOKER_REGISTRY[f.provider]
            if revoker.check_live(f.raw_secret):
                if lin:
                    _print_impact_analysis(lin)
                
                if notify_only:
                    click.echo("      🚨 notify-only: Secret is live, sending alert instead of revoking.")
                else:
                    if grace_period > 0:
                        click.echo(f"      ⏳ Grace period: {grace_period}s to Ctrl+C and cancel revocation...")
                        for remaining in range(grace_period, 0, -1):
                            click.echo(f"         Revoking in {remaining}s...", nl=False)
                            time.sleep(1)
                            click.echo("\r", nl=False)
                            
                    proceed = True
                    if rotate_manager and rotate_manager in ROTATORS:
                        click.echo(f"      🔄 Initiating pre-revocation rotation via {rotate_manager}...")
                        rotator = ROTATORS[rotate_manager]
                        proceed = rotator.rotate(f.provider, f.fingerprint, dry_run=effective_dry_run)
                        if not proceed:
                            click.echo("      ❌ Rotation failed. Aborting revocation to prevent pipeline breakage.")

                    if proceed:
                        result = revoker.revoke(f.raw_secret, f.fingerprint, dry_run=effective_dry_run)
                        click.echo(
                            f"      🔒 revocation: {result.detail} "
                            f"(success={result.success}, dry_run={result.dry_run})"
                        )
                        if metrics:
                            record_revocation(f.provider, result.success)
                            if result.success and not effective_dry_run:
                                try:
                                    mtime = os.stat(f.source_path).st_mtime
                                    ttr = max(0.0, time.time() - mtime)
                                    record_ttr(ttr)
                                except OSError:
                                    pass
                                    
                        report["revocations"].append(result.__dict__)
            else:
                click.echo("      ✓ secret already inactive/rotated — no action needed")

    duration = round(time.time() - start, 2)
    report["duration_seconds"] = duration
    if metrics:
        record_scan_duration(duration)

    if webhook_url:
        from ghostcred.integrations import send_webhook_report
        success = send_webhook_report(report, webhook_url)
        if success:
            click.echo(f"\n📡 Report successfully sent to webhook: {webhook_url}")
        else:
            click.echo(f"\n❌ Failed to send report to webhook: {webhook_url}")

    if json_out:
        Path(json_out).write_text(json.dumps(report, indent=2, default=str))
        click.echo(f"\n📝 Full report written to {json_out}")

    if metrics:
        serve_metrics(cfg.metrics_port)
        click.echo(f"📊 Metrics available at :{cfg.metrics_port}/metrics")

    if fail_on_finding and findings:
        click.echo(f"\n❌ {len(findings)} secret(s) found — blocking.", err=True)
        sys.exit(1)

    click.echo("\n✅ Scan complete.")
    return len(findings)


@click.group()
def main() -> None:
    """GhostCred — AI toolchain-aware secret scanner, lineage tracker, and auto-revoker."""


@main.command()
@click.option("--path", "path_", default=".", help="Root directory to scan.")
@click.option("--ai-toolchain/--no-ai-toolchain", default=True, help="Scan MCP/IDE/shell-history blind spots.")
@click.option("--global-configs/--no-global-configs", default=True, help="Include desktop AI app configs outside the repo.")
@click.option("--lineage/--no-lineage", default=True, help="Build blast-radius lineage for each finding.")
@click.option("--revoke-live", is_flag=True, default=False, help="Attempt real revocation for confirmed-live secrets.")
@click.option("--dry-run/--no-dry-run", default=True, help="Log revocation intent without calling provider APIs.")
@click.option("--min-confidence", default=None, type=float, help="Override minimum confidence threshold.")
@click.option("--json-out", type=click.Path(), default=None, help="Write full JSON report to this path.")
@click.option("--fail-on-finding", is_flag=True, default=False, help="Exit non-zero if any finding above threshold is present (CI PR blocking).")
@click.option("--metrics/--no-metrics", default=False, help="Expose Prometheus metrics on scan completion.")
@click.option("--rotate-manager", type=click.Choice(list(ROTATORS.keys())), help="Rotation manager to use before revoking.")
@click.option("--grace-period", default=0, type=int, help="Seconds to wait before revoking a live secret.")
@click.option("--notify-only", is_flag=True, default=False, help="Send alerts instead of actually revoking live secrets.")
@click.option("--webhook-url", default=None, help="URL to send the JSON report via HTTP POST.")
@click.option("--compliance-report", is_flag=True, default=False, help="Include compliance mapping (SOC 2, ISO 27001, etc.) in the report.")
def scan(
    path_: str,
    ai_toolchain: bool,
    global_configs: bool,
    lineage: bool,
    revoke_live: bool,
    dry_run: bool,
    min_confidence: float | None,
    json_out: str | None,
    fail_on_finding: bool,
    metrics: bool,
    rotate_manager: str | None,
    grace_period: int,
    notify_only: bool,
    webhook_url: str | None,
    compliance_report: bool,
) -> None:
    """Run a full scan: code + AI toolchain blind spots, with optional lineage and revocation."""
    root = Path(path_).resolve()
    cfg = GhostCredConfig.load(root)
    threshold = min_confidence if min_confidence is not None else cfg.min_confidence

    _run_scan(
        root=root,
        cfg=cfg,
        ai_toolchain=ai_toolchain,
        global_configs=global_configs,
        lineage=lineage,
        revoke_live=revoke_live,
        dry_run=dry_run,
        threshold=threshold,
        json_out=json_out,
        fail_on_finding=fail_on_finding,
        metrics=metrics,
        rotate_manager=rotate_manager,
        grace_period=grace_period,
        notify_only=notify_only,
        webhook_url=webhook_url or cfg.webhook_url,
        compliance_report=compliance_report,
    )


@main.command()
@click.option("--path", "path_", default=".", help="Root directory to watch.")
@click.option("--interval", default=60, help="Seconds between scans.")
@click.option("--ai-toolchain/--no-ai-toolchain", default=True)
@click.option("--lineage/--no-lineage", default=True)
@click.option("--revoke-live", is_flag=True, default=False)
@click.option("--dry-run/--no-dry-run", default=True)
def watch(
    path_: str,
    interval: int,
    ai_toolchain: bool,
    lineage: bool,
    revoke_live: bool,
    dry_run: bool,
) -> None:
    """Continuously rescan on an interval (local agent mode). Exposes Prometheus metrics."""
    root = Path(path_).resolve()
    cfg = GhostCredConfig.load(root)

    # Start metrics server once; the loop keeps updating counters.
    serve_metrics(cfg.metrics_port)
    click.echo(f"📊 Metrics available at :{cfg.metrics_port}/metrics")

    while True:
        _run_scan(
            root=root,
            cfg=cfg,
            ai_toolchain=ai_toolchain,
            global_configs=cfg.include_global_configs,
            lineage=lineage,
            revoke_live=revoke_live,
            dry_run=dry_run,
            threshold=cfg.min_confidence,
            json_out=None,
            fail_on_finding=False,
            metrics=True,
        )
        click.echo(f"⏱  sleeping {interval}s ...\n")
        time.sleep(interval)


@main.command()
@click.argument("secret", envvar="GHOSTCRED_SECRET")
@click.option("--provider", required=True, type=click.Choice(list(REVOKER_REGISTRY.keys())), help="Secret provider.")
@click.option("--fingerprint", "fp", default="manual", help="Fingerprint label for the report.")
@click.option("--rotate-manager", type=click.Choice(list(ROTATORS.keys())), help="Rotation manager to use before revoking.")
@click.option("--dry-run/--no-dry-run", default=True, help="Log intent only; don't call the revocation API.")
@click.option("--webhook-url", default=None, help="URL to send the revocation event via HTTP POST.")
def revoke(secret: str, provider: str, fp: str, rotate_manager: str | None, dry_run: bool, webhook_url: str | None) -> None:
    """Manually revoke a single known secret at its provider.

    Pass the secret via the GHOSTCRED_SECRET env var or as a positional argument.

    \b
    Example:
      GHOSTCRED_SECRET=ghp_xxx ghostcred revoke --provider github_pat --no-dry-run
    """
    revoker = REVOKER_REGISTRY[provider]
    click.echo(f"🔍 Checking liveness of {provider} secret ...")
    live = revoker.check_live(secret)
    if not live:
        click.echo("✓ Secret appears inactive/rotated — nothing to revoke.")
        return
    click.echo(f"⚠️  Secret is LIVE. Revoking (dry_run={dry_run}) ...")
    
    if rotate_manager and rotate_manager in ROTATORS:
        click.echo(f"      🔄 Initiating pre-revocation rotation via {rotate_manager}...")
        rotator = ROTATORS[rotate_manager]
        if not rotator.rotate(provider, fp, dry_run=dry_run):
            click.echo("      ❌ Rotation failed. Aborting revocation to prevent pipeline breakage.")
            return

    result = revoker.revoke(secret, fp, dry_run=dry_run)
    status = "✅" if result.success else "❌"
    click.echo(f"{status} {result.detail}")
    
    cfg = GhostCredConfig.load(Path.cwd())
    final_webhook = webhook_url or cfg.webhook_url
    if final_webhook:
        from ghostcred.integrations import send_webhook_report
        report = {
            "revocations": [result.__dict__],
            "findings": [{"provider": provider, "fingerprint": fp, "raw_secret": secret}]
        }
        success = send_webhook_report(report, final_webhook)
        if success:
            click.echo(f"📡 Report successfully sent to webhook: {final_webhook}")
        else:
            click.echo(f"❌ Failed to send report to webhook: {final_webhook}")


@main.command("list-providers")
def list_providers() -> None:
    """List all providers with auto-revocation support."""
    click.echo("Providers with GhostCred auto-revocation support:\n")
    for name, revoker in REVOKER_REGISTRY.items():
        click.echo(f"  • {name}")


@main.command("plant-decoys")
@click.option("--path", "path_", default=".", help="Root directory to plant decoys.")
def plant_decoys(path_: str) -> None:
    """Actively plant honeytokens (fake secrets) in AI toolchain locations."""
    from ghostcred.decoys import DecoyGenerator
    
    root = Path(path_).resolve()
    click.echo(f"🍯 Planting decoys in {root} ...")
    
    results = DecoyGenerator.plant_decoys(root)
    
    if not results:
        click.echo("  No suitable locations found for planting.")
        return
        
    for p, count in results.items():
        click.echo(f"  ✓ Planted {count} decoys in {p}")
    
    total = sum(results.values())
    click.echo(f"\n✅ Successfully planted {total} honeytokens.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
GhostCred Full Demo Runner
==========================

Walks through every capability of GhostCred in sequence,
printing clear section headers so you can follow along
or present it to an audience.

Usage (from the repo root):
    python scripts/run_demo.py

What it demonstrates:
  Step 1 — Code scanner:      detects hardcoded secrets in .env and app.py
  Step 2 — AI toolchain scan: finds the same secrets in .cursor/mcp.json
  Step 3 — Lineage tracking:  traces secrets into docker-build.log and ci-logs/
  Step 4 — Blast radius score: quantifies how far the leak has spread
  Step 5 — Liveness check:    asks the mock provider if the token is still active
  Step 6 — Dry-run revocation: shows what revocation would do without calling real APIs
  Step 7 — Live revocation:   actually kills the token in the mock provider
  Step 8 — Post-revoke check: confirms the token is now dead
  Step 9 — JSON report:       shows the full machine-readable output
  Step 10 — CI gate demo:     shows the exit-code behaviour that blocks a CI pipeline

Prerequisites:
    pip install -e .
    pip install flask          # for the mock provider
    # In a separate terminal: python scripts/mock_provider.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

# ── colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def header(n: int, title: str) -> None:
    print(f"\n{BOLD}{BLUE}{'─'*60}{RESET}")
    print(f"{BOLD}{BLUE}  Step {n}: {title}{RESET}")
    print(f"{BOLD}{BLUE}{'─'*60}{RESET}\n")

def ok(msg: str)   -> None: print(f"{GREEN}  ✅  {msg}{RESET}")
def warn(msg: str) -> None: print(f"{YELLOW}  ⚠️   {msg}{RESET}")
def err(msg: str)  -> None: print(f"{RED}  ❌  {msg}{RESET}")
def info(msg: str) -> None: print(f"  ℹ️   {msg}")

# ── paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).parent.parent.resolve()
DEMO_REPO  = REPO_ROOT / "demo-repo"
REPORT_OUT = REPO_ROOT / "ghostcred-demo-report.json"
SALT       = "demo-fixed-salt-for-reproducible-fingerprints"

# ── import ghostcred directly (no subprocess needed for Python-level demo) ────
sys.path.insert(0, str(REPO_ROOT))
from ghostcred.scanners       import scan_codebase, scan_ai_toolchain
from ghostcred.lineage        import build_lineage
from ghostcred.config         import GhostCredConfig
from ghostcred.revocation.github_revoker import GitHubRevoker

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 1 — Code Scanner
# ─────────────────────────────────────────────────────────────────────────────
header(1, "Code Scanner — .env, source files, build configs")

info(f"Scanning: {DEMO_REPO}")
info("Files in scope: app.py, .env, docker-build.log\n")

code_findings = scan_codebase(DEMO_REPO, salt=SALT)

if not code_findings:
    warn("No findings — check that demo-repo/ files are present.")
else:
    ok(f"Found {len(code_findings)} secret(s) in source/env files:\n")
    for f in code_findings:
        print(
            f"    [{f.source_kind.upper()}] {f.provider}\n"
            f"      File     : {Path(f.source_path).relative_to(REPO_ROOT)}\n"
            f"      Line     : {f.line}\n"
            f"      Redacted : {f.redacted}\n"
            f"      Confidence: {f.confidence:.0%}\n"
            f"      Revocable: {'yes' if f.revocable else 'no'}\n"
        )

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 2 — AI Toolchain Scanner
# ─────────────────────────────────────────────────────────────────────────────
header(2, "AI Toolchain Scanner — MCP configs & IDE settings")

info("Scanning: .cursor/mcp.json (project-local Cursor MCP config)")
info("This is the surface that Gitleaks / TruffleHog / detect-secrets miss.\n")

ai_findings = scan_ai_toolchain(DEMO_REPO, salt=SALT, include_global_configs=False)

if not ai_findings:
    warn("No AI toolchain findings — check demo-repo/.cursor/mcp.json exists.")
else:
    ok(f"Found {len(ai_findings)} secret(s) in AI toolchain configs:\n")
    for f in ai_findings:
        print(
            f"    [{f.source_kind.upper()}] {f.provider}\n"
            f"      File     : {Path(f.source_path).relative_to(REPO_ROOT)}\n"
            f"      Line     : {f.line}\n"
            f"      Redacted : {f.redacted}\n"
            f"      Confidence: {f.confidence:.0%}\n"
        )

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 3 — Lineage Tracking (Blast Radius)
# ─────────────────────────────────────────────────────────────────────────────
header(3, "Lineage Tracking — where else has this secret spread?")

# Pick the GitHub PAT for the lineage demo — it's the most interesting
# because it also appears in docker-build.log AND the ci-log.
github_finding = next(
    (f for f in code_findings if f.provider == "github_pat"), None
)

if not github_finding:
    warn("No github_pat finding to trace. Skipping lineage demo.")
else:
    info(f"Tracing fingerprint for: {github_finding.redacted}")
    info(f"Looking in: docker-build.log, ci-logs/\n")

    lineage = build_lineage(
        github_finding,
        root=DEMO_REPO,
        ci_log_dir=DEMO_REPO / "ci-logs",
    )

    ok(f"Blast Radius Score: {lineage.blast_radius_score}/100\n")

    if lineage.propagations:
        print(f"    Secret also found in {len(lineage.propagations)} additional location(s):\n")
        for p in lineage.propagations:
            try:
                display_path = str(Path(p.path).relative_to(REPO_ROOT))
            except ValueError:
                display_path = p.path
            print(f"    ⚠️  [{p.kind}]  {display_path}  (weight: +{p.weight})")
    else:
        info("No propagation found in local logs (docker-build.log/ci-logs must contain the secret).")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 4 — Blast Radius Breakdown
# ─────────────────────────────────────────────────────────────────────────────
header(4, "Blast Radius Score — understanding the number")

if github_finding:
    info("Score breakdown:")
    print(f"    Base (origin file always counts)  :  10 pts")
    if lineage.propagations:
        for p in lineage.propagations:
            print(f"    + {p.kind:<35}: +{p.weight} pts")
    print(f"\n    {BOLD}Total: {lineage.blast_radius_score}/100{RESET}")
    print()
    if lineage.blast_radius_score >= 70:
        err("HIGH BLAST RADIUS — secret is in CI logs visible to the whole org.")
    elif lineage.blast_radius_score >= 40:
        warn("MEDIUM BLAST RADIUS — secret leaked beyond the source file.")
    else:
        ok("LOW BLAST RADIUS — secret contained to a single location.")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 5 — Liveness Check (requires mock provider running)
# ─────────────────────────────────────────────────────────────────────────────
header(5, "Liveness Check — is the token still active?")

revoker = GitHubRevoker()
DEMO_TOKEN = "ghp_fakeDemoToken1234567890abcdefghijABCD"

info("Calling mock provider at http://localhost:5001/user ...")
info("(Start mock provider with: python scripts/mock_provider.py)\n")

is_live = revoker.check_live(DEMO_TOKEN)

if is_live:
    err(f"Token IS LIVE — {DEMO_TOKEN[:20]}... is still valid at the provider.")
    print(f"\n    {RED}This means an attacker who found it in your git history{RESET}")
    print(f"    {RED}could use it RIGHT NOW.{RESET}\n")
else:
    warn("Token appears inactive (mock provider not running or already revoked).")
    warn("Start the mock provider with: python scripts/mock_provider.py")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 6 — Dry-Run Revocation
# ─────────────────────────────────────────────────────────────────────────────
header(6, "Dry-Run Revocation — what WOULD happen (safe, no real API call)")

info("dry_run=True — this logs intent without touching any real API.\n")

fp = github_finding.fingerprint if github_finding else "demo-fp-123"
dry_result = revoker.revoke(DEMO_TOKEN, fingerprint=fp, dry_run=True)

ok(f"Dry run result: success={dry_result.success}")
print(f"    Detail  : {dry_result.detail}")
print(f"    Provider: {dry_result.provider}")
print(f"    Dry run : {dry_result.dry_run}\n")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 7 — Live Revocation (mock provider must be running)
# ─────────────────────────────────────────────────────────────────────────────
header(7, "Live Revocation — actually kills the token (on mock provider)")

if not is_live:
    warn("Skipping live revocation — token not live (mock provider may not be running).")
else:
    info("Calling DELETE /installation/token on mock provider...\n")
    live_result = revoker.revoke(DEMO_TOKEN, fingerprint=fp, dry_run=False)

    if live_result.success:
        ok(f"Token REVOKED: {live_result.detail}")
    else:
        err(f"Revocation failed: {live_result.detail}")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 8 — Post-Revoke Liveness Check
# ─────────────────────────────────────────────────────────────────────────────
header(8, "Post-Revoke Check — confirm the token is now dead")

if not is_live:
    warn("Skipping — token was not live before revocation attempt.")
else:
    time.sleep(0.5)
    still_live = revoker.check_live(DEMO_TOKEN)
    if not still_live:
        ok("Token is DEAD — /user now returns 401. Revocation confirmed.")
    else:
        err("Token still live — revocation may have failed.")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 9 — Full JSON Report
# ─────────────────────────────────────────────────────────────────────────────
header(9, "JSON Report — machine-readable output for SIEM / dashboards")

all_findings = code_findings + [
    f for f in ai_findings
    if f.fingerprint not in {x.fingerprint for x in code_findings}
]

report = {
    "scan_target": str(DEMO_REPO),
    "salt_hint": "demo-fixed-salt (use a real secret in production)",
    "findings": [],
}

for f in all_findings:
    entry = f.to_public_dict()
    if f.provider == "github_pat" and github_finding and f.fingerprint == github_finding.fingerprint:
        entry["lineage"] = lineage.to_public_dict()
    report["findings"].append(entry)

REPORT_OUT.write_text(json.dumps(report, indent=2, default=str))
ok(f"Report written to: {REPORT_OUT.relative_to(REPO_ROOT)}")
info(f"Total findings: {len(all_findings)}")
print()

# Print a trimmed preview
preview = json.dumps(report["findings"][0] if report["findings"] else {}, indent=2)
print("    First finding preview:")
for line in preview.splitlines()[:20]:
    print(f"    {line}")
if len(preview.splitlines()) > 20:
    print(f"    ... ({len(preview.splitlines()) - 20} more lines in file)")

# ─────────────────────────────────────────────────────────────────────────────
#  STEP 10 — CI Gate / Exit-Code Behaviour
# ─────────────────────────────────────────────────────────────────────────────
header(10, "CI Gate — how GhostCred blocks a pipeline on findings")

info("Simulating: ghostcred scan --path demo-repo --fail-on-finding")
info("In real CI this command runs as a step — non-zero exit blocks the PR.\n")

result = subprocess.run(
    [
        sys.executable, "-m", "ghostcred.cli" if True else "ghostcred",
        "scan",
        "--path", str(DEMO_REPO),
        "--ai-toolchain",
        "--no-lineage",           # skip lineage in CI gate demo for speed
        "--no-global-configs",
        "--fail-on-finding",
        "--dry-run",
        "--json-out", str(REPO_ROOT / "ghostcred-ci-gate-report.json"),
    ],
    capture_output=True,
    text=True,
)

print("    STDOUT:")
for line in result.stdout.splitlines()[:15]:
    print(f"      {line}")

print(f"\n    Exit code: {result.returncode}")
if result.returncode != 0:
    err("Pipeline BLOCKED — exit code 1 means CI would fail the PR.")
    ok("This is the correct behaviour: secrets stop the build.")
else:
    warn("Exit code 0 — no findings above threshold, or --fail-on-finding not working.")

# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{BOLD}{GREEN}{'─'*60}{RESET}")
print(f"{BOLD}{GREEN}  Demo complete.{RESET}")
print(f"{BOLD}{GREEN}{'─'*60}{RESET}\n")
print(f"  Full report : {REPORT_OUT.relative_to(REPO_ROOT)}")
print(f"  CI report   : ghostcred-ci-gate-report.json")
print()
print("  What was demonstrated:")
print("  1. Code scanner catches secrets in .env and source files")
print("  2. AI toolchain scanner catches secrets in MCP/IDE configs")
print("  3. Lineage tracker traces a secret across docker logs + CI logs")
print("  4. Blast radius score quantifies the spread (0–100)")
print("  5. Liveness check confirms the token is still active (mock provider)")
print("  6. Dry-run revocation shows intent safely")
print("  7. Live revocation kills the token at the provider")
print("  8. Post-revoke check confirms the token is dead")
print("  9. JSON report is ready for SIEM ingestion or Grafana")
print(" 10. CI gate exits non-zero to block the PR/commit\n")

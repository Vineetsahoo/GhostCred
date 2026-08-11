#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GhostCred Release-Gate Demo
#  Simulates the scan that would run at release time in CI (release.yml)
#  before the Docker image is signed and pushed to GHCR.
#
#  Usage (from repo root):
#    bash scripts/demo_release_scan.sh
#
#  What it demonstrates:
#    1. Pre-release code scan across the whole project
#    2. AI toolchain scan (catches secrets in MCP configs committed to the repo)
#    3. Full lineage pass with CI log tracing
#    4. Produces a JSON report suitable for SBOM attachment
#    5. Blocks release on any CRITICAL finding (exit 1)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO_TARGET="$REPO_ROOT/demo-repo"
REPORT_FILE="$REPO_ROOT/ghostcred-release-report.json"
SALT="${GHOSTCRED_SALT:-demo-fixed-salt-for-reproducible-fingerprints}"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  GhostCred — Release Gate Scan"
echo "  Target : $DEMO_TARGET"
echo "  Salt   : ${SALT:0:10}... (truncated)"
echo "══════════════════════════════════════════════════════════"
echo ""

# ── Step 1: Full scan with lineage ────────────────────────────────────────────
echo "▶ Step 1: Running full scan with lineage tracking..."
echo ""

ghostcred scan \
  --path "$DEMO_TARGET" \
  --ai-toolchain \
  --lineage \
  --no-global-configs \
  --dry-run \
  --json-out "$REPORT_FILE"

echo ""

# ── Step 2: Show the blast radius from the report ─────────────────────────────
echo "▶ Step 2: Blast radius summary from report..."
echo ""

python3 - <<'PYEOF'
import json, sys
from pathlib import Path

report_path = Path(__file__).parent.parent / "ghostcred-release-report.json"
if not report_path.exists():
    print("  [skip] Report not found.")
    sys.exit(0)

report = json.loads(report_path.read_text())
findings = report.get("findings", [])

print(f"  Total findings : {len(findings)}")
print()

for f in findings:
    lin = f.get("lineage", {})
    score = lin.get("blast_radius_score", "n/a")
    props = lin.get("propagations", [])
    print(f"  [{f['source_kind'].upper()}] {f['provider']}")
    print(f"    Location  : {f['source_path']}")
    print(f"    Redacted  : {f['redacted']}")
    print(f"    Confidence: {f['confidence']}")
    if lin:
        print(f"    Blast radius: {score}/100  ({len(props)} propagation(s))")
        for p in props:
            print(f"      ↳ {p['kind']} — {p['path']}")
    print()
PYEOF

# ── Step 3: Block release if any high-confidence finding exists ───────────────
echo "▶ Step 3: Release gate check (blocks if findings present)..."
echo ""

FINDING_COUNT=$(python3 -c "
import json
from pathlib import Path
r = json.loads(Path('$REPORT_FILE').read_text())
print(len([f for f in r.get('findings', []) if f['confidence'] >= 0.8]))
" 2>/dev/null || echo "0")

if [ "$FINDING_COUNT" -gt 0 ]; then
  echo "  ❌  RELEASE BLOCKED — $FINDING_COUNT high-confidence secret(s) detected."
  echo "      Fix the findings above before tagging a release."
  echo "      Full report: $REPORT_FILE"
  exit 1
else
  echo "  ✅  No high-confidence secrets found — release gate passed."
fi

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Release scan complete. Report: ghostcred-release-report.json"
echo "══════════════════════════════════════════════════════════"
echo ""

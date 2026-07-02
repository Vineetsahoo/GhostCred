#!/usr/bin/env bash
# GhostCred pre-commit hook
# Install: cp scripts/pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
set -euo pipefail

echo "🔍 GhostCred: scanning staged changes + AI toolchain configs before commit..."

if ! command -v ghostcred &> /dev/null; then
  echo "⚠️  ghostcred CLI not found. Install with: pip install -e ." >&2
  exit 1
fi

ghostcred scan \
  --path . \
  --ai-toolchain \
  --dry-run \
  --fail-on-finding \
  --json-out /tmp/ghostcred-precommit-report.json

STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "" >&2
  echo "❌ Commit blocked: GhostCred detected a secret (possibly in an MCP/IDE config" >&2
  echo "   or shell history reference). See /tmp/ghostcred-precommit-report.json." >&2
  exit 1
fi

echo "✅ GhostCred: clean. Proceeding with commit."

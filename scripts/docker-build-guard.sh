#!/usr/bin/env bash
# Scans the build context BEFORE handing it to `docker build`.
# Usage: scripts/docker-build-guard.sh <docker build args...>
set -euo pipefail

CONTEXT_DIR="${DOCKER_BUILD_CONTEXT:-.}"

echo "🔍 GhostCred: pre-build scan of context '$CONTEXT_DIR' ..."

docker build -f docker/Dockerfile.scanner -t ghostcred-scanner:latest . > /dev/null

docker run --rm -v "$(realpath "$CONTEXT_DIR")":/scan-target ghostcred-scanner:latest \
  scan --path /scan-target --ai-toolchain --lineage --fail-on-finding

echo "✅ GhostCred: build context clean. Proceeding with docker build..."
docker build "$@"

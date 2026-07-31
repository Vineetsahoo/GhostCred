# GhostCred

GhostCred is an AI dev toolchain secret leak detector, lineage tracker, and auto-revoker. It catches secrets in code and in the AI tooling surface that often gets missed by traditional scanners, then traces how far the leak spread and can revoke live credentials when configured to do so.

## What is current

- AI toolchain scanning for MCP configs, IDE settings, and shell history is built in.
- Lineage tracking records the blast radius across logs, artifacts, and git history.
- Revocation supports live checks, dry-run mode, webhook reporting, and optional rotation.
- The CLI includes `scan`, `revoke`, `watch`, `list-providers`, and `plant-decoys`.
- Security and release workflows already exist for scanning, SLSA verification, and signed artifact publication.

## Typical workflow

```bash
pip install -e .

# Scan code and AI toolchain locations
ghostcred scan --path . --ai-toolchain --lineage

# Block CI on any finding
ghostcred scan --path . --fail-on-finding --json-out report.json

# Check and revoke a known secret
GHOSTCRED_SECRET=ghp_xxx ghostcred revoke --provider github_pat --no-dry-run

# Keep watching with metrics enabled
ghostcred watch --path . --interval 120

# Plant decoys for detection testing
ghostcred plant-decoys --path .
```

## Recent updates

- JSON reports now include the raw secret value for downstream redaction or verification workflows.
- Recursive AI toolchain scanning now finds nested MCP configs and IDE settings more reliably.
- Findings are deduplicated by both fingerprint and source path to keep repeated occurrences visible.

## Documentation map

- Scanning and plugin details: [scanners/README.md](scanners/README.md)
- Revocation and supported providers: [revocation/README.md](revocation/README.md)
- Lineage and blast-radius tracking: [lineage/README.md](lineage/README.md)
- Metrics and observability: [metrics/README.md](metrics/README.md)
- Dev scripts and local guards: [scripts/README.md](scripts/README.md)
- Testing strategy and suite layout: [tests/README.md](tests/README.md)
- GitHub automation, workflow, and dependency-update policy: [.github/README.md](.github/README.md)
- Release and supply-chain checks: [.github/workflows/release.yml](.github/workflows/release.yml), [.github/workflows/security.yml](.github/workflows/security.yml), [.github/workflows/slsa-verify.yml](.github/workflows/slsa-verify.yml)
- Architecture overview: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Security and maintenance

- Security scanning runs in [.github/workflows/security.yml](.github/workflows/security.yml).
- Release signing, SBOM generation, and provenance attachment run in [.github/workflows/release.yml](.github/workflows/release.yml).
- Release verification runs in [.github/workflows/slsa-verify.yml](.github/workflows/slsa-verify.yml).
- Dependabot updates Python and Docker dependencies weekly through [.github/dependabot.yml](.github/dependabot.yml).
- Pull requests are expected to include tests and documentation updates when behavior changes.

## Operational notes

GhostCred is designed for sensitive environments. Use short-lived secrets, least-privilege CI credentials, and audit logs for every revocation or webhook event. If you need the concrete metrics names, supported providers, or exact scan targets, see the folder-level documentation instead of the root page.
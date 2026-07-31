# GitHub Automation

This directory contains the repository-level workflow, contribution, and dependency-update configuration for GhostCred.

## Contents

- `workflows/release.yml`: Builds, signs, and publishes release artifacts, including provenance and SBOM output.
- `workflows/security.yml`: Runs security scans such as SAST and container vulnerability checks.
- `workflows/slsa-verify.yml`: Verifies release provenance and signatures after publication.
- `workflows/ghostcred-scan.yml`: Runs the GhostCred scan in CI and comments on pull requests with findings.
- `dependabot.yml`: Updates Python and Docker dependencies on a weekly schedule.
- `PULL_REQUEST_TEMPLATE.md`: Documents the expected test and documentation checklist for pull requests.
- `ISSUE_TEMPLATE/`: Provides templates for bug reports and new provider requests.

## Security policy notes

- Keep workflow permissions minimal and scoped to the action that needs them.
- Treat release signing, SBOM generation, and provenance verification as required parts of the supply-chain path.
- Review dependency update pull requests as part of the normal security maintenance process.
- Use the pull request checklist to confirm tests and documentation changes before merging.

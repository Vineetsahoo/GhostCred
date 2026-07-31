# Scripts

This directory contains utility scripts for development, deployment, and testing GhostCred.

## Overview
- `mock_provider.py`: Local HTTP server used during testing to mock external provider APIs.
- `pre-commit-hook.sh`: Git `pre-commit` hook that scans staged files before they can be committed.
- `docker-build-guard.sh`: Wrapper around `docker build` that scans the build context before allowing the build to proceed.

## Common usage

Install the pre-commit hook:

```bash
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Guard a Docker build:

```bash
scripts/docker-build-guard.sh -t myapp:latest .
```

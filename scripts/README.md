# Scripts

This directory contains utility scripts for development, deployment, and testing GhostCred.

## Overview
- `mock_provider.py`: A local HTTP server used during testing to mock external provider APIs (e.g. GitHub, AWS) to simulate active credentials and revocation endpoints without hitting real infrastructure.
- `pre-commit-hook.sh`: A shell script designed to be installed as a git `pre-commit` hook that runs `ghostcred scan` on staged files before a developer can accidentally push a secret.
- `docker-build-guard.sh`: A script that wraps `docker build` commands, scanning the current context and Dockerfile for secrets before the build is allowed to proceed.

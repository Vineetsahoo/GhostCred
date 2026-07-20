# Lineage

This directory contains the **Blast Radius & Lineage Tracking** engine.

## Overview
When a secret is exposed in a codebase, it rarely stays in just one file. It propagates into Git histories, CI/CD pipeline logs (like GitHub Actions), compiled Docker images, and test artifacts. The Lineage module tracks where a secret has spread to give engineers a true understanding of the blast radius.

## Files
- `tracker.py`: Contains the `build_lineage` function and the `Propagation` tracker classes. It scans for the secret footprint in:
  - Docker Image Histories
  - GitHub Actions Logs
  - Git Commit Histories
  - Test Output Files (JUnit XML, Coverage XML)
  - Well-Known Files (e.g. `.netrc`)

## Impact Analysis
Before the revocation engine destroys an active credential, GhostCred leverages this lineage data to print a warning showing exactly which systems or pipelines will break if the secret is revoked.

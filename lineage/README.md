# Lineage

This directory contains the **Blast Radius & Lineage Tracking** engine.

## Overview
When a secret is exposed in a codebase, it rarely stays in just one file. It propagates into Git histories, CI/CD pipeline logs (like GitHub Actions), compiled Docker images, and test artifacts. The Lineage module tracks where a secret has spread to give engineers a true understanding of the blast radius.

## Files
- `tracker.py`: Contains the `build_lineage` function and the `Propagation` tracker classes.

## Data sources

The lineage tracker looks for the same secret fingerprint across:

- Docker image histories
- GitHub Actions logs
- Git commit history
- Test output files such as JUnit XML and coverage XML
- Well-known credential-bearing files such as `.netrc`

## Output

The tracker returns a compact graph with:

- `origin_file`: the first known source path
- `propagated_to`: downstream paths, kinds, and timestamps
- `blast_radius_score`: a 0-100 severity score based on how widely the secret spread

## Impact Analysis
Before the revocation engine destroys an active credential, GhostCred leverages this lineage data to print a warning showing exactly which systems or pipelines will break if the secret is revoked.

# Tests

This directory contains the pytest suite for GhostCred.

## Overview
GhostCred uses a security-focused test suite to prevent regressions in secret detection, revocation safety, lineage tracking, and report redaction.

## Key Files
- `test_scanners.py`: Verifies the core scanning logic, finding outputs, and redaction safety logic.
- `test_patterns.py`: Exhaustive test cases for every supported `SecretPattern` regex to minimize false positives and false negatives.
- `test_fuzz_patterns.py`: Uses `hypothesis` for property-based fuzz testing to ensure regex patterns don't suffer from ReDoS (Regular Expression Denial of Service).
- `test_lineage.py`: Tests the blast radius / lineage propagation logic.
- `test_integrations.py`: Tests external integrations like SIEM webhooks and checks redaction on the wire.
- `test_compliance.py`: Tests the compliance mapping rules (SOC 2, ISO 27001).
- `test_cli.py`: Exercises the CLI commands, exit codes, JSON report structure, and destructive-operation guardrails.
- `test_file_handling.py`: Covers file routing, platform-specific paths, and config edge cases.

## Security focus

- Regex accuracy and false-positive control
- ReDoS resistance for hostile inputs
- Safe dry-run versus live revocation behavior
- JSON and webhook redaction guarantees
- Lineage correctness so blast-radius reporting stays trustworthy

## Running Tests
Run the entire suite using:
```bash
pytest tests/ -v
```

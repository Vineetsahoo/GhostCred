# Tests

This directory contains the pytest suite for GhostCred.

## Overview
GhostCred has a robust testing framework designed to prevent regressions in regex matching, test integrations, and ensure the safety of the revocation engine.

## Key Files
- `test_scanners.py`: Verifies the core scanning logic, finding outputs, and redaction safety logic.
- `test_patterns.py`: Exhaustive test cases for every supported `SecretPattern` regex to minimize false positives and false negatives.
- `test_fuzz_patterns.py`: Uses `hypothesis` for property-based fuzz testing to ensure regex patterns don't suffer from ReDoS (Regular Expression Denial of Service).
- `test_lineage.py`: Tests the blast radius / lineage propagation logic.
- `test_integrations.py`: Tests external integrations like SIEM webhooks and checks redaction on the wire.
- `test_compliance.py`: Tests the compliance mapping rules (SOC 2, ISO 27001).

## Running Tests
Run the entire suite using:
```bash
pytest tests/ -v
```

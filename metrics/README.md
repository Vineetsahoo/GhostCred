# Metrics

This directory handles exposing internal state and operational metrics for GhostCred.

## Overview
Enterprise security teams need visibility into how GhostCred is performing, what secrets it's finding, and how quickly it's revoking them. The metrics module exposes this data via a Prometheus-compatible HTTP endpoint.

## Files
- `prometheus_exporter.py`: Starts a background HTTP server using `prometheus_client`.

## Exported metrics

- `ghostcred_findings_total{provider, source_kind}`
- `ghostcred_blast_radius_score{fingerprint_short}`
- `ghostcred_revocations_total{provider, status}`
- `ghostcred_scan_duration_seconds`

## Operational focus

- Total secrets found
- Revocations attempted, succeeded, and failed
- Time-to-remediation, meaning how long it took to revoke a secret after it appeared on disk
- Scan duration for performance tracking

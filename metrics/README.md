# Metrics

This directory handles exposing internal state and operational metrics for GhostCred.

## Overview
Enterprise security teams need visibility into how GhostCred is performing, what secrets it's finding, and how quickly it's revoking them. The metrics module exposes this data via a Prometheus-compatible HTTP endpoint.

## Files
- `prometheus_exporter.py`: Starts a background HTTP server (using `prometheus_client`) that exposes Gauges, Counters, and Histograms to Prometheus scrapers. Tracks data like:
  - Total secrets found
  - Revocations attempted / succeeded / failed
  - Time-To-Remediation (TTR) - How fast a secret was revoked after being written to disk

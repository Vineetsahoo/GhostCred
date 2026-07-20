# Grafana Dashboards

This directory contains pre-configured Grafana dashboards for monitoring GhostCred.

## Overview
GhostCred exposes operational metrics (like secrets found, active revocations, and Time-To-Remediation) via a Prometheus endpoint. The JSON files in this directory are out-of-the-box Grafana dashboard definitions that visualize these metrics.

## Usage
1. Import the JSON files in this directory directly into your Grafana instance.
2. Ensure you have configured Prometheus to scrape GhostCred (see the `prometheus/` directory).
3. The dashboards provide a complete SOC (Security Operations Center) view of DevSecOps secret leak activity.

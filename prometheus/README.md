# Prometheus Configuration

This directory contains configuration examples for Prometheus scraping.

## Overview
GhostCred serves a `/metrics` HTTP endpoint when configured to do so. This directory provides example `prometheus.yml` scrape configurations so that your Prometheus server knows how and where to pull data from running GhostCred instances or CI pipelines.

## Usage
Add the scrape job definitions found here to your primary `prometheus.yml` file to start ingesting GhostCred's operational data.

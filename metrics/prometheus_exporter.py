from __future__ import annotations

import time
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram, start_http_server, REGISTRY

FINDINGS_TOTAL = Counter(
    "ghostcred_findings_total",
    "Secrets detected",
    ["provider", "source_kind"],
)
BLAST_RADIUS_SCORE = Gauge(
    "ghostcred_blast_radius_score",
    "Blast radius score (0–100) for a finding",
    ["fingerprint_short"],
)
REVOCATIONS_TOTAL = Counter(
    "ghostcred_revocations_total",
    "Revocation attempts",
    ["provider", "status"],
)
SCAN_DURATION = Histogram(
    "ghostcred_scan_duration_seconds",
    "Time taken for a full scan run",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

_metrics_server_started = False


def record_finding(provider: str, source_kind: str) -> None:
    FINDINGS_TOTAL.labels(provider=provider, source_kind=source_kind).inc()


def record_blast_radius(fingerprint: str, score: int) -> None:
    BLAST_RADIUS_SCORE.labels(fingerprint_short=fingerprint[:12]).set(score)


def record_revocation(provider: str, success: bool) -> None:
    REVOCATIONS_TOTAL.labels(provider=provider, status="success" if success else "failed").inc()


def record_scan_duration(duration_seconds: float) -> None:
    SCAN_DURATION.observe(duration_seconds)


@contextmanager
def timed_scan():
    """Context manager that records scan duration automatically."""
    t0 = time.time()
    try:
        yield
    finally:
        record_scan_duration(time.time() - t0)


def serve_metrics(port: int = 9308) -> None:
    """Start the /metrics HTTP endpoint for Prometheus to scrape (idempotent)."""
    global _metrics_server_started
    if not _metrics_server_started:
        start_http_server(port)
        _metrics_server_started = True

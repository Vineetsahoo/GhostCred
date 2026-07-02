from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from ghostcred.scanners.patterns import CONTEXT_KEYWORDS, PATTERNS


def fingerprint(secret: str, salt: str) -> str:
    """Salted, non-reversible join key. Never store the raw secret."""
    return hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()


def redact(secret: str) -> str:
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:6]}{'*' * (len(secret) - 10)}{secret[-4:]}"


@dataclass
class Finding:
    provider: str
    fingerprint: str
    redacted: str
    source_path: str
    source_kind: str  # env | code | mcp_config | ide_config | shell_history | log
    line: int | None
    confidence: float
    revocable: bool
    raw_secret: str = field(repr=False, compare=False)  # in-memory only
    detected_at: float = field(default_factory=time.time)

    def to_public_dict(self) -> dict:
        """Serialization-safe view — never includes raw_secret."""
        return {
            "provider": self.provider,
            "fingerprint": self.fingerprint,
            "redacted": self.redacted,
            "source_path": self.source_path,
            "source_kind": self.source_kind,
            "line": self.line,
            "confidence": round(self.confidence, 2),
            "revocable": self.revocable,
            "detected_at": self.detected_at,
        }


def scan_text(text: str, source_path: str, source_kind: str, salt: str) -> list[Finding]:
    """Run all provider patterns against a text blob and return Findings."""
    findings: list[Finding] = []
    lines = text.splitlines()

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            secret = match.group(0)
            start = match.start()

            # crude line number lookup
            line_no = text.count("\n", 0, start) + 1

            # confidence boost if a contextual keyword appears nearby (same or prior line)
            window_start = max(0, start - 60)
            context_window = text[window_start:start]
            confidence = pattern.base_confidence
            if CONTEXT_KEYWORDS.search(context_window):
                confidence = min(1.0, confidence + 0.15)

            # generic 40-char base64 pattern (aws_secret_key) is too noisy without context —
            # require the keyword boost or skip it entirely
            if pattern.provider == "aws_secret_key" and not CONTEXT_KEYWORDS.search(context_window):
                continue

            findings.append(
                Finding(
                    provider=pattern.provider,
                    fingerprint=fingerprint(secret, salt),
                    redacted=redact(secret),
                    source_path=source_path,
                    source_kind=source_kind,
                    line=line_no,
                    confidence=confidence,
                    revocable=pattern.revocable,
                    raw_secret=secret,
                )
            )
    return findings


def scan_file(path: Path, source_kind: str, salt: str, max_bytes: int = 5_000_000) -> list[Finding]:
    try:
        if path.stat().st_size > max_bytes:
            return []
        text = path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []
    return scan_text(text, str(path), source_kind, salt)

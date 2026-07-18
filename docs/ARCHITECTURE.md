# GhostCred Architecture

## Data flow

```
                     ┌─────────────────────┐
                     │   Trigger sources    │
                     │  pre-commit / CI PR   │
                     │  / docker build / cron│
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │      CLI / Agent      │
                     │   ghostcred scan      │
                     └──────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
     ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐
     │  code_scanner   │ │ ai_toolchain_   │ │  (pluggable: iac, │
     │  .env, source,  │ │ scanner         │ │  container layers)│
     │  build files    │ │ MCP configs,    │ │                    │
     │                 │ │ IDE settings,   │ │                    │
     │                 │ │ shell history   │ │                    │
     └────────┬────────┘ └────────┬────────┘ └─────────┬──────────┘
              └─────────────────┬─┴──────────────────────┘
                                 ▼
                        ┌───────────────┐
                        │   Findings     │  (provider, secret hash, location, confidence)
                        └───────┬───────┘
                                 ▼
                     ┌─────────────────────┐
                     │  Lineage Tracker      │  walks docker logs, CI logs,
                     │  (blast radius graph) │  test output, git history for
                     │                       │  the same secret hash/fingerprint
                     └──────────┬───────────┘
                                 ▼
                     ┌─────────────────────┐
                     │  Liveness check       │  cheap read-only API call per
                     │  (per provider)       │  provider to confirm the secret
                     │                       │  is still active before revoking
                     └──────────┬───────────┘
                                 ▼
                 ┌───────────────┴────────────────┐
                 ▼                                 ▼
      ┌────────────────────┐          ┌─────────────────────────┐
      │ Auto-Revocation      │          │ Metrics + Alerting        │
      │ webhook per provider │          │ Prometheus exporter →     │
      │ (GitHub/AWS/OpenAI/  │          │ Grafana dashboard,        │
      │ Anthropic)           │          │ Slack/webhook alert       │
      └────────────────────┘          └─────────────────────────┘
```

## Why secrets need a fingerprint, not just a value

A raw secret value should never be persisted to disk, logged, or sent to Prometheus. GhostCred
stores a salted SHA-256 fingerprint (`sha256(secret + local_salt)`) as the join key across
scanners, lineage tracking, and dashboards. The plaintext only ever exists in memory for the
duration of the liveness check / revocation call, and is redacted everywhere else
(`ghp_****************************af3d`).

## Scanner interface (`scanners/base.py`)

Every scanner returns a list of `Finding` objects:

```
Finding(
  provider: str            # "github_pat", "aws_access_key", "openai_api_key", "anthropic_api_key", ...
  fingerprint: str          # salted hash, used as the join key everywhere else
  redacted: str             # e.g. "sk-ant-***************af3d"
  source_path: str          # absolute path
  source_kind: str          # "env" | "code" | "mcp_config" | "ide_config" | "shell_history" | "log"
  line: int | None
  confidence: float         # 0-1, regex hit vs. regex+entropy vs. regex+contextual keyword
  raw_secret: str           # kept in memory only, never serialized
)
```

This shape is deliberately provider-agnostic so the lineage tracker and revocation layer don't
need to know about scanner internals — they only care about `fingerprint` and `provider`.

## AI toolchain scan targets (the differentiator)

| Path pattern | Why it's a blind spot |
|---|---|
| `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) / `%APPDATA%/Claude/claude_desktop_config.json` (Windows) / `~/.config/Claude/claude_desktop_config.json` (Linux) | MCP server `env` blocks routinely contain raw API keys per official quickstarts |
| `**/.cursor/settings.json`, `**/.cursor/mcp.json` | Cursor MCP + model provider keys |
| `**/.vscode/settings.json`, `**/.vscode/mcp.json`, `*.code-workspace` | Copilot/extension tokens, workspace-level MCP servers |
| `~/.zsh_history`, `~/.bash_history`, `~/.zsh_sessions/*` | `export OPENAI_API_KEY=sk-...` typed directly at a shell prompt |
| `~/.aws/credentials`, `~/.config/gh/hosts.yml` | Legacy but still routinely re-scanned for cross-reference with lineage |
| `**/mcp.json`, `**/*.mcp.json` (project-local) | Project-committed MCP configs, the single most common accidental-commit vector |

## Lineage tracker

For every finding's fingerprint, the tracker greps forward through:
- Docker build logs / layer history (`docker history --no-trunc`, build log tail)
- GitHub Actions run logs (via `GH_TOKEN`, `gh run view --log`)
- Local test-output directories (`pytest` cache, `coverage.xml`, junit XML)
- Git history (`git log -p -S<fingerprint-safe-search>` is NOT used directly on plaintext;
  instead a bloom-filter of known-secret fingerprints is checked against blob hashes)

Output is a small graph: `{origin_file: [...], propagated_to: [{path, kind, timestamp}]}`,
scored into a 0-100 "blast radius score" (weighted by how public/shared the destination is —
a CI log visible to the whole org scores much higher than a local pytest cache dir).

## Revocation layer

Each provider revoker implements:

```python
class Revoker(Protocol):
    provider: str
    def check_live(self, secret: str) -> bool:
        ...
    def revoke(self, secret: str) -> RevocationResult:
        ...
```

Revocation always requires `check_live()` to return `True` first, and by default requires
`--revoke-live` / `GHOSTCRED_AUTO_REVOKE=1` to be set explicitly — this is a destructive,
security-critical action and should never fire silently on a false positive. In CI, it fires
automatically only on a `main`/`release` branch scan by default (configurable).

## Metrics

`prometheus_exporter.py` exposes:
- `ghostcred_findings_total{provider,source_kind}`
- `ghostcred_blast_radius_score{fingerprint_short}`
- `ghostcred_revocations_total{provider,status}`
- `ghostcred_scan_duration_seconds`

Grafana dashboard (`grafana/dashboards/ghostcred-dashboard.json`) plots secrets-over-time,
blast radius heatmap, and revocation latency (detection → revoked).

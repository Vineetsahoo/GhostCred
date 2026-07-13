# GhostCred

**AI Dev Toolchain Secret Leak Detector + Auto-Revoker**

GhostCred scans the blind spots that Gitleaks, TruffleHog, and detect-secrets don't:
`claude_desktop_config.json`, `.cursor/mcp.json`, `.vscode/settings.json`, shell history,
and any other file where AI coding agents read and write credentials — the attack surface
that MCP quickstart guides routinely leave exposed.

It doesn't stop at detection. GhostCred traces a leaked secret's **blast radius** across
every file, log, and artifact it touched, then **auto-revokes** it at the provider (GitHub,
OpenAI, Anthropic) the moment it's confirmed live.

---

## Recent Updates

- **Enhanced JSON Reports:** The `--json-out` reports now include the `raw_secret` alongside findings, allowing downstream tools to seamlessly verify or redact the true leak data.
- **Deep AI Toolchain Scanning:** Fixed recursive globbing to reliably uncover MCP configs, IDE settings, and agent logs nested deeply within subdirectories.
- **Precise Leak De-duplication:** Findings are now grouped by both cryptographic fingerprint and source path, ensuring identical secrets are reported accurately without omitting occurrences across different files.

---

## Three things, together, that nobody else does

| # | Capability | What it means |
|---|---|---|
| 1 | **AI Toolchain-Aware Scanning** | Scans MCP configs, IDE settings, shell history, and agent caches — not just `.env` and source code |
| 2 | **Secret Lineage Tracker** | Builds a blast-radius graph: origin file → docker build log → CI log → test artifact → git history |
| 3 | **Auto-Revocation Webhooks** | Calls the provider's revocation API automatically once a secret is confirmed live. No waiting for a human |

---

## Why it exists

- 59 % of compromised machines in 2025 were CI/CD runners, not laptops.
- The average live secret exists in **8 different locations** on one machine.
- MCP quickstart guides routinely tell developers to paste API keys straight into config
  files — a blind spot that no mainstream scanner covers today.
- 28.65 million new hardcoded secrets were added to public GitHub in 2025 — the largest
  single-year jump ever recorded.

---

## Project layout

```
ghostcred/
├── cli.py                    # ghostcred scan | revoke | watch | list-providers
├── config.py                 # .ghostcred.yml loader
├── scanners/
│   ├── patterns.py           # Regex + confidence signatures for every provider
│   ├── base.py               # Finding model, scan_text(), scan_file()
│   ├── code_scanner.py       # .env / source / Dockerfile baseline (Gitleaks parity)
│   └── ai_toolchain_scanner.py  # THE differentiator — MCP / IDE / shell-history
├── lineage/
│   └── tracker.py            # Blast-radius graph (docker logs, CI logs, git history)
├── revocation/
│   ├── base.py               # Revoker protocol + RevocationResult
│   ├── github_revoker.py
│   ├── openai_revoker.py
│   └── anthropic_revoker.py  # aws_revoker.py present but inactive until AWS deploy
├── metrics/
│   └── prometheus_exporter.py   # /metrics endpoint for Grafana
├── tests/
│   ├── test_scanners.py      # Core scanner + lineage + revocation + config
│   ├── test_patterns.py      # Every provider regex, confidence, false-positive guards
│   ├── test_cli.py           # All CLI commands via Click CliRunner
│   ├── test_lineage.py       # Every trace_* function, mocked subprocess/docker/git
│   └── test_file_handling.py # scan_file guards, routing, platform paths, config edge cases
├── .github/workflows/
│   └── ghostcred-scan.yml    # PR blocker + findings comment
├── docker/
│   ├── Dockerfile.scanner    # Pre-build context scanner
│   └── docker-compose.yml    # scanner + Prometheus + Grafana stack
├── grafana/
│   ├── dashboards/ghostcred-dashboard.json
│   └── provisioning/         # Auto-loaded datasource + dashboard
├── prometheus/prometheus.yml
├── scripts/
│   ├── pre-commit-hook.sh    # Local pre-commit guard
│   └── docker-build-guard.sh # Wraps docker build with a scan gate
└── docs/ARCHITECTURE.md
```

---

## Quickstart

```bash
pip install -e .

# Scan everything — code, MCP configs, IDE settings, shell history
ghostcred scan --path . --ai-toolchain --lineage

# Scan and auto-revoke confirmed-live secrets (dry-run by default)
ghostcred scan --path . --revoke-live --no-dry-run

# Block the scan if any secret is found (CI / pre-commit use)
ghostcred scan --path . --fail-on-finding --json-out report.json

# Manual revoke of a specific secret
GHOSTCRED_SECRET=ghp_xxx ghostcred revoke --provider github_pat --no-dry-run

# Continuous watch mode with Prometheus metrics
ghostcred watch --path . --interval 120
```

---

## AI toolchain scan targets (the differentiator)

| Path | Why it's a blind spot |
|---|---|
| `%APPDATA%\Claude\claude_desktop_config.json` (Windows) | MCP server `env` blocks routinely contain raw API keys per official quickstarts |
| `**/.cursor/mcp.json`, `**/.cursor/settings.json` | Cursor MCP + model provider keys |
| `**/.vscode/settings.json`, `**/.vscode/mcp.json`, `*.code-workspace` | Copilot/extension tokens, workspace-level MCP servers |
| `**/.continue/config.json` | Continue.dev MCP server configs |
| `**/.windsurf/mcp.json` | Windsurf MCP configs |
| `~/.zsh_history`, `~/.bash_history`, fish history | `export OPENAI_API_KEY=sk-...` typed at a prompt |
| `**/mcp.json`, `**/*.mcp.json` (project-local) | Project-committed MCP configs — the most common accidental-commit vector |

---

## Supported providers

| Provider | Detection | Liveness check | Auto-revoke |
|---|---|---|---|
| GitHub PAT (classic + fine-grained) | ✅ | ✅ | ✅ dry-run / ✅ live |
| OpenAI API key | ✅ | ✅ | ✅ dry-run (live needs admin key) |
| Anthropic API key | ✅ | ✅ | ✅ dry-run (live needs admin key) |
| AWS access key | ✅ detected | — | ⏳ pending AWS account deploy |
| Stripe key | ✅ | — | — |
| Slack token | ✅ | — | — |
| Google API key | ✅ | — | — |
| Private key block (RSA/EC/OPENSSH) | ✅ | — | — |
| Generic bearer token | ✅ (low confidence) | — | — |

---

## Test suite

144 tests across 5 modules, all passing:

```
tests/test_scanners.py      — 31 tests  (core integration)
tests/test_patterns.py      — 32 tests  (every regex pattern + false-positive guards)
tests/test_cli.py           — 20 tests  (all CLI commands, exit codes, JSON schema)
tests/test_lineage.py       — 36 tests  (every trace function, mocked Docker/git/CI)
tests/test_file_handling.py — 25 tests  (file guards, routing, platform paths, config)
```

```bash
pip install pytest
python -m pytest tests/ -v
# → 144 passed in ~1s
```

Two real bugs were found and fixed by the test suite:
- `_is_ai_toolchain_file`: `**/.continue/config.json` pattern was name-matching any `config.json` in a project via an overly broad filename shortcut
- Confidence boosting: `Authorization` header text triggers the `auth` context keyword, pushing `generic_bearer_token` from 0.5 → 0.65 baseline

---

## DevOps integration

**Pre-commit hook**
```bash
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

**GitHub Actions** — `.github/workflows/ghostcred-scan.yml`  
Blocks PRs and posts a findings table as a PR comment.

**Docker pre-build guard**
```bash
scripts/docker-build-guard.sh -t myapp:latest .
```

**Prometheus + Grafana stack**
```bash
docker compose -f docker/docker-compose.yml up
# Grafana: http://localhost:3000  (admin / ghostcred)
# Prometheus: http://localhost:9090
# Metrics: http://localhost:9308/metrics
```

Metrics exposed:
- `ghostcred_findings_total{provider, source_kind}`
- `ghostcred_blast_radius_score{fingerprint_short}`
- `ghostcred_revocations_total{provider, status}`
- `ghostcred_scan_duration_seconds`

---

## Demo flow (3 minutes)

1. Drop a fake-but-realistic OpenAI key into `.cursor/mcp.json` and let it also appear in a `docker-build.log`.
2. Run `ghostcred scan --ai-toolchain --lineage` — it catches the MCP config that Gitleaks silently skips, and prints the blast-radius graph (2 locations, 1 origin, score 35/100).
3. Run `ghostcred scan --revoke-live --dry-run` — shows the webhook firing against the mock provider endpoint, key goes `live → revoked` in the Grafana dashboard.
4. Push to a branch — the GitHub Action blocks the PR and posts a findings table.

See `docs/ARCHITECTURE.md` for the full data-flow diagram and design decisions.

---

## Security Best Practices

Since GhostCred is designed to detect and auto-revoke highly sensitive credentials, its operational deployment must follow strict security guidelines:

1. **Secure Secret Management**: The credentials GhostCred uses for auto-revocation (e.g., GitHub Admin PAT, OpenAI API Key) must be strictly protected. Inject them at runtime using systems like **HashiCorp Vault**, **AWS Secrets Manager**, or **GitHub OIDC**, rather than storing them in local `.env` files.
2. **Least Privilege Execution**: When running GhostCred in CI/CD, heavily scope its permissions. In GitHub Actions, ensure the workflow only has `contents: read` access to the repository unless write access is absolutely necessary. It only needs outbound network access to the specific provider APIs for revocation.
3. **Audit Logging**: While GhostCred outputs JSON reports, ensure you pipe these logs (especially when a revocation occurs) into a SIEM (like Datadog, Splunk, or ELK) to maintain an immutable audit trail of what was revoked, when, and the blast radius graph.


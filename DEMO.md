# GhostCred — Live Demo Guide

Step-by-step commands to see every part of GhostCred working — from first install
through live revocation. Each step builds on the previous one.

---

## The scenario

`demo-repo/` simulates a developer who:

- Hardcoded a GitHub PAT, OpenAI key, and DB URI directly in `app.py`
- Committed all four secrets to a `.env` file
- Accidentally baked them into `docker-build.log` during a Docker build
- Let them slip into a CI run log (`ci-logs/run-001.txt`)
- Pasted the GitHub PAT into their Cursor MCP config (`.cursor/mcp.json`)

GhostCred finds all of this, traces how far each secret spread (blast radius),
checks whether the token is still live at the provider, and revokes it.

---

## 0. Setup (one time)

```bash
# Windows — run from repo root
cd c:\Users\vinee\Downloads\ghostcred

# macOS / Linux
cd ~/path/to/ghostcred
```

```bash
# Install GhostCred in editable mode
pip install -e .

# Install Flask — only needed for the mock provider in steps 5–8
pip install flask

# Confirm the CLI is working
ghostcred --help
```

> **Troubleshooting:** If `ghostcred` is not found after install, make sure you ran
> `pip install -e .` from the repo root (the directory that contains `pyproject.toml`),
> not from a subdirectory. On Windows you may need to restart your terminal after install.

---

## 1. What we are scanning

```
demo-repo/
├── app.py                  ← GitHub PAT + OpenAI key hardcoded in Python source
├── .env                    ← all four secrets in an env file
├── .cursor/
│   └── mcp.json            ← GitHub PAT + OpenAI key inside a Cursor MCP config
├── docker-build.log        ← secrets baked into Docker ENV layer output
├── ci-logs/
│   └── run-001.txt         ← secrets echoed into a simulated CI run log
└── .ghostcred.yml          ← per-project GhostCred config for this demo
```

Open any file to see the fake secrets before the scan runs:

```bash
# Windows
type demo-repo\app.py

# macOS / Linux
cat demo-repo/app.py
```

---

## 2. Basic scan — code and env files only

```bash
ghostcred scan --path demo-repo --no-ai-toolchain --no-lineage
```

Expected: detects GitHub PAT, OpenAI key, Anthropic key, and database URI from
`app.py` and `.env`. Each finding shows provider, file, line, confidence, and
a redacted version of the secret.

---

## 3. AI toolchain scan — what other scanners miss

```bash
ghostcred scan --path demo-repo --ai-toolchain --no-global-configs --no-lineage
```

Now it also finds the same secrets inside `demo-repo/.cursor/mcp.json`.
The `source_kind` field shows `mcp_config` — distinct from `code` or `env`.

Gitleaks, TruffleHog, and detect-secrets scan source files and git history.
None of them know that `.cursor/mcp.json` is a credential surface. GhostCred does.

---

## 4. Full scan with lineage and blast radius

```bash
# macOS / Linux
ghostcred scan \
  --path demo-repo \
  --ai-toolchain \
  --no-global-configs \
  --lineage \
  --json-out ghostcred-report.json

# Windows (use ^ for line continuation, or run as one line)
ghostcred scan --path demo-repo --ai-toolchain --no-global-configs --lineage --json-out ghostcred-report.json
```

GhostCred now traces the GitHub PAT beyond the source file:

| Location found | Type | Weight |
|---|---|---|
| Origin file (`app.py`) | base | +10 |
| `docker-build.log` | docker_build_log | +25 |
| `ci-logs/run-001.txt` | github_actions_log | +40 |
| **Total blast radius** | | **75 / 100** |

Inspect the report:

```bash
# macOS / Linux / Windows (Python one-liner)
python -c "
import json
r = json.load(open('ghostcred-report.json'))
for f in r['findings']:
    lin = f.get('lineage', {})
    print(f['provider'], '| blast=', lin.get('blast_radius_score', 'n/a'))
    for p in lin.get('propagations', []):
        print('  ->', p['kind'], p['path'])
"
```

---

## 5. Start the mock provider (new terminal)

The mock provider runs a local Flask server that simulates GitHub, OpenAI, and
Anthropic API endpoints. Steps 6–8 require it to be running.

```bash
# Open a new terminal window, then run:
python scripts/mock_provider.py
```

You should see:
```
  GhostCred Mock Provider running at http://localhost:5001
  GET  /status  — check current token liveness state
  GET  /user    — GitHub PAT liveness check
  Press Ctrl+C to stop.
```

Confirm it is up:

```bash
curl http://localhost:5001/status
```

Expected response:
```json
{
  "ghp_fakeDemoToken12...": "LIVE",
  "sk-proj-FAKEKEYFOR...": "LIVE",
  "sk-ant-api03-aaaaaaa...": "LIVE"
}
```

> **If curl is not available on Windows**, open a browser and go to
> `http://localhost:5001/status` — you will see the same JSON response.

> **If the mock provider is not running**, steps 6–8 will report the token as
> inactive and skip revocation. That is expected — start the provider and retry.

---

## 6. Liveness check — is the token still active?

With the mock provider running, GhostCred can confirm whether a found token
is still valid before deciding to revoke it.

```bash
# Direct curl check (macOS / Linux / Windows with curl)
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ghp_fakeDemoToken1234567890abcdefghijABCD" \
  http://localhost:5001/user
```

Returns `200` — the token is live. An attacker who found it in git history
can use it right now.

---

## 7. Revoke — dry run first

Always run a dry run before live revocation. It shows exactly what would happen
without calling any API.

```bash
# macOS / Linux
GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD \
  ghostcred revoke --provider github_pat --dry-run

# Windows (PowerShell)
$env:GHOSTCRED_SECRET="ghp_fakeDemoToken1234567890abcdefghijABCD"
ghostcred revoke --provider github_pat --dry-run

# Windows (CMD)
set GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD
ghostcred revoke --provider github_pat --dry-run
```

Output confirms: `success=True, dry_run=True` — nothing was actually revoked.

---

## 8. Revoke — live (calls mock provider)

```bash
# macOS / Linux
GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD \
  ghostcred revoke --provider github_pat --no-dry-run

# Windows (PowerShell)
$env:GHOSTCRED_SECRET="ghp_fakeDemoToken1234567890abcdefghijABCD"
ghostcred revoke --provider github_pat --no-dry-run

# Windows (CMD)
set GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD
ghostcred revoke --provider github_pat --no-dry-run
```

Confirm the token is now dead:

```bash
curl http://localhost:5001/status
# ghp_fakeDemoToken12...: "REVOKED"

curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ghp_fakeDemoToken1234567890abcdefghijABCD" \
  http://localhost:5001/user
# Returns 401
```

---

## 9. Full automated demo (all steps in one run)

Runs all 10 steps in sequence with coloured terminal output.
Requires the mock provider running in a separate terminal (step 5).

```bash
python scripts/run_demo.py
```

Produces:
- `ghostcred-demo-report.json` — complete JSON report including lineage
- `ghostcred-ci-gate-report.json` — output of the CI gate check

---

## 10. Release gate scan

Simulates the check that runs before a Docker image is signed and pushed
to a registry. In the real `release.yml` workflow, this step blocks the
release if any high-confidence secret is found.

```bash
# macOS / Linux
bash scripts/demo_release_scan.sh
```

Exits with code 1 because `demo-repo` contains high-confidence secrets.
The exit code is what causes GitHub Actions to block the release job.

---

## 11. CI behaviour — how it blocks a PR

This is the exact command that runs inside `ghostcred-scan.yml` on every pull request:

```bash
# macOS / Linux
ghostcred scan \
  --path demo-repo \
  --ai-toolchain \
  --no-global-configs \
  --no-lineage \
  --fail-on-finding \
  --dry-run \
  --json-out ghostcred-ci-gate-report.json

echo "Exit code: $?"

# Windows
ghostcred scan --path demo-repo --ai-toolchain --no-global-configs --no-lineage --fail-on-finding --dry-run --json-out ghostcred-ci-gate-report.json
echo Exit code: %ERRORLEVEL%
```

Exit code `1` → GitHub Actions marks the step failed → PR cannot be merged.

---

## 12. Pre-commit hook — blocks at the commit level

Stops secrets from entering the repository in the first place.

```bash
# Install (macOS / Linux — one time per clone)
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Test it:

```bash
# macOS / Linux
echo 'API_KEY=ghp_fakeDemoToken1234567890abcdefghijABCD' > demo-repo/leaked.py
git add demo-repo/leaked.py
git commit -m "test commit"
# Expected: commit is rejected with ❌ Commit blocked message

# Clean up
git restore --staged demo-repo/leaked.py
rm demo-repo/leaked.py
```

---

## 13. Revocation strategy

GhostCred uses a three-stage revocation flow designed to prevent accidental
deletion and pipeline breakage.

### Stage 1 — Liveness check (always first)

Before any revocation attempt, GhostCred calls the provider's read-only
verification endpoint (`GET /user` for GitHub, models list for OpenAI, etc.).
If the secret is already inactive, revocation is skipped entirely.

### Stage 2 — Dry run (default)

Revocation is dry-run by default. The CLI logs what it would do and returns
a `RevocationResult` with `dry_run=True, success=True`. No API is called.
This is safe to run in any environment including CI.

```bash
# Dry run is the default — this is always safe
ghostcred revoke --provider github_pat --dry-run
```

### Stage 3 — Live revocation (explicit opt-in only)

Live revocation requires `--no-dry-run` on the CLI, or `GHOSTCRED_AUTO_REVOKE=1`
in the environment. It is never silent. The flow is:

```
check_live() → true
  → [optional] grace period countdown (--grace-period N seconds)
  → [optional] pre-revocation rotation (--rotate-manager)
  → revoke() → RevocationResult
  → [optional] webhook notification
```

| Provider | Revocation method | Requires |
|---|---|---|
| `github_pat` | `DELETE /installation/token` | GitHub App credentials or `GHOSTCRED_GITHUB_TOKEN` |
| `openai_api_key` | Admin API key deletion | `GHOSTCRED_OPENAI_ADMIN_KEY` (org admin key) |
| `anthropic_api_key` | Console API deletion | `GHOSTCRED_ANTHROPIC_ADMIN_KEY` (console admin key) |

### Authorization — what needs real credentials

| Action | Needs real auth? | Where to configure |
|---|---|---|
| Code scan, AI toolchain scan | No | Nothing needed |
| Lineage — local logs, docker logs | No | Nothing needed |
| Lineage — CI run logs | Yes (`GITHUB_TOKEN`) | `.env` or CI repository secret |
| Liveness check (local demo) | No — uses mock provider | Start `scripts/mock_provider.py` |
| Liveness check (production) | Yes — provider read token | `GHOSTCRED_GITHUB_TOKEN` in `.env` |
| Live revocation | Yes — provider admin key | `GHOSTCRED_GITHUB_TOKEN` / `GHOSTCRED_OPENAI_ADMIN_KEY` in `.env` |
| Metrics / Grafana | No | `docker compose up` inside `docker/` |

For the demo, everything through step 8 works with the mock provider.
No real API keys are needed.

For production:

```bash
cp .env.example .env
# Fill in:
# GHOSTCRED_GITHUB_TOKEN=ghp_your_admin_token
# GHOSTCRED_OPENAI_ADMIN_KEY=sk-org-...
# GHOSTCRED_SALT=<python -c "import secrets; print(secrets.token_hex(32))">
```

---

## 14. Observability stack

Run Prometheus and Grafana alongside the scanner:

```bash
cd docker
docker compose up -d
```

| Service | URL | Default credentials |
|---|---|---|
| Grafana | http://localhost:3000 | admin / ghostcred |
| Prometheus | http://localhost:9090 | — |
| GhostCred metrics | http://localhost:9308/metrics | — |

The Grafana dashboard tracks secrets detected over time per provider,
blast radius score per fingerprint, and revocation latency (detection → revoked).

---

## CLI quick-reference

| Command | What it does |
|---|---|
| `ghostcred scan --path <dir>` | Scan a directory for secrets |
| `--ai-toolchain` | Include MCP configs, IDE settings, shell history |
| `--no-global-configs` | Skip desktop app configs outside the repo |
| `--lineage` | Trace each secret into logs, docker history, git |
| `--fail-on-finding` | Exit code 1 if any finding above threshold (CI use) |
| `--json-out <file>` | Write full JSON report to a file |
| `--min-confidence <0-1>` | Override the confidence threshold (default 0.6) |
| `ghostcred revoke --provider <name>` | Revoke a single known secret |
| `--dry-run` / `--no-dry-run` | Log intent only / actually call the provider API |
| `ghostcred watch --interval 120` | Continuously rescan every N seconds |
| `ghostcred plant-decoys --path <dir>` | Plant honeytokens to test detection coverage |
| `ghostcred list-providers` | Show all providers with auto-revocation support |

---

## What each field in a finding means

| Field | Meaning |
|---|---|
| `provider` | Secret type: `github_pat`, `openai_api_key`, `database_uri`, etc. |
| `source_kind` | Where it was found: `code`, `env`, `mcp_config`, `ide_config`, `shell_history` |
| `redacted` | Safe display value — prefix + stars + suffix, never the full secret |
| `confidence` | 0–1. ≥ 0.9 = definitive pattern match. 0.6–0.9 = likely. Below 0.6 = review needed. |
| `revocable` | `true` if GhostCred has an automated revocation path for this provider |
| `blast_radius_score` | 0–100. How far the secret has spread beyond the file it was found in. |
| `propagations` | List of other locations where the same secret was detected (docker log, CI log, git commit) |
| `lineage.origin` | The first place the secret was found |
| `detected_at` | Unix timestamp of when the finding was recorded |

# GhostCred — Live Demo Guide

This is not documentation. This is the exact sequence of commands to run
to see every part of GhostCred working, from first install to live revocation.

---

## The scenario

`demo-repo/` simulates a developer who:
- Hardcoded a GitHub PAT, OpenAI key, and DB URI directly in `app.py`
- Committed them to a `.env` file
- Accidentally baked them into a `docker-build.log`
- Let them slip into a CI run log (`ci-logs/run-001.txt`)
- Pasted the GitHub PAT into their Cursor MCP config (`demo-repo/.cursor/mcp.json`)

GhostCred finds all of this, traces how far the secret spread (blast radius),
checks whether the token is still live, and revokes it.

---

## 0. Setup (one time)

```bash
# From the repo root
cd c:\Users\vinee\Downloads\ghostcred    # Windows
# or: cd ~/Downloads/ghostcred           # macOS/Linux

# Install GhostCred and demo dependencies
pip install -e .
pip install flask          # needed for the mock provider only

# Confirm the CLI works
ghostcred --help
```

---

## 1. Look at what we're scanning

The demo-repo has these "leaked" files:

```
demo-repo/
├── app.py                     ← GitHub PAT + OpenAI key hardcoded in source
├── .env                       ← all four secrets in env file
├── .cursor/mcp.json           ← GitHub PAT + OpenAI key in Cursor MCP config
├── docker-build.log           ← secrets baked into docker ENV layer
├── ci-logs/run-001.txt        ← secrets echoed into CI run output
└── .ghostcred.yml             ← config for this demo project
```

Open any of them to see the fake secrets before the scan finds them:

```bash
type demo-repo\app.py              # Windows
cat demo-repo/app.py               # macOS/Linux
```

---

## 2. Basic scan — code only

```bash
ghostcred scan --path demo-repo --no-ai-toolchain --no-lineage
```

Expected output: detects GitHub PAT, OpenAI key, DB URI, Anthropic key
from `app.py` and `.env`.

---

## 3. AI toolchain scan — what other scanners miss

```bash
ghostcred scan --path demo-repo --ai-toolchain --no-global-configs --no-lineage
```

Now it also finds the secrets inside `demo-repo/.cursor/mcp.json`.
Source kind shows `mcp_config` — distinct from `code` or `env`.

**This is GhostCred's differentiator.** Gitleaks, TruffleHog, and
detect-secrets don't know about MCP config files at all.

---

## 4. Full scan with lineage (blast radius)

```bash
ghostcred scan \
  --path demo-repo \
  --ai-toolchain \
  --no-global-configs \
  --lineage \
  --json-out ghostcred-report.json
```

Now GhostCred also traces the GitHub PAT into:
- `docker-build.log` (weight +25)
- `ci-logs/run-001.txt` (weight +40)

Blast radius score for the GitHub PAT will be **75/100** (10 base + 25 + 40).

Inspect the full report:

```bash
python -c "
import json
r = json.load(open('ghostcred-report.json'))
for f in r['findings']:
    lin = f.get('lineage', {})
    print(f\"{f['provider']} | confidence={f['confidence']} | blast={lin.get('blast_radius_score','n/a')}\")
    for p in lin.get('propagations', []):
        print(f\"  ↳ {p['kind']}: {p['path']}\")
"
```

---

## 5. Start the mock provider (new terminal)

The mock provider simulates GitHub's API locally so liveness checks
and revocations work without touching real credentials.

```bash
# Open a new terminal, then:
python scripts/mock_provider.py
```

You should see:
```
  GhostCred Mock Provider running at http://localhost:5001
  GET  /status  — check current token liveness state
  GET  /user    — GitHub PAT check
```

Confirm it's working:
```bash
curl http://localhost:5001/status
```

Expected:
```json
{
  "ghp_fakeDemoToken12...": "LIVE",
  "sk-proj-FAKEKEYFOR...": "LIVE",
  "sk-ant-api03-aaaaaaa...": "LIVE"
}
```

---

## 6. Liveness check — is the token actually active?

```bash
# Check if the GitHub PAT is live (calls GET /user on mock provider)
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ghp_fakeDemoToken1234567890abcdefghijABCD" \
  http://localhost:5001/user
```

Returns `200` — the token is live. An attacker who found it in git history
could use it right now.

---

## 7. Revoke via CLI — dry run first

```bash
# Dry run: logs what would happen, no real API call
GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD \
  ghostcred revoke --provider github_pat --dry-run
```

Output shows the revocation intent without actually calling the API.

---

## 8. Revoke via CLI — live (mock provider)

```bash
# Live revocation: calls DELETE /installation/token on mock provider
GHOSTCRED_SECRET=ghp_fakeDemoToken1234567890abcdefghijABCD \
  ghostcred revoke --provider github_pat --no-dry-run
```

Then confirm it's dead:

```bash
curl http://localhost:5001/status
```

The token now shows `REVOKED`.

Verify the mock provider actually rejects it:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: token ghp_fakeDemoToken1234567890abcdefghijABCD" \
  http://localhost:5001/user
```

Returns `401` — token is dead.

---

## 9. Run the full automated demo

This runs all 10 steps in sequence with coloured output:

```bash
python scripts/run_demo.py
```

Produces two output files:
- `ghostcred-demo-report.json` — full JSON report with lineage
- `ghostcred-ci-gate-report.json` — CI gate scan output

---

## 10. Release gate scan

Simulates what runs before a Docker image is signed and pushed:

```bash
bash scripts/demo_release_scan.sh
```

This exits with code 1 because the demo-repo has high-confidence secrets.
In the real release workflow (`release.yml`), this blocks the tag from being pushed.

---

## 11. CI behaviour — how it blocks a PR

```bash
# This is the exact command that runs in ghostcred-scan.yml
ghostcred scan \
  --path demo-repo \
  --ai-toolchain \
  --no-global-configs \
  --no-lineage \
  --fail-on-finding \
  --dry-run \
  --json-out ghostcred-ci-gate-report.json

echo "Exit code: $?"
```

Exit code is `1` → in GitHub Actions, this marks the step as failed
and blocks the PR from merging.

---

## 12. Pre-commit hook — blocks at the commit level

```bash
# Install the hook (one time per repo clone)
cp scripts/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Now try to commit something with a fake secret
echo 'API_KEY=ghp_fakeDemoToken1234567890abcdefghijABCD' > /tmp/leaked.py
cp /tmp/leaked.py demo-repo/leaked.py
git add demo-repo/leaked.py
git commit -m "test"    # GhostCred blocks this commit
```

The commit is rejected with:
```
❌ Commit blocked: GhostCred detected a secret
```

Clean up:
```bash
git reset HEAD demo-repo/leaked.py
rm demo-repo/leaked.py
```

---

## 13. Authorization point — what needs real credentials

| Action | Needs real auth? | Where configured |
|--------|-----------------|------------------|
| Code/AI scan (local) | No | Nothing needed |
| Lineage — local logs | No | Nothing needed |
| Lineage — CI logs | Yes — `GITHUB_TOKEN` | Set in `.env` or CI secret |
| Liveness check | Mock: no. Real: yes | Real token in `.env` as `GHOSTCRED_GITHUB_TOKEN` |
| Live revocation | Yes — provider admin key | `GHOSTCRED_GITHUB_TOKEN` / `GHOSTCRED_OPENAI_ADMIN_KEY` |
| Metrics / Grafana | No (local stack) | `docker compose up` in `docker/` |

For the local demo everything works with the mock provider — **no real API keys needed**.

For production use, set the admin keys in `.env` (copy from `.env.example`):

```bash
cp .env.example .env
# Edit .env and fill in:
# GHOSTCRED_GITHUB_TOKEN=ghp_your_real_admin_token
# GHOSTCRED_OPENAI_ADMIN_KEY=sk-...
# GHOSTCRED_SALT=<output of: python -c "import secrets; print(secrets.token_hex(32))">
```

---

## 14. Observability stack (Prometheus + Grafana)

Run the full Docker stack to see metrics in Grafana:

```bash
cd docker
docker compose up -d
```

- Grafana:    http://localhost:3000  (admin / ghostcred)
- Prometheus: http://localhost:9090
- Metrics:    http://localhost:9308/metrics

The Grafana dashboard shows:
- Secrets detected over time (by provider)
- Blast radius score per fingerprint
- Revocation latency (time from detection to revoked)

---

## What each scan output means

| Field | Meaning |
|-------|---------|
| `provider` | Which secret type: `github_pat`, `openai_api_key`, `database_uri`, etc. |
| `source_kind` | Where it was found: `code`, `env`, `mcp_config`, `shell_history`, `log` |
| `redacted` | Safe display: `ghp_fakeDe****...ij` — prefix + stars + suffix |
| `confidence` | 0–1. ≥0.9 = definitive match. 0.6–0.9 = likely. <0.6 = needs review. |
| `revocable` | Whether GhostCred has an auto-revocation path for this provider |
| `blast_radius_score` | 0–100. How far the secret has spread beyond the origin file. |
| `propagations` | Each place the same secret was found: docker log, CI log, git history |
